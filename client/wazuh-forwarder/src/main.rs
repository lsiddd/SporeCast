use anyhow::{Context, Result};
use chrono::Local;
use crossbeam_channel::bounded;
use log::{error, info, warn, LevelFilter};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    fs::OpenOptions,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread, // <-- MODIFIED: Import the standard library thread module
};

use wazuh_forwarder::{
    behavioral::StateManager,
    palo_alto_config::*,
    palo_alto_workers::*,
    telegram::send_telegram_message,
    threat_intel::{threat_intel_updater_thread, ThreatIntel},
};

// ==============================================================================
// --- Main Function ---
// Entry point for the Palo Alto Log Forwarder application.
// Initializes logging, sets up threads, and manages graceful shutdown.
// ==============================================================================
#[tokio::main]
async fn main() -> Result<()> {
    // --- Logging Setup ---
    let log_file_result = OpenOptions::new().create(true).append(true).open(LOG_FILE);
    let fern_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("main"),
                message
            ))
        })
        .level(LevelFilter::Debug)
        .chain(io::stdout());

    match log_file_result {
        Ok(file) => {
            fern_dispatch.chain(file).apply()?;
            info!("Logging configured. Detailed logs will be written to {}.", LOG_FILE);
        }
        Err(e) => {
            eprintln!("Failed to open log file {}: {}. Logging will only go to stdout.", LOG_FILE, e);
            fern_dispatch.apply()?;
        }
    };

    info!("==============================================");
    info!("     Palo Alto Raw Log Forwarder (Rust)     ");
    info!("==============================================");
    info!("Service starting up in Belém, State of Pará, Brazil. Current time: {}", 
          Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
    info!("Configured to receive Palo Alto logs on UDP port: {}", PALO_ALTO_SYSLOG_PORT);
    info!("Configured to forward a copy of raw logs to Wazuh on {}:{}", 
          WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT);
    info!("Configured to forward processed logs to ELK server at: {}:{}", ELK_HOST, ELK_PORT);

    // Test initial connection to ELK
    if let Err(e) = test_initial_connection().await {
        warn!("Initial ELK connection test failed. Service will attempt to reconnect as needed: {}", e);
    }

    // --- Signal Handling Setup ---
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut signals = Signals::new(&[SIGINT, SIGTERM])
        .context("Failed to register signal handlers")?;
    let signal_shutdown = shutdown.clone();
    thread::Builder::new()
        .name("signal_handler".to_string())
        .spawn(move || {
            info!("Signal handler thread started. Waiting for SIGINT or SIGTERM.");
            for sig in signals.forever() {
                warn!("Received OS signal {:?}. Initiating graceful shutdown sequence...", sig);
                signal_shutdown.store(true, Ordering::Relaxed);
                break;
            }
            info!("Signal handler thread finished.");
        })?;

    // --- Channels for Inter-Thread Communication ---
    let (raw_log_tx, raw_log_rx) = bounded(MAX_RECEIVER_QUEUE_SIZE);
    info!("Created raw log channel with max capacity: {} logs.", MAX_RECEIVER_QUEUE_SIZE);

    let (wazuh_raw_tx, wazuh_raw_rx) = bounded(MAX_RECEIVER_QUEUE_SIZE);
    info!("Created Wazuh raw log channel with max capacity: {} logs.", MAX_RECEIVER_QUEUE_SIZE);

    let (elk_tx, elk_rx) = bounded(MAX_ENRICHMENT_QUEUE_SIZE);
    info!("Created ELK sender channel with max capacity: {} logs.", MAX_ENRICHMENT_QUEUE_SIZE);

    let (wazuh_enriched_tx, wazuh_enriched_rx) = bounded(MAX_WAZUH_QUEUE_SIZE);
    info!("Created Wazuh enriched log channel with max capacity: {} logs.", MAX_WAZUH_QUEUE_SIZE);

    let (state_merger_tx, state_merger_rx) = bounded(ENRICHMENT_WORKER_COUNT * 2);
    info!("Created state merger channel with max capacity: {} history updates.", ENRICHMENT_WORKER_COUNT * 2);

    // --- State Manager Initialization ---
    let mut state_manager_instance = StateManager::new(STATE_FILE);
    if let Err(e) = state_manager_instance.load() {
        error!("Failed to load previous state from {}: {}. Starting with fresh history.", STATE_FILE, e);
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance));
    info!("State manager initialized. Behavioral analysis history will be saved to {}.", STATE_FILE);

    // --- Threat Intelligence Database Initialization ---
    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    info!("Threat intelligence database initialized.");

    // --- Spawn Threat Intelligence Updater Task ---
    if ENABLE_THREAT_INTEL_FEEDS {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone).await;
        });
        info!("Threat intelligence updater task spawned.");
    } else {
        info!("Threat intelligence feed fetching is disabled by configuration.");
    }

    // --- Spawn State Merger Thread ---
    let merger_shutdown_clone = shutdown.clone();
    let merger_state_manager_clone = state_manager.clone();
    let state_merger_handle = thread::Builder::new()
        .name("state_merger".to_string())
        .spawn(move || {
            if let Err(e) = state_merger_thread(
                state_merger_rx,
                merger_state_manager_clone,
                merger_shutdown_clone,
            ) {
                error!("State merger thread encountered a critical error: {}", e);
            }
            info!("State merger thread has exited.");
        })?;
    info!("State merger thread spawned.");

    // --- Spawn Palo Alto Syslog Receiver Task ---
    let syslog_receiver_shutdown = shutdown.clone();
    let raw_log_tx_for_receiver = raw_log_tx.clone();
    let wazuh_raw_tx_for_receiver = wazuh_raw_tx.clone();
    let syslog_receiver_handle = tokio::spawn(async move {
        if let Err(e) = palo_alto_syslog_receiver_thread(
            raw_log_tx_for_receiver, 
            wazuh_raw_tx_for_receiver, 
            syslog_receiver_shutdown
        ).await {
            error!("Palo Alto syslog receiver task encountered a critical error: {}", e);
        }
        info!("Palo Alto syslog receiver task has exited.");
    });
    info!("Palo Alto syslog receiver task spawned.");

    // --- Spawn Palo Alto Enrichment Worker Tasks ---
    // v-- MODIFICATION START --v
    let mut enrichment_handles = Vec::new();
    for i in 0..ENRICHMENT_WORKER_COUNT {
        let raw_log_rx_clone = raw_log_rx.clone();
        let elk_tx_clone = elk_tx.clone();
        let wazuh_enriched_tx_clone = wazuh_enriched_tx.clone();
        let intel_db_clone = threat_intel_db.clone();
        let state_merger_tx_clone = state_merger_tx.clone();
        let shutdown_clone = shutdown.clone();
        
        // Spawn workers in dedicated OS threads, not on the tokio runtime
        let handle = thread::Builder::new()
            .name(format!("pa_enrich_worker_{}", i))
            .spawn(move || {
                // The worker function is now synchronous
                if let Err(e) = palo_alto_enrichment_worker_thread(
                    i,
                    raw_log_rx_clone,
                    elk_tx_clone,
                    wazuh_enriched_tx_clone,
                    intel_db_clone,
                    state_merger_tx_clone,
                    shutdown_clone,
                ) {
                    error!("[Worker {}] Palo Alto enrichment worker thread encountered a critical error: {}", i, e);
                }
                info!("[Worker {}] Palo Alto enrichment worker thread has exited.", i);
            })?;
        enrichment_handles.push(handle);
    }
    // ^-- MODIFICATION END --^
    info!("Spawned {} Palo Alto enrichment worker threads.", ENRICHMENT_WORKER_COUNT);

    // --- Spawn ELK Sender Task ---
    let elk_sender_shutdown = shutdown.clone();
    let elk_sender_handle = tokio::spawn(async move {
        if let Err(e) = elk_sender_thread(elk_rx, elk_sender_shutdown).await {
            error!("ELK sender task encountered a critical error: {}", e);
        }
        info!("ELK sender task has exited.");
    });
    info!("ELK sender task spawned.");

    // --- Spawn Wazuh Enriched Syslog Sender Task ---
    let wazuh_enhanced_sender_shutdown = shutdown.clone();
    let wazuh_enhanced_sender_handle = tokio::spawn(async move {
        if let Err(e) = wazuh_enriched_syslog_sender_thread(wazuh_enriched_rx, wazuh_enhanced_sender_shutdown).await {
            error!("Wazuh enriched syslog sender task encountered a critical error: {}", e);
        }
        info!("Wazuh enriched syslog sender task has exited.");
    });
    info!("Wazuh enriched syslog sender task spawned.");

    // --- Spawn Wazuh Raw Syslog Sender Task ---
    let wazuh_raw_sender_shutdown = shutdown.clone();
    let wazuh_raw_sender_handle = tokio::spawn(async move {
        if let Err(e) = wazuh_raw_syslog_sender_thread(wazuh_raw_rx, wazuh_raw_sender_shutdown).await {
            error!("Wazuh raw syslog sender task encountered a critical error: {}", e);
        }
        info!("Wazuh raw syslog sender task has exited.");
    });
    info!("Wazuh raw syslog sender task spawned.");

    // --- Main Thread Waits for Other Tasks/Threads ---
    info!("Main task waiting for Palo Alto syslog receiver task to complete.");
    syslog_receiver_handle.await.unwrap();

    info!("Main task waiting for all Palo Alto enrichment worker tasks to complete.");
    drop(raw_log_tx);
    drop(wazuh_raw_tx);
    // v-- MODIFICATION START --v
    for handle in enrichment_handles {
        handle.join().unwrap(); // Use join for std::thread::JoinHandle
    }
    // ^-- MODIFICATION END --^

    info!("Main task waiting for ELK sender task to complete.");
    drop(elk_tx);
    elk_sender_handle.await.unwrap();

    info!("Main task waiting for Wazuh enriched syslog sender task to complete.");
    drop(wazuh_enriched_tx);
    wazuh_enhanced_sender_handle.await.unwrap();

    info!("Main task waiting for Wazuh raw syslog sender task to complete.");
    match wazuh_raw_sender_handle.await {
        Ok(_) => info!("Wazuh raw sender task completed successfully."),
        Err(e) => error!("Wazuh raw sender task panicked: {}", e),
    }

    info!("Main task waiting for state merger thread to complete.");
    drop(state_merger_tx);
    state_merger_handle.join().unwrap();

    info!("All worker tasks/threads have finished. Service is performing final shutdown.");
    tokio::spawn(send_telegram_message(
        "✅ *Shutdown Complete:* Palo Alto Log Forwarder service stopped gracefully.".to_string(),
    ));

    Ok(())
}
