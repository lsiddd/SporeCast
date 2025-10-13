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
    thread,
};

mod behavioral;
mod config;
mod parsing;
mod telegram;
mod threat_intel;
mod workers;

use behavioral::{StateManager};
use config::*;
use telegram::send_telegram_message;
use threat_intel::{threat_intel_updater_thread, ThreatIntel};
use workers::*;

// ==============================================================================
// --- Main Function ---
// The entry point of the Fortigate Log Forwarder application.
// Initializes logging, sets up threads, and manages graceful shutdown.
// ==============================================================================
#[tokio::main] // Use tokio's main macro for async entry point
async fn main() -> Result<()> {
    // --- Logging Setup ---
    // Attempts to open the log file for appending. If it fails, logs to stdout only.
    let log_file_result = OpenOptions::new().create(true).append(true).open(LOG_FILE);
    let fern_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            // Define the log message format: Timestamp - Level - ThreadName - Message
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("main"), // Use "main" if thread name is not set.
                message
            ))
        })
        .level(LevelFilter::Debug) // Set default logging level to DEBUG for verbose output.
        .chain(io::stdout()); // Always log to standard output.

    match log_file_result {
        Ok(file) => {
            fern_dispatch.chain(file).apply()?; // Chain to file if successful.
            info!(
                "Logging configured. Detailed logs will be written to {}.",
                LOG_FILE
            );
        }
        Err(e) => {
            eprintln!(
                "Failed to open log file {}: {}. Logging will only go to stdout.",
                LOG_FILE, e
            );
            fern_dispatch.apply()?; // Apply dispatch only to stdout if file logging fails.
        }
    };

    info!("==============================================");
    info!("     Fortigate Raw Log Forwarder (Rust)     ");
    info!("==============================================");
    info!(
        "Service starting up in Belém, State of Pará, Brazil. Current time: {}",
        Local::now().format("%Y-%m-%d %H:%M:%S %Z")
    );
    info!(
        "Configured to receive Fortigate logs on UDP port: {}",
        FORTIGATE_SYSLOG_PORT
    );
    info!(
        "Configured to forward a copy of raw logs to Wazuh on {}:{}",
        WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT
    );
    info!(
        "Configured to forward processed logs to ELK server at: {}:{}",
        ELK_HOST, ELK_PORT
    );

    // Perform an initial connection test to ELK.
    // The service can proceed even if this fails, as the sender thread has reconnection logic.
    if let Err(e) = test_initial_connection().await {
        warn!(
            "Initial ELK connection test failed. Service will attempt to reconnect as needed: {}",
            e
        );
    }

    // --- Signal Handling Setup ---
    // Create an atomic boolean to signal threads for shutdown.
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut signals =
        Signals::new(&[SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
    let signal_shutdown = shutdown.clone(); // Clone for the signal handling thread.
    thread::Builder::new()
        .name("signal_handler".to_string())
        .spawn(move || {
            info!("Signal handler thread started. Waiting for SIGINT or SIGTERM.");
            for sig in signals.forever() {
                warn!(
                    "Received OS signal {:?}. Initiating graceful shutdown sequence...",
                    sig
                );
                signal_shutdown.store(true, Ordering::Relaxed); // Set shutdown flag.
                break; // Exit loop after first signal.
            }
            info!("Signal handler thread finished.");
        })?;

    // --- Channels for Inter-Thread Communication ---
    // Channel from Syslog Receiver to Enrichment Workers (raw logs)
    let (raw_log_tx, raw_log_rx) = bounded(MAX_RECEIVER_QUEUE_SIZE);
    info!(
        "Created raw log channel with max capacity: {} logs.",
        MAX_RECEIVER_QUEUE_SIZE
    );

    // Channel from Syslog Receiver to Wazuh (raw logs)
    let (wazuh_raw_tx, wazuh_raw_rx) = bounded(MAX_RECEIVER_QUEUE_SIZE);
    info!(
        "Created Wazuh raw log channel with max capacity: {} logs.",
        MAX_RECEIVER_QUEUE_SIZE
    );

    // Channel from Enrichment Workers to ELK Sender (enriched JSON logs)
    let (elk_tx, elk_rx) = bounded(MAX_ENRICHMENT_QUEUE_SIZE);
    info!(
        "Created ELK sender channel with max capacity: {} logs.",
        MAX_ENRICHMENT_QUEUE_SIZE
    );

    // New Channel from Enrichment Workers to Wazuh (enriched, formatted logs)
    let (wazuh_enriched_tx, wazuh_enriched_rx) = bounded(MAX_WAZUH_QUEUE_SIZE);
    info!(
        "Created Wazuh enriched log channel with max capacity: {} logs.",
        MAX_WAZUH_QUEUE_SIZE
    );


    // Channel from Enrichment Workers to State Merger (worker's AlertHistory clones)
    let (state_merger_tx, state_merger_rx) = bounded(ENRICHMENT_WORKER_COUNT * 2); // Buffer for history updates
    info!(
        "Created state merger channel with max capacity: {} history updates.",
        ENRICHMENT_WORKER_COUNT * 2
    );

    // --- State Manager Initialization ---
    let mut state_manager_instance = StateManager::new(STATE_FILE);
    if let Err(e) = state_manager_instance.load() {
        error!(
            "Failed to load previous state from {}: {}. Starting with fresh history.",
            STATE_FILE, e
        );
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance));
    info!(
        "State manager initialized. Behavioral analysis history will be saved to {}.",
        STATE_FILE
    );

    // --- Threat Intelligence Database Initialization ---
    // threat_intel_db is now Arc<Mutex<ThreatIntel>> to allow interior mutability and sharing
    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    info!("Threat intelligence database initialized.");

    // --- Spawn Threat Intelligence Updater Task (Async) ---
    if ENABLE_THREAT_INTEL_FEEDS {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone).await;
        });
        info!("Threat intelligence updater task spawned.");
    } else {
        info!("Threat intelligence feed fetching is disabled by configuration. No updater task spawned.");
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

    // --- Spawn Syslog Receiver Task (Async) ---
    let syslog_receiver_shutdown = shutdown.clone();
    let raw_log_tx_for_receiver = raw_log_tx.clone();
    let wazuh_raw_tx_for_receiver = wazuh_raw_tx.clone(); // Pass this clone
    let syslog_receiver_handle = tokio::spawn(async move {
        if let Err(e) =
            syslog_receiver_thread(raw_log_tx_for_receiver, wazuh_raw_tx_for_receiver, syslog_receiver_shutdown).await
        {
            error!("Syslog receiver task encountered a critical error: {}", e);
        }
        info!("Syslog receiver task has exited.");
    });
    info!("Syslog receiver task spawned.");

    // --- Spawn Enrichment Worker Threads (Blocking CPU-bound tasks) ---
    let mut enrichment_handles = Vec::new();
    for i in 0..ENRICHMENT_WORKER_COUNT {
        let raw_log_rx_clone = raw_log_rx.clone();
        let elk_tx_clone = elk_tx.clone();
        let wazuh_enriched_tx_clone = wazuh_enriched_tx.clone(); // Clone for each worker
        let intel_db_clone = threat_intel_db.clone();
        let state_merger_tx_clone = state_merger_tx.clone();
        let shutdown_clone = shutdown.clone();
        let handle = thread::Builder::new()
            .name(format!("enrich_worker_{}", i))
            .spawn(move || {
                if let Err(e) = enrichment_worker_thread(
                    i,
                    raw_log_rx_clone,
                    elk_tx_clone,
                    wazuh_enriched_tx_clone, // Pass to enrichment worker
                    intel_db_clone,
                    state_merger_tx_clone,
                    shutdown_clone,
                ) {
                    error!(
                        "[Worker {}] Enrichment worker thread encountered a critical error: {}",
                        i, e
                    );
                }
                info!("[Worker {}] Enrichment worker thread has exited.", i);
            })?;
        enrichment_handles.push(handle);
    }
    info!(
        "Spawned {} enrichment worker threads.",
        ENRICHMENT_WORKER_COUNT
    );

    // --- Spawn ELK Sender Task (Async) ---
    let elk_sender_shutdown = shutdown.clone();
    let elk_sender_handle = tokio::spawn(async move {
        if let Err(e) = elk_sender_thread(elk_rx, elk_sender_shutdown).await {
            error!("ELK sender task encountered a critical error: {}", e);
        }
        info!("ELK sender task has exited.");
    });
    info!("ELK sender task spawned.");

    // --- Spawn Wazuh Enhanced Syslog Sender Task (Async) ---
    let wazuh_enhanced_sender_shutdown = shutdown.clone();
    let wazuh_enhanced_sender_handle = tokio::spawn(async move {
        if let Err(e) = wazuh_enhanced_syslog_sender_thread(wazuh_enriched_rx, wazuh_enhanced_sender_shutdown).await {
            error!("Wazuh enhanced syslog sender task encountered a critical error: {}", e);
        }
        info!("Wazuh enhanced syslog sender task has exited.");
    });
    info!("Wazuh enhanced syslog sender task spawned.");

    // --- Spawn Wazuh Raw Syslog Sender Task (Async) ---
    let wazuh_raw_sender_shutdown = shutdown.clone();
    let wazuh_raw_sender_handle = tokio::spawn(async move {
        if let Err(e) = wazuh_raw_syslog_sender_thread(wazuh_raw_rx, wazuh_raw_sender_shutdown).await {
            error!("Wazuh raw syslog sender task encountered a critical error: {}", e);
        }
        info!("Wazuh raw syslog sender task has exited.");
    });
    info!("Wazuh raw syslog sender task spawned.");

    // --- Main Thread Waits for Other Tasks/Threads ---
    info!("Main task waiting for syslog_receiver task to complete.");
    syslog_receiver_handle.await.unwrap();

    info!("Main task waiting for all enrichment worker threads to complete.");
    drop(raw_log_tx); // Close the original sender to signal workers to drain
    drop(wazuh_raw_tx); // Close this sender too
    for handle in enrichment_handles {
        handle.join().unwrap();
    }

    info!("Main task waiting for elk_sender task to complete.");
    drop(elk_tx); // Close the sender side of the elk channel to signal sender to finish
    elk_sender_handle.await.unwrap();

    info!("Main task waiting for wazuh_enhanced_syslog_sender task to complete.");
    drop(wazuh_enriched_tx); // Close the sender side of the wazuh enriched channel
    wazuh_enhanced_sender_handle.await.unwrap();

    info!("Main task waiting for wazuh_raw_syslog_sender task to complete.");
    match wazuh_raw_sender_handle.await {
        Ok(_) => info!("Wazuh raw sender task completed successfully."),
        Err(e) => error!("Wazuh raw sender task panicked: {}", e),
    }

    info!("Main task waiting for state_merger thread to complete.");
    drop(state_merger_tx); // Close the sender side of the state merger channel
    state_merger_handle.join().unwrap();

    info!("All worker tasks/threads have finished. Service is performing final shutdown.");
    tokio::spawn(send_telegram_message(
        "✅ *Shutdown Complete:* Fortigate Log Forwarder service stopped gracefully.".to_string(),
    ));

    Ok(())
}