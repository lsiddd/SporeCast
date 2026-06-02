use anyhow::{anyhow, Context, Result};
use chrono::Local;
use clap::Parser;
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

use wazuh_forwarder::{
    behavioral::StateManager,
    config_reader::ForwarderConfig,
    palo_alto_config::*,
    palo_alto_workers::*,
    threat_intel::{threat_intel_updater_thread, ThreatIntel},
};

#[derive(Parser)]
#[command(name = "palo_alto_forwarder")]
struct Cli {
    #[arg(short, long, default_value = "forwarder-config.toml")]
    config: String,
}

// ==============================================================================
// --- Main Function ---
// ==============================================================================
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load runtime config, falling back to hardcoded defaults if file missing/invalid
    let config = ForwarderConfig::load_from_file(&cli.config).unwrap_or_else(|e| {
        eprintln!(
            "Failed to load config from '{}': {}. Using hardcoded defaults.",
            cli.config, e
        );
        ForwarderConfig::default()
    });

    config.validate().context("Config validation failed")?;

    let elk_host = config.network.elk_host.clone();
    let elk_port = config.network.elk_port;
    let wazuh_host = config.network.wazuh_host.clone();
    let wazuh_port = config.network.wazuh_port;
    let syslog_port = config.network.syslog_port;
    let enrichment_worker_count = config.performance.enrichment_worker_count;
    let batch_size = config.performance.elk_batch_size;
    let flush_interval_secs = config.performance.elk_batch_flush_interval_secs;
    let state_file = config.logging.state_file.clone();
    let max_receiver_queue = config.performance.max_receiver_queue_size;
    let max_enrichment_queue = config.performance.max_enrichment_queue_size;
    let max_wazuh_queue = config.performance.max_wazuh_queue_size;

    // Logging Setup
    let mut fern_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("main"),
                message
            ))
        })
        .level(LevelFilter::Info)
        .chain(io::stdout());

    if NO_LOG_FILE {
        fern_dispatch.apply()?;
        info!("Logging configured for stdout only (log file writes disabled).");
    } else {
        let log_file_path = config.logging.log_file.as_str();
        let log_file_result = OpenOptions::new().create(true).append(true).open(log_file_path);
        match log_file_result {
            Ok(file) => {
                fern_dispatch = fern_dispatch.chain(file);
                fern_dispatch.apply()?;
                info!("Logging configured. Detailed logs will be written to {}.", log_file_path);
            }
            Err(e) => {
                eprintln!("Failed to open log file {}: {}. Logging will only go to stdout.", log_file_path, e);
                fern_dispatch.apply()?;
            }
        }
    }

    info!("==============================================");
    info!("     Palo Alto Raw Log Forwarder (Rust)     ");
    info!("==============================================");
    info!(
        "Service starting. Current time: {}",
        Local::now().format("%Y-%m-%d %H:%M:%S %Z")
    );
    info!("Config loaded from: {}", cli.config);
    info!("Configured to receive Palo Alto logs on UDP port: {}", syslog_port);
    info!("Configured to forward enriched logs to Wazuh on {}:{}", wazuh_host, wazuh_port);
    info!("Configured to forward processed logs to ELK server at: {}:{}", elk_host, elk_port);

    if let Err(e) = test_initial_connection(&elk_host, elk_port).await {
        warn!("Initial ELK connection test failed. Service will attempt to reconnect as needed: {}", e);
    }

    // Signal Handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut signals = Signals::new([SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
    let signal_shutdown = shutdown.clone();
    thread::Builder::new()
        .name("signal_handler".to_string())
        .spawn(move || {
            info!("Signal handler thread started. Waiting for SIGINT or SIGTERM.");
            if let Some(sig) = signals.forever().next() {
                warn!("Received OS signal {:?}. Initiating graceful shutdown sequence...", sig);
                signal_shutdown.store(true, Ordering::Release);
            }
            info!("Signal handler thread finished.");
        })?;

    // Channels
    let (raw_log_tx, raw_log_rx) = bounded(max_receiver_queue);
    let (elk_tx, elk_rx) = bounded(max_enrichment_queue);
    let (wazuh_enriched_tx, wazuh_enriched_rx) = bounded(max_wazuh_queue);
    let state_merger_queue_size = enrichment_worker_count
        .checked_mul(2)
        .ok_or_else(|| anyhow!("enrichment worker count is too large"))?;
    let (state_merger_tx, state_merger_rx) = bounded(state_merger_queue_size);

    // State Manager
    let mut state_manager_instance = StateManager::new(&state_file);
    if let Err(e) = state_manager_instance.load() {
        error!("Failed to load previous state from {}: {}. Starting with fresh history.", state_file, e);
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance));

    // Threat Intel
    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    let threat_intel_handle = if ENABLE_THREAT_INTEL_FEEDS {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        Some(tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone).await;
        }))
    } else {
        None
    };
    if threat_intel_handle.is_some() {
        info!("Threat intelligence updater task spawned.");
    }

    // State Merger Thread
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
        })?;

    // Syslog Receiver Task
    let syslog_receiver_shutdown = shutdown.clone();
    let raw_log_tx_for_receiver = raw_log_tx.clone();
    let syslog_receiver_handle = tokio::spawn(async move {
        if let Err(e) = palo_alto_syslog_receiver_thread(
            raw_log_tx_for_receiver,
            syslog_receiver_shutdown,
            syslog_port,
        ).await {
            error!("Palo Alto syslog receiver task encountered a critical error: {}", e);
        }
    });

    // Enrichment Worker Threads
    let mut enrichment_handles = Vec::new();
    for i in 0..enrichment_worker_count {
        let raw_log_rx_clone = raw_log_rx.clone();
        let elk_tx_clone = elk_tx.clone();
        let wazuh_enriched_tx_clone = wazuh_enriched_tx.clone();
        let intel_db_clone = threat_intel_db.clone();
        let state_merger_tx_clone = state_merger_tx.clone();
        let shutdown_clone = shutdown.clone();

        let handle = thread::Builder::new()
            .name(format!("pa_enrich_worker_{}", i))
            .spawn(move || {
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
    info!("Spawned {} Palo Alto enrichment worker threads.", enrichment_worker_count);

    // Sender Tasks
    let elk_sender_handle = tokio::spawn(elk_sender_thread(
        elk_rx,
        shutdown.clone(),
        elk_host.clone(),
        elk_port,
        batch_size,
        flush_interval_secs,
    ));
    let wazuh_enhanced_sender_handle = tokio::spawn(wazuh_enriched_syslog_sender_thread(
        wazuh_enriched_rx,
        shutdown.clone(),
        wazuh_host,
        wazuh_port,
    ));

    // Wait for shutdown
    syslog_receiver_handle
        .await
        .context("Palo Alto syslog receiver task panicked")?;

    info!("Main task waiting for all Palo Alto enrichment worker tasks to complete.");
    drop(raw_log_tx);
    for handle in enrichment_handles {
        handle
            .join()
            .map_err(|_| anyhow!("Palo Alto enrichment worker thread panicked"))?;
    }

    info!("Main task waiting for ELK sender task to complete.");
    drop(elk_tx);
    elk_sender_handle
        .await
        .context("ELK sender task panicked")?
        .context("ELK sender task failed")?;

    info!("Main task waiting for Wazuh enriched syslog sender task to complete.");
    drop(wazuh_enriched_tx);
    wazuh_enhanced_sender_handle
        .await
        .context("Wazuh enriched syslog sender task panicked")?
        .context("Wazuh enriched syslog sender task failed")?;

    if let Some(handle) = threat_intel_handle {
        handle
            .await
            .context("Threat intelligence updater task panicked")?;
    }

    info!("Main task waiting for state merger thread to complete.");
    drop(state_merger_tx);
    state_merger_handle
        .join()
        .map_err(|_| anyhow!("State merger thread panicked"))?;

    info!("All worker tasks/threads have finished. Service is performing final shutdown.");

    Ok(())
}
