use anyhow::{anyhow, Context, Result};
use chrono::Local;
use crossbeam_channel::bounded;
use log::{error, info, warn};
use parking_lot::Mutex;
use serde_json::Value;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use crate::{
    application::runtime::{spawn_signal_handler, state_merger_queue_size},
    application::state::StateManager,
    application::threat_intel::threat_intel_updater_thread,
    application::workers::{
        state_merger_thread, tshark_enrichment_worker_thread, tshark_stdin_receiver_thread,
    },
    domain::indicators::ThreatIntel,
    infrastructure::config::ForwarderConfig,
    infrastructure::geoip::GeoIpEnricher,
    infrastructure::senders::{elk_sender_thread, test_initial_connection},
};

pub async fn run(config: ForwarderConfig, stdout_mode: bool) -> Result<()> {
    let elk_host = config.network.elk_host.clone();
    let elk_port = config.network.elk_port;
    let enrichment_worker_count = config.performance.enrichment_worker_count;
    let batch_size = config.performance.elk_batch_size;
    let flush_interval_secs = config.performance.elk_batch_flush_interval_secs;
    let state_file = config.logging.state_file.clone();
    let max_receiver_queue = config.performance.max_receiver_queue_size;
    let max_enrichment_queue = config.performance.max_enrichment_queue_size;

    info!("==============================================");
    info!("     Tshark EK Stream Forwarder (Rust)      ");
    info!("==============================================");
    info!(
        "Service starting. {}",
        Local::now().format("%Y-%m-%d %H:%M:%S %Z")
    );

    if stdout_mode {
        info!("Mode: stdout (enriched JSON printed to stdout, no ELK)");
    } else {
        info!("Mode: ELK at {}:{}", elk_host, elk_port);
        if let Err(e) = test_initial_connection(&elk_host, elk_port).await {
            warn!(
                "Initial ELK connection test failed. Will retry as needed: {}",
                e
            );
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let _signal_handler = spawn_signal_handler(shutdown.clone())?;

    let (parsed_tx, parsed_rx) = bounded(max_receiver_queue);
    let (elk_tx, elk_rx) = bounded::<Value>(max_enrichment_queue);
    let (state_merger_tx, state_merger_rx) =
        bounded(state_merger_queue_size(enrichment_worker_count)?);

    let mut state_manager_instance = StateManager::new(&state_file);
    if let Err(e) = state_manager_instance.load() {
        info!("No prior state at {}: {}. Starting fresh.", state_file, e);
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance));

    let geoip_enricher: Option<Arc<GeoIpEnricher>> = if config.geoip.enabled {
        GeoIpEnricher::open(&config.geoip.database_path).map(Arc::new)
    } else {
        None
    };

    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    let intel_ready = Arc::new(AtomicBool::new(false));
    let threat_intel_handle = if config.threat_intelligence.enable_threat_intel_feeds {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        let intel_ready_clone = intel_ready.clone();
        Some(tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone, intel_ready_clone).await;
        }))
    } else {
        intel_ready.store(true, Ordering::Relaxed);
        None
    };

    let state_merger_handle = thread::Builder::new()
        .name("state_merger".to_string())
        .spawn({
            let shutdown_clone = shutdown.clone();
            let state_manager_clone = state_manager.clone();
            move || {
                if let Err(e) =
                    state_merger_thread(state_merger_rx, state_manager_clone, shutdown_clone)
                {
                    error!("State merger thread error: {}", e);
                }
            }
        })?;

    if config.threat_intelligence.enable_threat_intel_feeds {
        info!("Waiting for initial threat intel load before processing packets...");
        while !intel_ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        info!(
            "Threat intel ready ({} indicators). Starting packet processing.",
            threat_intel_db.lock().indicator_count()
        );
    }

    let stdin_receiver_handle = tokio::spawn({
        let shutdown_clone = shutdown.clone();
        let tx = parsed_tx.clone();
        async move {
            if let Err(e) = tshark_stdin_receiver_thread(tx, shutdown_clone).await {
                error!("Tshark stdin receiver error: {}", e);
            }
        }
    });

    let mut enrichment_handles = Vec::new();
    for i in 0..enrichment_worker_count {
        let handle = thread::Builder::new()
            .name(format!("tshark_enrich_worker_{}", i))
            .spawn({
                let parsed_rx_clone = parsed_rx.clone();
                let elk_tx_clone = elk_tx.clone();
                let intel_db_clone = threat_intel_db.clone();
                let state_merger_tx_clone = state_merger_tx.clone();
                let shutdown_clone = shutdown.clone();
                let geoip_clone = geoip_enricher.clone();
                move || {
                    if let Err(e) = tshark_enrichment_worker_thread(
                        i,
                        parsed_rx_clone,
                        elk_tx_clone,
                        intel_db_clone,
                        state_merger_tx_clone,
                        shutdown_clone,
                        geoip_clone,
                    ) {
                        error!("[TsharkWorker {}] Critical error: {}", i, e);
                    }
                }
            })?;
        enrichment_handles.push(handle);
    }
    info!(
        "Spawned {} enrichment worker threads.",
        enrichment_worker_count
    );

    let elk_sender_handle = if stdout_mode {
        let elk_rx_clone = elk_rx.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            let stdout = io::stdout();
            loop {
                if shutdown_clone.load(Ordering::Relaxed) && elk_rx_clone.is_empty() {
                    break;
                }
                let elk_rx_c = elk_rx_clone.clone();
                match tokio::task::spawn_blocking(move || {
                    elk_rx_c.recv_timeout(Duration::from_secs(1))
                })
                .await
                {
                    Ok(Ok(value)) => {
                        if let Ok(line) = serde_json::to_string(&value) {
                            let mut out = stdout.lock();
                            let _ = writeln!(out, "{}", line);
                        }
                    }
                    Ok(Err(crossbeam_channel::RecvTimeoutError::Disconnected)) => break,
                    Ok(Err(crossbeam_channel::RecvTimeoutError::Timeout)) => {}
                    Err(_) => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    } else {
        tokio::spawn(elk_sender_thread(
            elk_rx,
            shutdown.clone(),
            elk_host.clone(),
            elk_port,
            batch_size,
            flush_interval_secs,
        ))
    };

    stdin_receiver_handle
        .await
        .context("Tshark stdin receiver task panicked")?;

    info!("Stdin closed. Draining enrichment queue.");
    drop(parsed_tx);
    for handle in enrichment_handles {
        handle
            .join()
            .map_err(|_| anyhow!("Enrichment worker thread panicked"))?;
    }

    drop(elk_tx);
    elk_sender_handle
        .await
        .context("Output sender task panicked")?
        .context("Output sender task failed")?;

    if let Some(handle) = threat_intel_handle {
        handle.await.context("Threat intel updater task panicked")?;
    }

    drop(state_merger_tx);
    state_merger_handle
        .join()
        .map_err(|_| anyhow!("State merger thread panicked"))?;

    info!("All tasks finished.");
    Ok(())
}
