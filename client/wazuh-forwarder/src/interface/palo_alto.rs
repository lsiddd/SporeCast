use anyhow::{anyhow, Context, Result};
use chrono::Local;
use crossbeam_channel::bounded;
use log::{error, info, warn};
use parking_lot::Mutex;
use std::{
    io::{self, BufRead, Write},
    sync::{atomic::AtomicBool, Arc},
    thread,
};

use crate::{
    application::runtime::{spawn_signal_handler, state_merger_queue_size},
    application::state::StateManager,
    application::threat_intel::threat_intel_updater_thread,
    application::workers::{
        palo_alto_enrichment_worker_thread, palo_alto_syslog_receiver_thread, state_merger_thread,
    },
    domain::indicators::ThreatIntel,
    infrastructure::config::ForwarderConfig,
    infrastructure::geoip::GeoIpEnricher,
    infrastructure::senders::{
        elk_sender_thread, test_initial_connection, wazuh_enriched_syslog_sender_thread,
    },
};

pub async fn run(config: ForwarderConfig) -> Result<()> {
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

    info!("==============================================");
    info!("     Palo Alto Raw Log Forwarder (Rust)     ");
    info!("==============================================");
    info!(
        "Service starting. Current time: {}",
        Local::now().format("%Y-%m-%d %H:%M:%S %Z")
    );
    info!(
        "Configured to receive Palo Alto logs on UDP port: {}",
        syslog_port
    );
    info!(
        "Configured to forward enriched logs to Wazuh on {}:{}",
        wazuh_host, wazuh_port
    );
    info!(
        "Configured to forward processed logs to ELK server at: {}:{}",
        elk_host, elk_port
    );

    if let Err(e) = test_initial_connection(&elk_host, elk_port).await {
        warn!(
            "Initial ELK connection test failed. Service will attempt to reconnect as needed: {}",
            e
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let _signal_handler = spawn_signal_handler(shutdown.clone())?;

    let (raw_log_tx, raw_log_rx) = bounded(max_receiver_queue);
    let (elk_tx, elk_rx) = bounded(max_enrichment_queue);
    let (wazuh_enriched_tx, wazuh_enriched_rx) = bounded(max_wazuh_queue);
    let (state_merger_tx, state_merger_rx) =
        bounded(state_merger_queue_size(enrichment_worker_count)?);

    let mut state_manager_instance = StateManager::new(&state_file);
    if let Err(e) = state_manager_instance.load() {
        error!(
            "Failed to load previous state from {}: {}. Starting with fresh history.",
            state_file, e
        );
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance));

    let geoip_enricher: Option<Arc<GeoIpEnricher>> = if config.geoip.enabled {
        GeoIpEnricher::open(&config.geoip.database_path).map(Arc::new)
    } else {
        info!("GeoIP enrichment disabled in config.");
        None
    };

    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    let intel_ready = Arc::new(AtomicBool::new(false));
    let threat_intel_handle = if config.threat_intelligence.enable_threat_intel_feeds {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        let intel_ready_clone = intel_ready.clone();
        info!("Threat intelligence updater task spawned.");
        Some(tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone, intel_ready_clone).await;
        }))
    } else {
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
                    error!("State merger thread encountered a critical error: {}", e);
                }
            }
        })?;

    let syslog_receiver_handle = tokio::spawn({
        let shutdown_clone = shutdown.clone();
        let raw_log_tx_clone = raw_log_tx.clone();
        async move {
            if let Err(e) =
                palo_alto_syslog_receiver_thread(raw_log_tx_clone, shutdown_clone, syslog_port)
                    .await
            {
                error!(
                    "Palo Alto syslog receiver task encountered a critical error: {}",
                    e
                );
            }
        }
    });

    let mut enrichment_handles = Vec::new();
    for i in 0..enrichment_worker_count {
        let handle = thread::Builder::new()
            .name(format!("pa_enrich_worker_{}", i))
            .spawn({
                let raw_log_rx_clone = raw_log_rx.clone();
                let elk_tx_clone = elk_tx.clone();
                let wazuh_enriched_tx_clone = wazuh_enriched_tx.clone();
                let intel_db_clone = threat_intel_db.clone();
                let state_merger_tx_clone = state_merger_tx.clone();
                let shutdown_clone = shutdown.clone();
                let geoip_clone = geoip_enricher.clone();
                move || {
                    if let Err(e) = palo_alto_enrichment_worker_thread(
                        i,
                        raw_log_rx_clone,
                        elk_tx_clone,
                        wazuh_enriched_tx_clone,
                        intel_db_clone,
                        state_merger_tx_clone,
                        shutdown_clone,
                        geoip_clone,
                    ) {
                        error!(
                            "[Worker {}] Palo Alto enrichment worker encountered a critical error: {}",
                            i, e
                        );
                    }
                    info!("[Worker {}] Palo Alto enrichment worker has exited.", i);
                }
            })?;
        enrichment_handles.push(handle);
    }
    info!(
        "Spawned {} Palo Alto enrichment worker threads.",
        enrichment_worker_count
    );

    let elk_sender_handle = tokio::spawn(elk_sender_thread(
        elk_rx,
        shutdown.clone(),
        elk_host.clone(),
        elk_port,
        batch_size,
        flush_interval_secs,
    ));
    let wazuh_sender_handle = tokio::spawn(wazuh_enriched_syslog_sender_thread(
        wazuh_enriched_rx,
        shutdown.clone(),
        wazuh_host,
        wazuh_port,
    ));

    syslog_receiver_handle
        .await
        .context("Palo Alto syslog receiver task panicked")?;

    info!("Draining enrichment workers.");
    drop(raw_log_tx);
    for handle in enrichment_handles {
        handle
            .join()
            .map_err(|_| anyhow!("Palo Alto enrichment worker thread panicked"))?;
    }

    drop(elk_tx);
    elk_sender_handle
        .await
        .context("ELK sender task panicked")?
        .context("ELK sender task failed")?;

    drop(wazuh_enriched_tx);
    wazuh_sender_handle
        .await
        .context("Wazuh enriched syslog sender task panicked")?
        .context("Wazuh enriched syslog sender task failed")?;

    if let Some(handle) = threat_intel_handle {
        handle
            .await
            .context("Threat intelligence updater task panicked")?;
    }

    drop(state_merger_tx);
    state_merger_handle
        .join()
        .map_err(|_| anyhow!("State merger thread panicked"))?;

    info!("All worker tasks/threads have finished. Service is performing final shutdown.");
    Ok(())
}

/// Reads Palo Alto syslog lines from stdin, enriches each, and prints JSON to stdout.
/// Used for dev/test: `cat firewall.log | palo_alto_forwarder --stdin`
pub async fn run_stdin(config: ForwarderConfig) -> Result<()> {
    use crate::application::threat_intel::threat_intel_updater_thread;
    use crate::domain::behavioral::AlertHistory;
    use crate::domain::enrichment::enrich_and_analyze_log;
    use crate::domain::palo_alto::parse_palo_alto_log_to_json;
    use std::time::Duration;

    info!("Palo Alto stdin mode: reading syslog lines from stdin");

    let geoip = if config.geoip.enabled {
        GeoIpEnricher::open(&config.geoip.database_path).map(Arc::new)
    } else {
        None
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    let intel_ready = Arc::new(AtomicBool::new(false));

    let threat_intel_handle = if config.threat_intelligence.enable_threat_intel_feeds {
        info!("Starting threat intel updater. Waiting for initial feed load...");
        let intel_clone = intel_db.clone();
        let shutdown_clone = shutdown.clone();
        let intel_ready_clone = intel_ready.clone();
        Some(tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone, intel_ready_clone).await;
        }))
    } else {
        info!("Threat intel feeds disabled in config.");
        intel_ready.store(true, std::sync::atomic::Ordering::Relaxed);
        None
    };

    if config.threat_intelligence.enable_threat_intel_feeds {
        while !intel_ready.load(std::sync::atomic::Ordering::Acquire) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        info!(
            "Threat intel ready ({} indicators). Starting log processing.",
            intel_db.lock().indicator_count()
        );
    }

    let intel_arc = Arc::new(intel_db.lock().clone());
    let mut state = AlertHistory::default();
    let stdout = io::stdout();

    for line in io::stdin().lock().lines() {
        let line = line.context("stdin read error")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match parse_palo_alto_log_to_json(line) {
            Ok(parsed) => {
                let enriched = enrich_and_analyze_log(
                    parsed,
                    &intel_arc,
                    &mut state,
                    geoip.as_deref().map(|g| g as &dyn crate::domain::ports::GeoIpLookup),
                );
                if let Ok(json_str) = serde_json::to_string(&enriched) {
                    let mut out = stdout.lock();
                    let _ = writeln!(out, "{}", json_str);
                }
            }
            Err(e) => {
                warn!("Failed to parse line: {}. Line: {}", e, &line[..line.len().min(80)]);
            }
        }
    }

    info!("Stdin closed. Signalling threat intel updater to stop.");
    shutdown.store(true, std::sync::atomic::Ordering::Release);
    if let Some(handle) = threat_intel_handle {
        let _ = handle.await;
    }
    Ok(())
}
