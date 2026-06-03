use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use serde_json::Value;
use parking_lot::Mutex;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

use crate::application::state::StateManager;
use crate::domain::enrichment::enrich_and_analyze_log;
use crate::domain::palo_alto::{format_json_to_palo_alto_syslog, parse_palo_alto_log_to_json};
use crate::domain::{behavioral::AlertHistory, indicators::ThreatIntel};
use crate::infrastructure::defaults::{
    DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD, MAX_RECEIVER_QUEUE_SIZE,
};
use crate::infrastructure::geoip::GeoIpEnricher;
use crate::infrastructure::performance::QUEUE_MONITOR;


// ==============================================================================
// --- Palo Alto Syslog Receiver Thread ---
// ==============================================================================
/// Receives Palo Alto syslog messages over UDP and enqueues raw log lines.
#[tracing::instrument(skip(raw_log_tx, shutdown))]
pub async fn palo_alto_syslog_receiver_thread(
    raw_log_tx: Sender<String>,
    shutdown: Arc<AtomicBool>,
    syslog_port: u16,
) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", syslog_port);
    info!(
        "Starting Palo Alto syslog receiver on UDP port {}",
        syslog_port
    );

    let socket = UdpSocket::bind(&bind_addr)
        .await
        .context(format!("Failed to bind UDP socket to {}", bind_addr))?;
    info!(
        "Palo Alto syslog receiver successfully bound to {}",
        bind_addr
    );

    let mut buffer = [0; 8192];
    let mut log_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                let raw_message = String::from_utf8_lossy(&buffer[..size]);
                debug!("Received Palo Alto log from {}: {}", addr, raw_message);

                log_count = log_count.saturating_add(1);
                if log_count.is_multiple_of(1000) {
                    info!("Processed {} Palo Alto logs so far", log_count);
                }

                QUEUE_MONITOR.check_queue_health(
                    raw_log_tx.len(),
                    MAX_RECEIVER_QUEUE_SIZE,
                    "raw_log_queue",
                );

                if let Err(e) = raw_log_tx.try_send(raw_message.into_owned()) {
                    warn!(
                        "Failed to send raw log to enrichment queue: {}. Queue may be full.",
                        e
                    );
                }
            }
            Ok(Err(e)) => {
                error!("UDP receive error: {}. Will retry.", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) => {
                debug!("UDP receive timeout, checking for shutdown signal");
            }
        }
    }

    info!(
        "Palo Alto syslog receiver shutting down. Total logs processed: {}",
        log_count
    );
    Ok(())
}

// ==============================================================================
// --- Palo Alto Enrichment Worker Thread ---
// ==============================================================================
/// Parses, enriches, and routes raw Palo Alto logs to ELK/Wazuh queues.
#[tracing::instrument(skip(
    raw_log_rx,
    elk_tx,
    wazuh_enriched_tx,
    threat_intel,
    state_merger_tx,
    shutdown,
    geoip
))]
pub fn palo_alto_enrichment_worker_thread(
    worker_id: usize,
    raw_log_rx: Receiver<String>,
    elk_tx: Sender<Value>,
    wazuh_enriched_tx: Sender<String>,
    threat_intel: Arc<Mutex<ThreatIntel>>,
    state_merger_tx: Sender<AlertHistory>,
    shutdown: Arc<AtomicBool>,
    geoip: Option<Arc<GeoIpEnricher>>,
) -> Result<()> {
    info!(
        "[Worker {}] Starting Palo Alto enrichment worker thread",
        worker_id
    );

    let mut worker_state = AlertHistory::default();
    let mut processed_count = 0u64;
    let mut enriched_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match raw_log_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(raw_log) => {
                processed_count = processed_count.saturating_add(1);
                debug!(
                    "[Worker {}] Processing raw log #{}: {}",
                    worker_id, processed_count, raw_log
                );

                match parse_palo_alto_log_to_json(&raw_log) {
                    Ok(mut parsed_log) => {
                        debug!("[Worker {}] Successfully parsed Palo Alto log", worker_id);

                        let should_skip_behavioral =
                            DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD && QUEUE_MONITOR.is_high_load();

                        if !should_skip_behavioral {
                            let intel_arc = Arc::new(threat_intel.lock().clone());
                            parsed_log = enrich_and_analyze_log(
                                parsed_log,
                                &intel_arc,
                                &mut worker_state,
                                geoip.as_deref().map(|g| g as &dyn crate::domain::ports::GeoIpLookup),
                            );

                            if parsed_log.get("forwarder_enrichment").is_some() {
                                enriched_count = enriched_count.saturating_add(1);
                                debug!("[Worker {}] Log enriched with threat intelligence and behavioral analysis", worker_id);

                                // Only forward to Wazuh if threat intel indicators were found
                                match format_json_to_palo_alto_syslog(&parsed_log) {
                                    Ok(formatted_syslog) => {
                                        if let Err(e) = wazuh_enriched_tx.try_send(formatted_syslog)
                                        {
                                            warn!("[Worker {}] Failed to send formatted log to Wazuh enriched queue: {}. Queue may be full.", worker_id, e);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("[Worker {}] Failed to format JSON back to syslog for Wazuh: {}", worker_id, e);
                                    }
                                }
                            } else {
                                debug!("[Worker {}] Skipping Wazuh forwarding - no threat intel indicators found", worker_id);
                            }
                        } else {
                            debug!(
                                "[Worker {}] Skipping behavioral analysis due to high load",
                                worker_id
                            );
                        }

                        // 2. Send the original `parsed_log` to ELK, consuming it (no clone).
                        if let Err(e) = elk_tx.try_send(parsed_log) {
                            warn!("[Worker {}] Failed to send enriched log to sender queue: {}. Queue may be full.", worker_id, e);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "[Worker {}] Failed to parse Palo Alto log: {}. Raw log: {}",
                            worker_id, e, raw_log
                        );
                    }
                }

                if processed_count.is_multiple_of(100) {
                    if let Err(e) = state_merger_tx.try_send(worker_state.clone()) {
                        debug!("[Worker {}] Failed to send state update: {}", worker_id, e);
                    }
                    info!(
                        "[Worker {}] Processed {} logs, {} enriched",
                        worker_id, processed_count, enriched_count
                    );
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    if let Err(e) = state_merger_tx.try_send(worker_state) {
        warn!(
            "[Worker {}] Failed to send final state update: {}",
            worker_id, e
        );
    }

    info!(
        "[Worker {}] Palo Alto enrichment worker shutting down. Processed: {}, Enriched: {}",
        worker_id, processed_count, enriched_count
    );
    Ok(())
}

// ==============================================================================
// --- State Merger Thread ---
// ==============================================================================
/// Merges per-worker behavioral state and persists it periodically.
#[tracing::instrument(skip(state_merger_rx, state_manager, shutdown))]
pub fn state_merger_thread(
    state_merger_rx: Receiver<AlertHistory>,
    state_manager: Arc<Mutex<StateManager>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Starting Palo Alto state merger thread");

    let mut updates_processed = 0u64;
    let mut last_save = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        match state_merger_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(worker_state) => {
                updates_processed = updates_processed.saturating_add(1);
                debug!("Merging state update #{}", updates_processed);

                let mut manager = state_manager.lock();
                manager.merge_worker_state(&worker_state);

                if last_save.elapsed().as_secs() >= 10 {
                    if let Err(e) = manager.save() {
                        error!("Failed to save state to disk: {}", e);
                    } else {
                        debug!("Saved behavioral analysis state to disk");
                    }
                    last_save = Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    let manager = state_manager.lock();
    if let Err(e) = manager.save() {
        error!("Failed to save final state to disk: {}", e);
    } else {
        info!("Saved final behavioral analysis state to disk");
    }

    info!(
        "Palo Alto state merger thread shutting down. Updates processed: {}",
        updates_processed
    );
    Ok(())
}
