use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use parking_lot::Mutex;
use serde_json::Value;
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
use crate::domain::ports::GeoIpLookup;
use crate::domain::{behavioral::AlertHistory, indicators::ThreatIntel};
use crate::infrastructure::defaults::{
    DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD, MAX_RECEIVER_QUEUE_SIZE,
};
use crate::infrastructure::geoip::GeoIpEnricher;
use crate::infrastructure::performance::QUEUE_MONITOR;

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct PaloAltoProcessOutcome {
    pub parsed: bool,
    pub enriched: bool,
    pub elk_sent: bool,
    pub wazuh_sent: bool,
}

pub(crate) fn process_palo_alto_log_item(
    worker_id: usize,
    raw_log: &str,
    elk_tx: &Sender<Value>,
    wazuh_enriched_tx: &Sender<String>,
    threat_intel: &ThreatIntel,
    worker_state: &mut AlertHistory,
    geoip: Option<&dyn GeoIpLookup>,
    skip_enrichment: bool,
) -> PaloAltoProcessOutcome {
    let mut outcome = PaloAltoProcessOutcome::default();

    match parse_palo_alto_log_to_json(raw_log) {
        Ok(mut parsed_log) => {
            outcome.parsed = true;
            debug!("[Worker {}] Successfully parsed Palo Alto log", worker_id);

            if !skip_enrichment {
                let intel_arc = Arc::new(threat_intel.clone());
                parsed_log = enrich_and_analyze_log(parsed_log, &intel_arc, worker_state, geoip);

                if parsed_log.get("forwarder_enrichment").is_some() {
                    outcome.enriched = true;
                    debug!(
                        "[Worker {}] Log enriched with threat intelligence and behavioral analysis",
                        worker_id
                    );

                    match format_json_to_palo_alto_syslog(&parsed_log) {
                        Ok(formatted_syslog) => match wazuh_enriched_tx.try_send(formatted_syslog)
                        {
                            Ok(()) => outcome.wazuh_sent = true,
                            Err(e) => warn!(
                                "[Worker {}] Failed to send formatted log to Wazuh enriched queue: {}. Queue may be full.",
                                worker_id, e
                            ),
                        },
                        Err(e) => warn!(
                            "[Worker {}] Failed to format JSON back to syslog for Wazuh: {}",
                            worker_id, e
                        ),
                    }
                } else {
                    debug!(
                        "[Worker {}] Skipping Wazuh forwarding - no threat intel indicators found",
                        worker_id
                    );
                }
            } else {
                debug!(
                    "[Worker {}] Skipping enrichment due to high load",
                    worker_id
                );
            }

            match elk_tx.try_send(parsed_log) {
                Ok(()) => outcome.elk_sent = true,
                Err(e) => warn!(
                    "[Worker {}] Failed to send enriched log to sender queue: {}. Queue may be full.",
                    worker_id, e
                ),
            }
        }
        Err(e) => warn!(
            "[Worker {}] Failed to parse Palo Alto log: {}. Raw log: {}",
            worker_id, e, raw_log
        ),
    }

    outcome
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct PaloAltoReceiverOutcome {
    pub enqueued: bool,
}

pub(crate) fn enqueue_palo_alto_syslog_message(
    raw_message: &str,
    raw_log_tx: &Sender<String>,
    queue_capacity: usize,
) -> PaloAltoReceiverOutcome {
    QUEUE_MONITOR.check_queue_health(raw_log_tx.len(), queue_capacity, "raw_log_queue");

    match raw_log_tx.try_send(raw_message.to_string()) {
        Ok(()) => PaloAltoReceiverOutcome { enqueued: true },
        Err(e) => {
            warn!(
                "Failed to send raw log to enrichment queue: {}. Queue may be full.",
                e
            );
            PaloAltoReceiverOutcome { enqueued: false }
        }
    }
}

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

                enqueue_palo_alto_syslog_message(
                    raw_message.as_ref(),
                    &raw_log_tx,
                    MAX_RECEIVER_QUEUE_SIZE,
                );
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

                let should_skip_enrichment =
                    DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD && QUEUE_MONITOR.is_high_load();
                let intel_snapshot = threat_intel.lock().clone();
                let outcome = process_palo_alto_log_item(
                    worker_id,
                    &raw_log,
                    &elk_tx,
                    &wazuh_enriched_tx,
                    &intel_snapshot,
                    &mut worker_state,
                    geoip
                        .as_deref()
                        .map(|g| g as &dyn crate::domain::ports::GeoIpLookup),
                    should_skip_enrichment,
                );
                if outcome.enriched {
                    enriched_count = enriched_count.saturating_add(1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;
    use serde_json::json;
    use std::collections::HashMap;

    const MALICIOUS_TRAFFIC_LOG: &str = "<14>Jun 02 13:10:07 PA-VM-01 1,2026/06/02 13:10:07,007951000123,TRAFFIC,deny,2561,2026/06/02 13:10:07,10.10.20.44,203.0.113.10,0.0.0.0,0.0.0.0,deny-any,,,telnet,vsys1,trust,untrust,ethernet1/3,ethernet1/1,LFP-SIEM,2026/06/02 13:10:07,4839202,1,51514,23,0,0,0x0,tcp,deny,66,66,0,1";

    fn threat_intel_with_ip(ip: &str) -> ThreatIntel {
        let mut intel = ThreatIntel::new();
        let mut malicious_ips = HashMap::new();
        malicious_ips.insert(ip.to_string(), vec!["unit-test-feed".to_string()]);
        intel.malicious_ips = Arc::new(malicious_ips);
        intel
    }

    #[test]
    fn valid_palo_alto_log_is_enriched_and_routed_to_elk_and_wazuh() {
        let (elk_tx, elk_rx) = bounded(1);
        let (wazuh_tx, wazuh_rx) = bounded(1);
        let intel = threat_intel_with_ip("203.0.113.10");
        let mut worker_state = AlertHistory::default();

        let outcome = process_palo_alto_log_item(
            0,
            MALICIOUS_TRAFFIC_LOG,
            &elk_tx,
            &wazuh_tx,
            &intel,
            &mut worker_state,
            None,
            false,
        );

        assert_eq!(
            outcome,
            PaloAltoProcessOutcome {
                parsed: true,
                enriched: true,
                elk_sent: true,
                wazuh_sent: true,
            }
        );
        let elk_log = elk_rx
            .try_recv()
            .expect("ELK queue should receive enriched log");
        assert_eq!(
            elk_log["forwarder_enrichment"]["ioc_matches"]["malicious_ips"][0],
            json!({
                "ip": "203.0.113.10",
                "status": "blocklisted",
                "sources": ["unit-test-feed"],
                "source_count": 1
            })
        );
        let wazuh_log = wazuh_rx
            .try_recv()
            .expect("Wazuh queue should receive formatted syslog");
        assert!(wazuh_log.contains("dst_ip=203.0.113.10"));
    }

    #[test]
    fn invalid_palo_alto_log_is_dropped_without_output() {
        let (elk_tx, elk_rx) = bounded(1);
        let (wazuh_tx, wazuh_rx) = bounded(1);
        let intel = ThreatIntel::new();
        let mut worker_state = AlertHistory::default();

        let outcome = process_palo_alto_log_item(
            0,
            "not a palo alto log",
            &elk_tx,
            &wazuh_tx,
            &intel,
            &mut worker_state,
            None,
            false,
        );

        assert_eq!(outcome, PaloAltoProcessOutcome::default());
        assert!(elk_rx.try_recv().is_err());
        assert!(wazuh_rx.try_recv().is_err());
    }

    #[test]
    fn syslog_receiver_enqueues_raw_message() {
        let (raw_tx, raw_rx) = bounded(1);

        let outcome = enqueue_palo_alto_syslog_message("raw syslog", &raw_tx, 1);

        assert_eq!(outcome, PaloAltoReceiverOutcome { enqueued: true });
        assert_eq!(
            raw_rx.try_recv().expect("raw log should be queued"),
            "raw syslog"
        );
    }

    #[test]
    fn syslog_receiver_drops_raw_message_when_queue_is_full() {
        let (raw_tx, raw_rx) = bounded(1);
        raw_tx
            .try_send("occupied".to_string())
            .expect("test queue should be filled");

        let outcome = enqueue_palo_alto_syslog_message("dropped", &raw_tx, 1);

        assert_eq!(outcome, PaloAltoReceiverOutcome { enqueued: false });
        assert_eq!(
            raw_rx.try_recv().expect("original queued item remains"),
            "occupied"
        );
        assert!(raw_rx.try_recv().is_err());
    }
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
