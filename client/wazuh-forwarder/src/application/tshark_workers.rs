use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use parking_lot::Mutex;
use serde_json::Value;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::domain::ports::GeoIpLookup;
use crate::domain::{behavioral::AlertHistory, indicators::ThreatIntel};
use crate::domain::{enrichment::enrich_and_analyze_log, tshark::normalize_packet};
use crate::infrastructure::defaults::{
    DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD, MAX_RECEIVER_QUEUE_SIZE,
};
use crate::infrastructure::geoip::GeoIpEnricher;
use crate::infrastructure::performance::QUEUE_MONITOR;

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct TsharkProcessOutcome {
    pub enriched: bool,
    pub elk_sent: bool,
}

pub(crate) fn process_tshark_packet_item(
    worker_id: usize,
    packet: Value,
    elk_tx: &Sender<Value>,
    threat_intel: &ThreatIntel,
    worker_state: &mut AlertHistory,
    geoip: Option<&dyn GeoIpLookup>,
    skip_enrichment: bool,
) -> TsharkProcessOutcome {
    let mut outcome = TsharkProcessOutcome::default();

    let enriched = if !skip_enrichment {
        let intel_arc = Arc::new(threat_intel.clone());
        let enriched = enrich_and_analyze_log(packet, &intel_arc, worker_state, geoip);
        outcome.enriched = enriched.get("forwarder_enrichment").is_some();
        enriched
    } else {
        packet
    };

    match elk_tx.try_send(enriched) {
        Ok(()) => outcome.elk_sent = true,
        Err(e) => warn!(
            "[TsharkWorker {}] Failed to send to ELK queue: {}",
            worker_id, e
        ),
    }

    outcome
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct TsharkReceiverOutcome {
    pub parsed_packet: bool,
    pub normalized_packet: bool,
    pub enqueued: bool,
}

pub(crate) fn process_tshark_ek_line(
    line: &str,
    parsed_tx: &Sender<Value>,
    queue_capacity: usize,
) -> TsharkReceiverOutcome {
    let line = line.trim();
    if line.is_empty() || line.starts_with(r#"{"index""#) {
        return TsharkReceiverOutcome::default();
    }

    let packet_json = match serde_json::from_str::<Value>(line) {
        Ok(packet_json) => packet_json,
        Err(e) => {
            warn!(
                "Failed to parse tshark JSON line: {}. Line: {}",
                e,
                &line[..line.len().min(120)]
            );
            return TsharkReceiverOutcome::default();
        }
    };

    let Some(normalized) = normalize_packet(&packet_json) else {
        debug!("Skipped non-IP packet (no IP layer found)");
        return TsharkReceiverOutcome {
            parsed_packet: true,
            normalized_packet: false,
            enqueued: false,
        };
    };

    QUEUE_MONITOR.check_queue_health(parsed_tx.len(), queue_capacity, "tshark_parsed_queue");

    match parsed_tx.try_send(normalized) {
        Ok(()) => TsharkReceiverOutcome {
            parsed_packet: true,
            normalized_packet: true,
            enqueued: true,
        },
        Err(e) => {
            warn!("Failed to enqueue tshark packet: {}. Queue may be full.", e);
            TsharkReceiverOutcome {
                parsed_packet: true,
                normalized_packet: true,
                enqueued: false,
            }
        }
    }
}

// ==============================================================================
// --- Tshark Stdin Receiver Task ---
// ==============================================================================
/// Reads tshark EK JSON from stdin line by line (real-time with `-l`).
///
/// tshark EK emits pairs: index line then data line.
/// We skip index lines and parse data lines.
#[tracing::instrument(skip(parsed_tx, shutdown))]
pub async fn tshark_stdin_receiver_thread(
    parsed_tx: Sender<Value>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Starting tshark stdin receiver (expecting EK JSON from stdin)");

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut packet_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match tokio::time::timeout(Duration::from_secs(1), reader.next_line()).await {
            Ok(Ok(Some(line))) => {
                let outcome = process_tshark_ek_line(&line, &parsed_tx, MAX_RECEIVER_QUEUE_SIZE);
                if outcome.normalized_packet {
                    packet_count = packet_count.saturating_add(1);
                    if packet_count.is_multiple_of(1000) {
                        info!("Processed {} tshark packets", packet_count);
                    }
                }
            }
            Ok(Ok(None)) => {
                info!("Stdin closed (tshark exited). Shutting down receiver.");
                break;
            }
            Ok(Err(e)) => {
                error!("Stdin read error: {}. Shutting down receiver.", e);
                break;
            }
            Err(_) => {
                // Timeout — check shutdown and loop
            }
        }
    }

    info!(
        "Tshark stdin receiver shutting down. Total packets processed: {}",
        packet_count
    );
    Ok(())
}

// ==============================================================================
// --- Tshark Enrichment Worker Thread ---
// ==============================================================================
/// Enriches pre-parsed tshark packet Values with GeoIP, threat intel, and behavioral analysis.
#[tracing::instrument(skip(parsed_rx, elk_tx, threat_intel, state_merger_tx, shutdown, geoip))]
pub fn tshark_enrichment_worker_thread(
    worker_id: usize,
    parsed_rx: Receiver<Value>,
    elk_tx: Sender<Value>,
    threat_intel: Arc<Mutex<ThreatIntel>>,
    state_merger_tx: Sender<AlertHistory>,
    shutdown: Arc<AtomicBool>,
    geoip: Option<Arc<GeoIpEnricher>>,
) -> Result<()> {
    info!(
        "[TsharkWorker {}] Starting tshark enrichment worker thread",
        worker_id
    );

    let mut worker_state = AlertHistory::default();
    let mut processed_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match parsed_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(packet) => {
                processed_count = processed_count.saturating_add(1);

                let should_skip_behavioral =
                    DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD && QUEUE_MONITOR.is_high_load();

                let intel_snapshot = threat_intel.lock().clone();
                process_tshark_packet_item(
                    worker_id,
                    packet,
                    &elk_tx,
                    &intel_snapshot,
                    &mut worker_state,
                    geoip
                        .as_deref()
                        .map(|g| g as &dyn crate::domain::ports::GeoIpLookup),
                    should_skip_behavioral,
                );

                if processed_count.is_multiple_of(100) {
                    if let Err(e) = state_merger_tx.try_send(worker_state.clone()) {
                        debug!(
                            "[TsharkWorker {}] Failed to send state update: {}",
                            worker_id, e
                        );
                    }
                    info!(
                        "[TsharkWorker {}] Processed {} packets",
                        worker_id, processed_count
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
            "[TsharkWorker {}] Failed to send final state update: {}",
            worker_id, e
        );
    }

    info!(
        "[TsharkWorker {}] Shutting down. Processed: {}",
        worker_id, processed_count
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;
    use serde_json::json;
    use std::collections::HashMap;

    fn threat_intel_with_ip(ip: &str) -> ThreatIntel {
        let mut intel = ThreatIntel::new();
        let mut malicious_ips = HashMap::new();
        malicious_ips.insert(ip.to_string(), vec!["unit-test-feed".to_string()]);
        intel.malicious_ips = Arc::new(malicious_ips);
        intel
    }

    fn normalized_packet() -> Value {
        json!({
            "source_address": "198.51.100.99",
            "destination_address": "10.0.0.1",
            "log_type": "tshark"
        })
    }

    #[test]
    fn normalized_tshark_packet_is_enriched_and_routed_to_elk() {
        let (elk_tx, elk_rx) = bounded(1);
        let intel = threat_intel_with_ip("198.51.100.99");
        let mut worker_state = AlertHistory::default();

        let outcome = process_tshark_packet_item(
            0,
            normalized_packet(),
            &elk_tx,
            &intel,
            &mut worker_state,
            None,
            false,
        );

        assert_eq!(
            outcome,
            TsharkProcessOutcome {
                enriched: true,
                elk_sent: true
            }
        );
        let elk_log = elk_rx.try_recv().expect("ELK queue should receive packet");
        assert_eq!(
            elk_log["forwarder_enrichment"]["ioc_matches"]["malicious_ips"][0],
            json!({
                "ip": "198.51.100.99",
                "status": "blocklisted",
                "sources": ["unit-test-feed"],
                "source_count": 1
            })
        );
    }

    #[test]
    fn full_output_queue_drops_tshark_item_without_panicking() {
        let (elk_tx, elk_rx) = bounded(1);
        elk_tx
            .try_send(json!({ "occupied": true }))
            .expect("test queue should be filled");
        let intel = threat_intel_with_ip("198.51.100.99");
        let mut worker_state = AlertHistory::default();

        let outcome = process_tshark_packet_item(
            0,
            normalized_packet(),
            &elk_tx,
            &intel,
            &mut worker_state,
            None,
            false,
        );

        assert_eq!(
            outcome,
            TsharkProcessOutcome {
                enriched: true,
                elk_sent: false
            }
        );
        assert_eq!(
            elk_rx.try_recv().expect("original queued item remains"),
            json!({ "occupied": true })
        );
        assert!(elk_rx.try_recv().is_err());
    }

    #[test]
    fn stdin_receiver_skips_index_and_invalid_lines_without_output() {
        let (parsed_tx, parsed_rx) = bounded(1);

        assert_eq!(
            process_tshark_ek_line(r#"{"index":{"_index":"packets"}}"#, &parsed_tx, 1),
            TsharkReceiverOutcome::default()
        );
        assert_eq!(
            process_tshark_ek_line("not-json", &parsed_tx, 1),
            TsharkReceiverOutcome::default()
        );
        assert!(parsed_rx.try_recv().is_err());
    }

    #[test]
    fn stdin_receiver_enqueues_normalized_ip_packet() {
        let (parsed_tx, parsed_rx) = bounded(1);
        let line = json!({
            "timestamp": "1780410712000",
            "layers": {
                "ip": {
                    "ip_ip_src": "192.0.2.10",
                    "ip_ip_dst": "8.8.8.8"
                }
            }
        })
        .to_string();

        let outcome = process_tshark_ek_line(&line, &parsed_tx, 1);

        assert_eq!(
            outcome,
            TsharkReceiverOutcome {
                parsed_packet: true,
                normalized_packet: true,
                enqueued: true
            }
        );
        let packet = parsed_rx
            .try_recv()
            .expect("normalized packet should be queued");
        assert_eq!(packet["source_address"], "192.0.2.10");
        assert_eq!(packet["destination_address"], "8.8.8.8");
    }

    #[test]
    fn stdin_receiver_reports_normalized_packet_dropped_when_queue_is_full() {
        let (parsed_tx, parsed_rx) = bounded(1);
        parsed_tx
            .try_send(json!({ "occupied": true }))
            .expect("test queue should be filled");
        let line = json!({
            "timestamp": "1780410712000",
            "layers": {
                "ip": {
                    "ip_ip_src": "192.0.2.10",
                    "ip_ip_dst": "8.8.8.8"
                }
            }
        })
        .to_string();

        let outcome = process_tshark_ek_line(&line, &parsed_tx, 1);

        assert_eq!(
            outcome,
            TsharkReceiverOutcome {
                parsed_packet: true,
                normalized_packet: true,
                enqueued: false
            }
        );
        assert_eq!(
            parsed_rx.try_recv().expect("original queued item remains"),
            json!({ "occupied": true })
        );
        assert!(parsed_rx.try_recv().is_err());
    }
}
