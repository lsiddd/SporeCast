use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use serde_json::Value;
use parking_lot::Mutex;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::domain::{behavioral::AlertHistory, indicators::ThreatIntel};
use crate::domain::{enrichment::enrich_and_analyze_log, tshark::normalize_packet};
use crate::infrastructure::defaults::{
    DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD, MAX_RECEIVER_QUEUE_SIZE,
};
use crate::infrastructure::geoip::GeoIpEnricher;
use crate::infrastructure::performance::QUEUE_MONITOR;

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
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Skip EK bulk index lines
                if line.starts_with(r#"{"index""#) {
                    continue;
                }

                match serde_json::from_str::<Value>(line) {
                    Ok(packet_json) => {
                        if let Some(normalized) = normalize_packet(&packet_json) {
                            packet_count = packet_count.saturating_add(1);

                            QUEUE_MONITOR.check_queue_health(
                                parsed_tx.len(),
                                MAX_RECEIVER_QUEUE_SIZE,
                                "tshark_parsed_queue",
                            );

                            if let Err(e) = parsed_tx.try_send(normalized) {
                                warn!("Failed to enqueue tshark packet: {}. Queue may be full.", e);
                            }

                            if packet_count.is_multiple_of(1000) {
                                info!("Processed {} tshark packets", packet_count);
                            }
                        } else {
                            debug!("Skipped non-IP packet (no IP layer found)");
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse tshark JSON line: {}. Line: {}",
                            e,
                            &line[..line.len().min(120)]
                        );
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

                let enriched = if !should_skip_behavioral {
                    let intel_arc = Arc::new(threat_intel.lock().clone());
                    enrich_and_analyze_log(packet, &intel_arc, &mut worker_state, geoip.as_deref().map(|g| g as &dyn crate::domain::ports::GeoIpLookup))
                } else {
                    packet
                };

                if let Err(e) = elk_tx.try_send(enriched) {
                    warn!(
                        "[TsharkWorker {}] Failed to send to ELK queue: {}",
                        worker_id, e
                    );
                }

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
