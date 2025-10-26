use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    time::timeout,
};

use crate::behavioral::{AlertHistory, StateManager};
use crate::palo_alto_config::*;
use crate::palo_alto_parsing::{enrich_and_analyze_log, format_json_to_palo_alto_syslog, parse_palo_alto_log_to_json};
use crate::telegram::send_telegram_message;
use crate::threat_intel::ThreatIntel;

// ==============================================================================
// --- Palo Alto Syslog Receiver Thread ---
// Receives raw Palo Alto syslog messages via UDP and distributes them to processing queues
// ==============================================================================
pub async fn palo_alto_syslog_receiver_thread(
    raw_log_tx: Sender<String>,
    wazuh_raw_tx: Sender<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", PALO_ALTO_SYSLOG_PORT);
    info!(
        "Starting Palo Alto syslog receiver on UDP port {}",
        PALO_ALTO_SYSLOG_PORT
    );

    let socket = UdpSocket::bind(&bind_addr)
        .await
        .context(format!("Failed to bind UDP socket to {}", bind_addr))?;

    info!("Palo Alto syslog receiver successfully bound to {}", bind_addr);

    // Send startup notification
    tokio::spawn(send_telegram_message(
        format!("🚀 *Palo Alto Log Forwarder Started:* Listening for logs on UDP port {}.", PALO_ALTO_SYSLOG_PORT)
    ));

    let mut buffer = [0; 8192]; // Palo Alto logs can be quite large
    let mut log_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, addr))) => {
                let raw_message = String::from_utf8_lossy(&buffer[..size]);
                debug!("Received Palo Alto log from {}: {}", addr, raw_message);

                log_count += 1;
                if log_count % 1000 == 0 {
                    info!("Processed {} Palo Alto logs so far", log_count);
                }

                // Send to enrichment processing
                if let Err(e) = raw_log_tx.try_send(raw_message.to_string()) {
                    warn!("Failed to send raw log to enrichment queue: {}. Queue may be full.", e);
                }

                // Send copy to Wazuh raw forwarder
                if let Err(e) = wazuh_raw_tx.try_send(raw_message.to_string()) {
                    warn!("Failed to send raw log to Wazuh queue: {}. Queue may be full.", e);
                }
            }
            Ok(Err(e)) => {
                error!("UDP receive error: {}. Will retry.", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) => {
                // Timeout - continue to check shutdown
                debug!("UDP receive timeout, checking for shutdown signal");
            }
        }
    }

    info!("Palo Alto syslog receiver thread shutting down. Total logs processed: {}", log_count);
    Ok(())
}

// ==============================================================================
// --- Palo Alto Enrichment Worker Thread ---
// Processes raw Palo Alto logs: parsing, enrichment, and threat analysis
// ==============================================================================
pub fn palo_alto_enrichment_worker_thread(
    worker_id: usize,
    raw_log_rx: Receiver<String>,
    elk_tx: Sender<Value>, // SENDS A JSON VALUE
    wazuh_enriched_tx: Sender<String>,
    threat_intel: Arc<Mutex<ThreatIntel>>,
    state_merger_tx: Sender<AlertHistory>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("[Worker {}] Starting Palo Alto enrichment worker thread", worker_id);

    let mut worker_state = AlertHistory::default();
    let mut processed_count = 0u64;
    let mut enriched_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match raw_log_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(raw_log) => {
                processed_count += 1;
                debug!("[Worker {}] Processing raw log #{}: {}", worker_id, processed_count, raw_log);

                // Parse Palo Alto log
                match parse_palo_alto_log_to_json(&raw_log) {
                    Ok(mut parsed_log) => {
                        debug!("[Worker {}] Successfully parsed Palo Alto log", worker_id);

                        // Perform enrichment and threat analysis
                        {
                            let intel_guard = threat_intel.lock().unwrap();
                            let intel_arc = Arc::new(intel_guard.clone());
                            drop(intel_guard);
                            parsed_log = enrich_and_analyze_log(parsed_log, &intel_arc, &mut worker_state);

                            if parsed_log.get("forwarder_enrichment").is_some() {
                                enriched_count += 1;
                                info!("[Worker {}] Log enriched with threat intelligence and behavioral analysis", worker_id);
                            }
                        }

                        // Send enriched JSON to the sender thread (which now goes to Logstash)
                        if let Err(e) = elk_tx.try_send(parsed_log.clone()) {
                            warn!("[Worker {}] Failed to send enriched log to sender queue: {}. Queue may be full.", worker_id, e);
                        }

                        // Format back to syslog for Wazuh
                        match format_json_to_palo_alto_syslog(&parsed_log) {
                            Ok(formatted_syslog) => {
                                if let Err(e) = wazuh_enriched_tx.try_send(formatted_syslog) {
                                    warn!("[Worker {}] Failed to send formatted log to Wazuh enriched queue: {}. Queue may be full.", worker_id, e);
                                }
                            }
                            Err(e) => {
                                warn!("[Worker {}] Failed to format JSON back to syslog for Wazuh: {}", worker_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[Worker {}] Failed to parse Palo Alto log: {}. Raw log: {}", worker_id, e, raw_log);
                    }
                }

                if processed_count % 100 == 0 {
                    if let Err(e) = state_merger_tx.try_send(worker_state.clone()) {
                        debug!("[Worker {}] Failed to send state update: {}", worker_id, e);
                    }
                    info!("[Worker {}] Processed {} logs, {} enriched", worker_id, processed_count, enriched_count);
                }
            }
            Err(_) => {
                debug!("[Worker {}] Receive timeout or channel closed, checking shutdown", worker_id);
                if raw_log_rx.is_empty() && shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    if let Err(e) = state_merger_tx.try_send(worker_state) {
        warn!("[Worker {}] Failed to send final state update: {}", worker_id, e);
    }

    info!("[Worker {}] Palo Alto enrichment worker shutting down. Processed: {}, Enriched: {}",
          worker_id, processed_count, enriched_count);
    Ok(())
}

// ==============================================================================
// --- Logstash Sender Thread (REWRITTEN) ---
// Sends enriched JSON logs to the Logstash TCP input.
// This version uses a persistent TCP stream, not HTTP POST.
// ==============================================================================
pub async fn elk_sender_thread(
    elk_rx: Receiver<Value>, // RECEIVES A JSON VALUE
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Logstash sender task started.");
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT)
        .parse()
        .context(format!("Failed to parse Logstash host:port address: {}:{}", ELK_HOST, ELK_PORT))?;

    let mut retry_delay = 5;
    let mut stream: Option<TcpStream> = None;

    while !shutdown.load(Ordering::Relaxed) || !elk_rx.is_empty() {
        if stream.is_none() {
            warn!("Logstash sender: Not connected. Retrying in {}s.", retry_delay);
            tokio::time::sleep(Duration::from_secs(retry_delay)).await;

            match TcpStream::connect(&addr).await {
                Ok(s) => {
                    info!("Logstash sender: Successfully connected to Logstash at {}.", addr);
                    stream = Some(s);
                    retry_delay = 5; // Reset backoff on success
                }
                Err(e) => {
                    error!("Logstash sender: Connection to Logstash failed: {}. Next retry in {}s.", e, retry_delay * 2);
                    retry_delay = std::cmp::min(retry_delay * 2, 60); // Exponential backoff up to 60s
                    continue;
                }
            };
        }

        if let Some(s) = stream.as_mut() {
            match elk_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(log_json) => {
                    // Serialize the JSON Value to a string and add a newline for Logstash's json_lines codec
                    let mut payload = match serde_json::to_string(&log_json) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to serialize log to JSON string: {}", e);
                            continue;
                        }
                    };
                    payload.push('\n');

                    // Attempt to write the payload to the stream
                    if let Err(e) = s.write_all(payload.as_bytes()).await {
                        error!("Failed to write to Logstash TCP stream: {}. Marking connection as broken.", e);
                        stream = None; // Connection is broken, will trigger reconnect
                    } else {
                        debug!("Successfully sent log to Logstash.");
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    debug!("Logstash sender: No data in queue. Awaiting new logs.");
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(_) => {
                    info!("Logstash sender: Channel disconnected. Shutting down.");
                    break;
                }
            }
        }
    }

    info!("Logstash sender thread shutting down.");
    Ok(())
}

// ==============================================================================
// --- Wazuh Syslog Sender Threads ---
// Forward logs to Wazuh via syslog (both raw and enriched)
// ==============================================================================
pub async fn wazuh_raw_syslog_sender_thread(
    wazuh_raw_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Starting Wazuh raw syslog sender thread");

    let wazuh_addr = format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT);
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to create UDP socket for Wazuh raw sender")?;

    let mut sent_count = 0u64;
    let mut failed_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match wazuh_raw_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(raw_log) => {
                match socket.send_to(raw_log.as_bytes(), &wazuh_addr).await {
                    Ok(_) => {
                        sent_count += 1;
                        debug!("Sent raw log to Wazuh. Total: {}", sent_count);
                    }
                    Err(e) => {
                        failed_count += 1;
                        warn!("Failed to send raw log to Wazuh: {}. Total failed: {}", e, failed_count);
                    }
                }
            }
            Err(_) => {
                debug!("Wazuh raw sender timeout, checking shutdown");
                if wazuh_raw_rx.is_empty() && shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    info!("Wazuh raw syslog sender shutting down. Sent: {}, Failed: {}", sent_count, failed_count);
    Ok(())
}

pub async fn wazuh_enriched_syslog_sender_thread(
    wazuh_enriched_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Starting Wazuh enriched syslog sender thread");

    let wazuh_addr = format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT);
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to create UDP socket for Wazuh enriched sender")?;

    let mut sent_count = 0u64;
    let mut failed_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        match wazuh_enriched_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(enriched_log) => {
                match socket.send_to(enriched_log.as_bytes(), &wazuh_addr).await {
                    Ok(_) => {
                        sent_count += 1;
                        debug!("Sent enriched log to Wazuh. Total: {}", sent_count);

                        if sent_count % 100 == 0 {
                            info!("Sent {} enriched logs to Wazuh", sent_count);
                        }
                    }
                    Err(e) => {
                        failed_count += 1;
                        warn!("Failed to send enriched log to Wazuh: {}. Total failed: {}", e, failed_count);
                    }
                }
            }
            Err(_) => {
                debug!("Wazuh enriched sender timeout, checking shutdown");
                if wazuh_enriched_rx.is_empty() && shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    info!("Wazuh enriched syslog sender shutting down. Sent: {}, Failed: {}", sent_count, failed_count);
    Ok(())
}

// ==============================================================================
// --- State Merger Thread ---
// Merges behavioral analysis state from all worker threads
// ==============================================================================
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
                updates_processed += 1;
                debug!("Merging state update #{}", updates_processed);

                let mut manager = state_manager.lock().unwrap();
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
            Err(_) => {
                debug!("State merger timeout, checking shutdown");
                if state_merger_rx.is_empty() && shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    let manager = state_manager.lock().unwrap();
    if let Err(e) = manager.save() {
        error!("Failed to save final state to disk: {}", e);
    } else {
        info!("Saved final behavioral analysis state to disk");
    }

    info!("Palo Alto state merger thread shutting down. Updates processed: {}", updates_processed);
    Ok(())
}


// ==============================================================================
// --- Connection Testing (REWRITTEN) ---
// Test initial connectivity to the Logstash TCP input
// ==============================================================================
pub async fn test_initial_connection() -> Result<()> {
    info!("Testing initial connection to Logstash TCP input at {}:{}", ELK_HOST, ELK_PORT);

    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT).parse()?;

    match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            info!("✅ Logstash TCP connection test passed.");
            Ok(())
        }
        Ok(Err(e)) => Err(anyhow!("Logstash connection test failed: {}", e)),
        Err(_) => Err(anyhow!("Logstash connection test timed out")),
    }
}
