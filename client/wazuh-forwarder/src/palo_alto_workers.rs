use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use serde_json::Value;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    task,
    time::timeout,
};

use crate::behavioral::{AlertHistory, StateManager};
use crate::palo_alto_config::{ELK_HOST, ELK_PORT, PALO_ALTO_SYSLOG_PORT};
use crate::unified_config::*;
use crate::palo_alto_parsing::{enrich_and_analyze_log, format_json_to_palo_alto_syslog, parse_palo_alto_log_to_json};
use crate::threat_intel::ThreatIntel;
use crate::performance::{STRING_POOL, QUEUE_MONITOR, get_circuit_breaker, ConnectionPool};

// ==============================================================================
// --- Palo Alto Syslog Receiver Thread ---
// ==============================================================================
pub async fn palo_alto_syslog_receiver_thread(
    raw_log_tx: Sender<String>,
    _wazuh_raw_tx: Sender<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", PALO_ALTO_SYSLOG_PORT);
    info!("Starting Palo Alto syslog receiver on UDP port {}", PALO_ALTO_SYSLOG_PORT);

    let socket = UdpSocket::bind(&bind_addr)
        .await
        .context(format!("Failed to bind UDP socket to {}", bind_addr))?;
    info!("Palo Alto syslog receiver successfully bound to {}", bind_addr);

    let mut buffer = [0; 8192];
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

                QUEUE_MONITOR.check_queue_health(
                    raw_log_tx.len(), 
                    MAX_RECEIVER_QUEUE_SIZE, 
                    "raw_log_queue"
                );
                
                let mut log_string = STRING_POOL.get_string();
                log_string.push_str(&raw_message);
                
                if let Err(e) = raw_log_tx.try_send(log_string.clone()) {
                    warn!("Failed to send raw log to enrichment queue: {}. Queue may be full.", e);
                }
                
                STRING_POOL.return_string(log_string);
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

    info!("Palo Alto syslog receiver thread shutting down. Total logs processed: {}", log_count);
    Ok(())
}

// ==============================================================================
// --- Palo Alto Enrichment Worker Thread ---
// ==============================================================================
pub fn palo_alto_enrichment_worker_thread(
    worker_id: usize,
    raw_log_rx: Receiver<String>,
    elk_tx: Sender<Value>,
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

                match parse_palo_alto_log_to_json(&raw_log) {
                    Ok(mut parsed_log) => {
                        debug!("[Worker {}] Successfully parsed Palo Alto log", worker_id);

                        let should_skip_behavioral = DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD && QUEUE_MONITOR.is_high_load();
                        
                        if !should_skip_behavioral {
                            let intel_guard = threat_intel.lock().unwrap();
                            let intel_arc = Arc::new(intel_guard.clone());
                            drop(intel_guard);
                            parsed_log = enrich_and_analyze_log(parsed_log, &intel_arc, &mut worker_state);

                            if parsed_log.get("forwarder_enrichment").is_some() {
                                enriched_count += 1;
                                debug!("[Worker {}] Log enriched with threat intelligence and behavioral analysis", worker_id);

                                // Only forward to Wazuh if threat intel indicators were found
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
                            } else {
                                debug!("[Worker {}] Skipping Wazuh forwarding - no threat intel indicators found", worker_id);
                            }
                        } else {
                            debug!("[Worker {}] Skipping behavioral analysis due to high load", worker_id);
                        }

                        // 2. Send the original `parsed_log` to ELK, consuming it (no clone).
                        if let Err(e) = elk_tx.try_send(parsed_log) {
                            warn!("[Worker {}] Failed to send enriched log to sender queue: {}. Queue may be full.", worker_id, e);
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
// --- Logstash Sender Thread (REWRITTEN WITH CONNECTION POOLING AND BATCHING) ---
// ==============================================================================
pub async fn elk_sender_thread(
    elk_rx: Receiver<Value>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Logstash sender task started with connection pooling and batching.");
    
    let connection_pool = Arc::new(ConnectionPool::new(
        ELK_HOST.to_string(), 
        ELK_PORT, 
        CONNECTION_POOL_SIZE
    ));
    let circuit_breaker = get_circuit_breaker("elk_sender");
    
    let mut retry_delay = 5;
    let mut batch_buffer: Vec<Value> = Vec::with_capacity(ELK_BATCH_SIZE);
    let mut last_batch_flush = std::time::Instant::now();

    while !shutdown.load(Ordering::Relaxed) || !elk_rx.is_empty() {
        if !circuit_breaker.can_execute() {
            warn!("ELK circuit breaker is OPEN, skipping batch processing");
            tokio::time::sleep(Duration::from_secs(retry_delay)).await;
            continue;
        }

        let elk_rx_clone = elk_rx.clone();
        let recv_result = task::spawn_blocking(move || {
            elk_rx_clone.recv_timeout(Duration::from_secs(1))
        }).await?;
        
        match recv_result {
            Ok(log_json) => {
                batch_buffer.push(log_json);
                
                if batch_buffer.len() >= ELK_BATCH_SIZE || 
                   last_batch_flush.elapsed() >= Duration::from_secs(ELK_BATCH_FLUSH_INTERVAL_SECS) {
                    
                    if let Err(e) = flush_batch_to_elk(&batch_buffer, &connection_pool, &circuit_breaker).await {
                        error!("Failed to flush batch to ELK: {}", e);
                        circuit_breaker.record_failure();
                        retry_delay = std::cmp::min(retry_delay * 2, 60);
                    } else {
                        circuit_breaker.record_success();
                        retry_delay = 5;
                    }
                    
                    batch_buffer.clear();
                    last_batch_flush = std::time::Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !batch_buffer.is_empty() && 
                   last_batch_flush.elapsed() >= Duration::from_secs(ELK_BATCH_FLUSH_INTERVAL_SECS) {
                    
                    if let Err(e) = flush_batch_to_elk(&batch_buffer, &connection_pool, &circuit_breaker).await {
                        error!("Failed to flush partial batch to ELK: {}", e);
                        circuit_breaker.record_failure();
                    } else {
                        circuit_breaker.record_success();
                    }
                    
                    batch_buffer.clear();
                    last_batch_flush = std::time::Instant::now();
                }
                
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

    if !batch_buffer.is_empty() {
        if let Err(e) = flush_batch_to_elk(&batch_buffer, &connection_pool, &circuit_breaker).await {
            error!("Failed to flush final batch to ELK: {}", e);
        }
    }
    
    info!("Logstash sender thread shutting down.");
    Ok(())
}

// ==============================================================================
// --- Wazuh Syslog Sender Threads ---
// ==============================================================================
pub async fn wazuh_raw_syslog_sender_thread(
    wazuh_raw_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("Starting Wazuh raw syslog sender thread with circuit breaker");

    let wazuh_addr = format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT);
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to create UDP socket for Wazuh raw sender")?;

    let circuit_breaker = get_circuit_breaker("wazuh_raw_sender");
    let mut sent_count = 0u64;
    let mut failed_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        if !circuit_breaker.can_execute() {
            warn!("Wazuh raw sender circuit breaker is OPEN, skipping sends");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        
        let wazuh_raw_rx_clone = wazuh_raw_rx.clone();
        let recv_result = task::spawn_blocking(move || {
            wazuh_raw_rx_clone.recv_timeout(Duration::from_secs(1))
        }).await?;

        match recv_result {
            Ok(raw_log) => {
                match timeout(Duration::from_secs(5), socket.send_to(raw_log.as_bytes(), &wazuh_addr)).await {
                    Ok(Ok(_)) => {
                        sent_count += 1;
                        circuit_breaker.record_success();
                    }
                    Ok(Err(e)) => {
                        failed_count += 1;
                        circuit_breaker.record_failure();
                        warn!("Failed to send raw log to Wazuh: {}. Total failed: {}", e, failed_count);
                    }
                    Err(_) => {
                        failed_count += 1;
                        circuit_breaker.record_failure();
                        warn!("Failed to send raw log to Wazuh: timeout. Total failed: {}", failed_count);
                    }
                }
            }
            Err(_) => {
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
    info!("Starting Wazuh enriched syslog sender thread with circuit breaker");

    let wazuh_addr = format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT);
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to create UDP socket for Wazuh enriched sender")?;

    let circuit_breaker = get_circuit_breaker("wazuh_enriched_sender");
    let mut sent_count = 0u64;
    let mut failed_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        if !circuit_breaker.can_execute() {
            warn!("Wazuh enriched sender circuit breaker is OPEN, skipping sends");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        
        let wazuh_enriched_rx_clone = wazuh_enriched_rx.clone();
        let recv_result = task::spawn_blocking(move || {
            wazuh_enriched_rx_clone.recv_timeout(Duration::from_secs(1))
        }).await?;
        
        match recv_result {
            Ok(enriched_log) => {
                match timeout(Duration::from_secs(5), socket.send_to(enriched_log.as_bytes(), &wazuh_addr)).await {
                    Ok(Ok(_)) => {
                        sent_count += 1;
                        circuit_breaker.record_success();
                        if sent_count % 100 == 0 {
                            info!("Sent {} enriched logs to Wazuh", sent_count);
                        }
                    }
                    Ok(Err(e)) => {
                        failed_count += 1;
                        circuit_breaker.record_failure();
                        warn!("Failed to send enriched log to Wazuh: {}. Total failed: {}", e, failed_count);
                    }
                    Err(_) => {
                        failed_count += 1;
                        circuit_breaker.record_failure();
                        warn!("Failed to send enriched log to Wazuh: timeout. Total failed: {}", failed_count);
                    }
                }
            }
            Err(_) => {
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
                manager._merge_worker_state(&worker_state);

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
// ==============================================================================
pub async fn test_initial_connection() -> Result<()> {
    info!("Testing initial connection to Logstash TCP input at {}:{}", ELK_HOST, ELK_PORT);

    let connection_pool = ConnectionPool::new(
        ELK_HOST.to_string(), 
        ELK_PORT, 
        1
    );

    match connection_pool.get_connection().await {
        Ok(_) => {
            info!("✅ Logstash TCP connection test passed.");
            Ok(())
        }
        Err(e) => Err(anyhow!("Logstash connection test failed: {}", e)),
    }
}

// Helper function to flush batch to ELK with connection pooling
async fn flush_batch_to_elk(
    batch: &[Value], 
    pool: &Arc<ConnectionPool>, 
    circuit_breaker: &Arc<crate::performance::CircuitBreaker>
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    
    if !circuit_breaker.can_execute() {
        return Err(anyhow!("Circuit breaker is open"));
    }
    
    let mut stream = pool.get_connection().await
        .context("Failed to get connection from pool")?;
    
    let mut payload = String::with_capacity(batch.len() * 512);
    for log_json in batch {
        match serde_json::to_string(log_json) {
            Ok(json_str) => {
                payload.push_str(&json_str);
                payload.push('\n');
            }
            Err(e) => {
                warn!("Failed to serialize log to JSON: {}", e);
                continue;
            }
        }
    }
    
    match timeout(Duration::from_secs(10), stream.write_all(payload.as_bytes())).await {
        Ok(Ok(_)) => {
            debug!("Successfully sent batch of {} logs to ELK", batch.len());
            pool.return_connection(stream);
            Ok(())
        }
        Ok(Err(e)) => {
            Err(anyhow!("Failed to write to ELK stream: {}", e))
        }
        Err(_) => {
            Err(anyhow!("ELK write operation timed out"))
        }
    }
}