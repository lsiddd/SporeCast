use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{Receiver, Sender};
use log::{debug, error, info, warn};
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
};

use crate::behavioral::{AlertHistory, StateManager};
use crate::config::*;
use crate::parsing::{enrich_and_analyze_log, format_json_to_fortigate_syslog, parse_fortigate_log_to_json};
use crate::telegram::send_telegram_message;
use crate::threat_intel::ThreatIntel;

// ==============================================================================
// --- Syslog Receiver Thread (Async) ---
// This thread binds to a UDP port and listens for incoming Fortigate Syslog messages.
// It then forwards a raw copy to Wazuh and sends a raw copy to the enrichment worker pool.
// ==============================================================================
pub async fn syslog_receiver_thread(
    enrichment_tx: Sender<String>, // Channel to send raw logs to enrichment threads.
    wazuh_raw_tx: Sender<String>,  // Channel to send raw logs to Wazuh.
    shutdown: Arc<AtomicBool>,     // Atomic flag for graceful shutdown.
) -> Result<()> {
    info!(
        "Syslog receiver task starting. Will bind to UDP port {}.",
        FORTIGATE_SYSLOG_PORT
    );
    let bind_addr = format!("0.0.0.0:{}", FORTIGATE_SYSLOG_PORT);
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind UDP socket to {}. This likely means another process (like Wazuh) is already listening on this port. Please reconfigure Wazuh to listen on a different port (e.g., 1514) and ensure this application is the only one on {}.", bind_addr, FORTIGATE_SYSLOG_PORT))?;

    info!("Successfully bound UDP socket to {}.", bind_addr);

    let mut buf = [0; 2048]; // Buffer for incoming UDP packets.

    loop {
        let shutdown_clone_for_select = shutdown.clone(); // Clone for each select iteration
        tokio::select! {
            // Prioritize shutdown over receiving data
            _ = tokio::time::sleep(Duration::from_millis(100)), if shutdown_clone_for_select.load(Ordering::Relaxed) => {
                info!("Syslog receiver: Shutdown signal received.");
                break;
            }
            // Attempt to receive a UDP packet
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src_addr)) => {
                        let raw_log_bytes = &buf[..len];
                        let raw_log = String::from_utf8_lossy(raw_log_bytes).trim().to_string();
                        if raw_log.is_empty() {
                            debug!("Received empty UDP packet from {}. Skipping.", src_addr);
                            continue;
                        }
                        info!(
                            "Received raw Fortigate log ({} bytes) from {}.",
                            len, src_addr
                        );
                        debug!("Raw log content: '{}'", raw_log);

                        // --- Send RAW LOG to ENRICHMENT WORKERS ---
                        debug!(
                            "Sending raw log to enrichment channel. Queue size: {}",
                            enrichment_tx.len()
                        );
                        if enrichment_tx.send(raw_log.clone()).is_err() { // Clone for enrichment
                            warn!("Channel to enrichment workers disconnected. Initiating shutdown of syslog receiver task.");
                            break; // Exit loop if sender channel is closed.
                        }

                        // --- FORWARD RAW LOG TO WAZUH (as is) ---
                        // This sends the original, non-enriched log to Wazuh.
                        // The enriched log will be sent via another path later.
                        debug!(
                            "Sending raw log to Wazuh raw log channel. Queue size: {}",
                            wazuh_raw_tx.len()
                        );
                        if wazuh_raw_tx.send(raw_log).is_err() {
                            warn!("Channel to Wazuh raw log sender disconnected. Initiating shutdown of syslog receiver task.");
                            break;
                        }

                    }
                    Err(e) => {
                        error!(
                            "Critical error receiving UDP packet: {}. Waiting 1 second before retrying.",
                            e
                        );
                        // On error, wait briefly before retrying to prevent busy-looping
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }

    info!("Syslog receiver task received shutdown signal. Exiting loop.");
    Ok(())
}

// ==============================================================================
// --- Enrichment Worker Thread ---
// This thread parses raw logs, enriches them with threat intelligence,
// performs behavioral analysis, and then sends them to the ELK sender thread
// AND to the Wazuh enriched log sender thread.
// Each worker maintains its own AlertHistory that is periodically merged.
// ==============================================================================
pub fn enrichment_worker_thread(
    worker_id: usize,
    raw_log_rx: Receiver<String>, // Channel to receive raw logs from syslog receiver.
    elk_tx: Sender<String>,        // Channel to send processed JSON logs to ELK sender.
    wazuh_enriched_tx: Sender<String>, // New channel to send enriched logs to Wazuh sender.
    threat_intel_db: Arc<Mutex<ThreatIntel>>, // Shared Threat Intelligence database (read-only access).
    state_merger_tx: Sender<AlertHistory>,     // Channel to send worker's AlertHistory for merging.
    shutdown: Arc<AtomicBool>,                 // Atomic flag for graceful shutdown.
) -> Result<()> {
    info!("[Worker {}] Enrichment worker thread started.", worker_id);
    let mut worker_alert_history = AlertHistory::default();
    let mut last_merge_time = Instant::now();
    const MERGE_INTERVAL_SECS: u64 = 5; // How often to send worker's history for merging.

    while !shutdown.load(Ordering::Relaxed) || !raw_log_rx.is_empty() {
        // Acquire lock once per iteration, then clone the Arc for processing
        // This is still a mutex, but the clone on ThreatIntel is now cheap (Arc clone)
        let intel_guard = threat_intel_db.lock().unwrap();
        let intel = Arc::new(ThreatIntel {
            malicious_ips: intel_guard.malicious_ips.clone(),
            malicious_domains: intel_guard.malicious_domains.clone(),
            malicious_hashes: intel_guard.malicious_hashes.clone(),
            malicious_urls: intel_guard.malicious_urls.clone(),
            last_updated: intel_guard.last_updated,
        });
        drop(intel_guard); // Release the mutex lock early

        match raw_log_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(raw_log) => {
                debug!(
                    "[Worker {}] Received raw log for processing. Raw log channel size: {}",
                    worker_id,
                    raw_log_rx.len()
                );
                match parse_fortigate_log_to_json(&raw_log) {
                    Ok(log_json) => {
                        let enriched_log_json =
                            enrich_and_analyze_log(log_json, &intel, &mut worker_alert_history);

                        // Send to ELK
                        let enriched_json_string = serde_json::to_string(&enriched_log_json)
                            .context("Failed to serialize enriched log to JSON string for ELK")?;
                        debug!("[Worker {}] Sending enriched log to ELK sender channel. ELK queue size: {}", worker_id, elk_tx.len());
                        if elk_tx.send(enriched_json_string).is_err() {
                            warn!("[Worker {}] Channel to ELK sender disconnected. Initiating shutdown.", worker_id);
                            break;
                        }

                        // Send enriched log to Wazuh in Fortigate syslog format
                        match format_json_to_fortigate_syslog(&enriched_log_json) {
                            Ok(formatted_syslog) => {
                                debug!("[Worker {}] Sending formatted enriched log to Wazuh channel. Wazuh queue size: {}", worker_id, wazuh_enriched_tx.len());
                                if wazuh_enriched_tx.send(formatted_syslog).is_err() {
                                    warn!("[Worker {}] Channel to Wazuh enriched log sender disconnected. Initiating shutdown.", worker_id);
                                    break;
                                }
                            },
                            Err(e) => {
                                error!("[Worker {}] Failed to format enriched log for Wazuh: {}. Log: {:?}", worker_id, e, enriched_log_json);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "[Worker {}] Failed to parse Fortigate log: '{}'. Error: {}",
                            worker_id, raw_log, e
                        );
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                debug!(
                    "[Worker {}] No raw logs in queue, checking shutdown flag.",
                    worker_id
                );
            }
            Err(e) => {
                info!(
                    "[Worker {}] Raw log channel disconnected: {}. Exiting thread loop.",
                    worker_id, e
                );
                break;
            }
        }

        // Periodically send worker's history to the merger thread
        if last_merge_time.elapsed().as_secs() >= MERGE_INTERVAL_SECS && ENABLE_BEHAVIORAL_ANALYSIS
        {
            debug!(
                "[Worker {}] Sending behavioral history for merging.",
                worker_id
            );
            if let Err(e) = state_merger_tx.send(worker_alert_history.clone()) {
                error!(
                    "[Worker {}] Failed to send alert history for merging: {}",
                    worker_id, e
                );
            }
            worker_alert_history = AlertHistory::default(); // Reset worker's history after sending
            last_merge_time = Instant::now();
        }
    }

    // Send final history before shutting down
    if ENABLE_BEHAVIORAL_ANALYSIS && !worker_alert_history.src_ips.is_empty() {
        info!(
            "[Worker {}] Sending final behavioral history before shutting down.",
            worker_id
        );
        if let Err(e) = state_merger_tx.send(worker_alert_history) {
            error!(
                "[Worker {}] Failed to send final alert history for merging: {}",
                worker_id, e
            );
        }
    }

    info!(
        "[Worker {}] Enrichment worker thread shutting down gracefully.",
        worker_id
    );
    Ok(())
}

// ==============================================================================
// --- State Merger Thread ---
// This thread receives AlertHistory updates from enrichment workers and
// merges them into the main StateManager's AlertHistory. It also handles
// periodically saving the consolidated state to disk.
// ==============================================================================
pub fn state_merger_thread(
    state_rx: Receiver<AlertHistory>,
    state_manager: Arc<Mutex<StateManager>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("State merger thread started.");
    let mut last_save_time = Instant::now();
    const SAVE_INTERVAL_SECS: u64 = 10; // How often to save the consolidated state to disk.

    while !shutdown.load(Ordering::Relaxed) || !state_rx.is_empty() {
        match state_rx.recv_timeout(Duration::from_millis(500)) {
            // Poll for history updates
            Ok(history_update) => {
                debug!("Received history update from worker. Merging.");
                let mut sm = state_manager.lock().unwrap();
                sm.state.alert_history.merge(history_update);
                // No need to save immediately, wait for interval
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                debug!("State merger: No new history updates in queue.");
            }
            Err(e) => {
                info!(
                    "State merger: History channel disconnected: {}. Exiting thread loop.",
                    e
                );
                break;
            }
        }

        // Periodically save the consolidated state to disk
        if last_save_time.elapsed().as_secs() >= SAVE_INTERVAL_SECS {
            debug!("Attempting to save consolidated state due to interval.");
            let sm = state_manager.lock().unwrap();
            if let Err(e) = sm.save() {
                error!(
                    "Failed to save consolidated behavioral analysis state: {}",
                    e
                );
            }
            drop(sm); // Release lock immediately after saving
            last_save_time = Instant::now();
        }
    }

    // Final save before shutting down
    info!("State merger: Channel closed or shutdown signal received. Performing final state save.");
    let sm = state_manager.lock().unwrap();
    if let Err(e) = sm.save() {
        error!(
            "Failed to perform final save of behavioral analysis state: {}",
            e
        );
    }
    drop(sm);
    info!("State merger thread shut down gracefully.");
    Ok(())
}

// ==============================================================================
// --- ELK Sender Thread (Async) ---
// This thread connects to the ELK (Logstash) server and sends processed JSON logs.
// It handles reconnection logic and sends periodic heartbeats.
// ==============================================================================
pub async fn elk_sender_thread(receiver: Receiver<String>, shutdown: Arc<AtomicBool>) -> Result<()> {
    info!("ELK sender task started.");
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT)
        .parse()
        .with_context(|| {
            format!(
                "Failed to parse ELK host:port address: {}:{}",
                ELK_HOST, ELK_PORT
            )
        })?;

    let mut retry_delay = 5; // Initial reconnection delay in seconds.
    let mut last_heartbeat = Instant::now(); // Tracks time for sending heartbeats.
    let mut logs_processed_since_heartbeat = 0; // Counts logs for heartbeat message.
    let mut stream: Option<TcpStream> = None; // The TCP stream to Logstash.
    let mut batch_buffer: Vec<String> = Vec::with_capacity(ELK_BATCH_SIZE); // Buffer for batching logs
    let mut last_batch_flush = Instant::now();

    // Attempt initial connection to ELK.
    debug!("ELK sender: Attempting initial connection to {}.", addr);
    match tokio::time::timeout(
        Duration::from_secs(SOCKET_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => {
            // tokio::net::TcpStream does not have set_write_timeout/set_read_timeout
            // relying on tokio::time::timeout for overall operation timeouts.
            info!("ELK sender: Successfully connected to ELK at {}.", addr);
            tokio::spawn(send_telegram_message(format!(
                // Cloned String here
                "✅ *Connection Established:* Successfully connected to ELK server at {}:{}.",
                ELK_HOST, ELK_PORT
            )));
            stream = Some(s);
        }
        Ok(Err(e)) => {
            error!(
                "ELK sender: Initial connection to ELK failed: {}. Will retry as logs arrive.",
                e
            );
            tokio::spawn(send_telegram_message(format!(
                // Cloned String here
                "🚨 *Initial ELK Connection Failed:* {}. Check firewall/connectivity.",
                e
            )));
        }
        Err(_) => {
            error!("ELK sender: Initial connection to ELK timed out.");
            tokio::spawn(send_telegram_message(format!(
                // Cloned String here
                "🚨 *Initial ELK Connection Timed Out:* Check firewall/connectivity to {}:{}.",
                ELK_HOST, ELK_PORT
            )));
        }
    };

    // Helper function to send the current batch
    // Define this as a nested async function, not a closure, for easier mutable reference handling.
    async fn send_batch(
        stream: &mut TcpStream,
        buffer: &mut Vec<String>,
        logs_processed_count: &mut u64,
    ) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let payload = buffer.join("\n") + "\n"; // Join with newline and add final newline
        debug!(
            "ELK sender: Sending batch of {} logs ({} bytes) to ELK.",
            buffer.len(),
            payload.len()
        );
        stream.write_all(payload.as_bytes()).await.context("Failed to write to ELK TCP stream")?;
        *logs_processed_count += buffer.len() as u64;
        buffer.clear();
        Ok(())
    }

    loop {
        // Clone receiver for this loop iteration's spawn_blocking
        let receiver_clone_for_blocking = receiver.clone();

        // Check shutdown flag
        if shutdown.load(Ordering::Relaxed) && receiver.is_empty() && batch_buffer.is_empty() {
            info!("ELK sender: Shutdown signal received and queues are empty.");
            break;
        }

        // Send a heartbeat message periodically.
        if last_heartbeat.elapsed().as_secs() >= HEARTBEAT_INTERVAL_SECS {
            let message = format!("❤️ *Heartbeat:* Service is alive. {} logs forwarded since last heartbeat. ELK Queue size: {}. Batch buffer: {}.",
                                 logs_processed_since_heartbeat, receiver.len(), batch_buffer.len());
            tokio::spawn(send_telegram_message(message.clone())); // Cloned String here for info!
            info!("{}", message); // `message` is still available here
            logs_processed_since_heartbeat = 0; // Reset counter.
            last_heartbeat = Instant::now(); // Reset timer.
        }

        // Try to receive a log from the channel or flush batch if timeout reached
        let recv_timeout = if batch_buffer.is_empty() {
            Duration::from_secs(1) // Wait longer if no logs in buffer
        } else {
            // Wait up to ELK_BATCH_FLUSH_INTERVAL_SECS, but no longer than needed to fill batch
            let remaining_time = Duration::from_secs(ELK_BATCH_FLUSH_INTERVAL_SECS)
                .checked_sub(last_batch_flush.elapsed())
                .unwrap_or(Duration::ZERO);
            remaining_time.min(Duration::from_millis(100)) // Poll more frequently for batching
        };

        tokio::select! {
            // Prioritize receiving messages from the channel
            result = tokio::task::spawn_blocking(move || receiver_clone_for_blocking.recv_timeout(recv_timeout)) => {
                match result {
                    Ok(Ok(message)) => {
                        debug!(
                            "ELK sender: Received log from channel. ELK Queue size remaining: {}",
                            receiver.len()
                        );
                        batch_buffer.push(message);

                        if batch_buffer.len() >= ELK_BATCH_SIZE {
                            debug!(
                                "Batch buffer full ({} logs). Flushing to ELK.",
                                batch_buffer.len()
                            );
                            if let Some(s) = stream.as_mut() {
                                if let Err(e) =
                                    send_batch(s, &mut batch_buffer, &mut logs_processed_since_heartbeat).await
                                {
                                    warn!("ELK sender: Failed to send batch to TCP stream: {}. Connection might be broken. Attempting to reconnect.", e);
                                    stream = None; // Mark stream as broken.
                                }
                            } else {
                                debug!("ELK sender: No active connection, holding batch in buffer.");
                            }
                            last_batch_flush = Instant::now();
                        }
                    }
                    Ok(Err(crossbeam_channel::RecvTimeoutError::Timeout)) => {
                        // No messages in the queue for the timeout duration.
                        // Check if it's time to flush partial batch.
                        if !batch_buffer.is_empty()
                            && last_batch_flush.elapsed().as_secs() >= ELK_BATCH_FLUSH_INTERVAL_SECS
                        {
                            debug!(
                                "ELK sender: Flushing partial batch ({} logs) due to timeout.",
                                batch_buffer.len()
                            );
                            if let Some(s) = stream.as_mut() {
                                if let Err(e) =
                                    send_batch(s, &mut batch_buffer, &mut logs_processed_since_heartbeat).await
                                {
                                    warn!("ELK sender: Failed to send partial batch to TCP stream: {}. Connection might be broken. Attempting to reconnect.", e);
                                    stream = None; // Mark stream as broken.
                                }
                            } else {
                                debug!(
                                    "ELK sender: No active connection, holding partial batch in buffer."
                                );
                            }
                            last_batch_flush = Instant::now();
                        }
                        debug!("ELK sender: No data in queue for timeout. Checking shutdown status.");
                    }
                    Ok(Err(e)) => {
                        // The channel has disconnected (e.g., sender thread terminated).
                        info!(
                            "ELK sender: Channel to receiver disconnected: {}. Exiting thread loop.",
                            e
                        );
                        break;
                    }
                    Err(e) => {
                        // This is a tokio::task::JoinError if spawn_blocking panicked.
                        error!("ELK sender: Error from blocking task: {}. Exiting thread loop.", e);
                        break;
                    }
                }
            }
            // Allow polling for the shutdown signal and checking the buffer even when `recv_timeout` doesn't yield.
            _ = tokio::time::sleep(Duration::from_millis(100)), if !shutdown.load(Ordering::Relaxed) => {
                // This branch helps ensure the loop doesn't get stuck if `recv_timeout` is very long
                // and no messages arrive, but a shutdown signal is sent.
                continue;
            }
        }

        // Reconnection logic if stream.is_none()
        if stream.is_none() {
            warn!(
                "ELK sender: Not connected. Waiting {}s before next reconnection attempt.",
                retry_delay
            );
            tokio::spawn(send_telegram_message(format!(
                // Cloned String here
                "⚠️ *ELK Connection Lost:* Retrying in {}s. ELK Queue size: {}. Batch buffer: {}.",
                retry_delay,
                receiver.len(),
                batch_buffer.len()
            )));
            tokio::time::sleep(Duration::from_secs(retry_delay)).await; // Wait before retrying.

            debug!("ELK sender: Attempting to reconnect to ELK at {}.", addr);
            match tokio::time::timeout(
                Duration::from_secs(SOCKET_TIMEOUT_SECS),
                TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(s)) => {
                    // tokio::net::TcpStream does not have set_write_timeout/set_read_timeout
                    // relying on tokio::time::timeout for overall operation timeouts.
                    info!("ELK sender: Successfully reconnected to ELK.");
                    tokio::spawn(send_telegram_message(format!(
                        // Cloned String here
                        "✅ *Reconnected:* Successfully reconnected to ELK."
                    )));
                    stream = Some(s); // Set new stream.
                    retry_delay = 5; // Reset delay.
                }
                Ok(Err(e)) => {
                    error!(
                        "ELK sender: Reconnection to ELK failed: {}. Next retry in {}s.",
                        e,
                        std::cmp::min(retry_delay * 2, 60)
                    );
                    retry_delay = std::cmp::min(retry_delay * 2, 60); // Exponential backoff, max 60s.
                }
                Err(_) => {
                    error!(
                        "ELK sender: Reconnection to ELK timed out. Next retry in {}s.",
                        std::cmp::min(retry_delay * 2, 60)
                    );
                    retry_delay = std::cmp::min(retry_delay * 2, 60);
                }
            }
        }
    }

    // Attempt to flush any remaining logs in the buffer before shutting down
    if !batch_buffer.is_empty() {
        info!(
            "ELK sender: Flushing remaining {} logs in buffer before shutting down.",
            batch_buffer.len()
        );
        if let Some(s) = stream.as_mut() {
            if let Err(e) = send_batch(s, &mut batch_buffer, &mut logs_processed_since_heartbeat).await {
                error!("ELK sender: Failed to flush final batch: {}", e);
            }
        } else {
            warn!("ELK sender: No active ELK connection to flush remaining logs.");
        }
    }

    info!("ELK sender task received shutdown signal or queue is empty. Flushing remaining logs and shutting down.");
    // Small final delay to ensure any last-moment writes complete.
    tokio::time::sleep(Duration::from_millis(100)).await;
    info!("ELK sender task shut down gracefully.");
    Ok(())
}

// ==============================================================================
// --- Wazuh Enhanced Syslog Sender Thread (Async) ---
// This thread sends the enriched, formatted Fortigate logs to Wazuh.
// ==============================================================================
pub async fn wazuh_enhanced_syslog_sender_thread(
    receiver: Receiver<String>, // Channel to receive formatted enriched logs.
    shutdown: Arc<AtomicBool>,  // Atomic flag for graceful shutdown.
) -> Result<()> {
    info!("Wazuh enhanced syslog sender task started.");
    let wazuh_syslog_addr: SocketAddr =
        format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT)
            .parse()
            .with_context(|| {
                format!(
                    "Failed to parse Wazuh local syslog address: {}:{}",
                    WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT
                )
            })?;
    let wazuh_socket = UdpSocket::bind("0.0.0.0:0") // Bind to any available local port
        .await
        .context("Failed to bind UDP socket for Wazuh forwarding")?;

    info!(
        "Wazuh enhanced log forwarding configured to {}.",
        wazuh_syslog_addr
    );

    loop {
        let receiver_clone_for_blocking = receiver.clone();
        if shutdown.load(Ordering::Relaxed) && receiver.is_empty() {
            info!("Wazuh enhanced syslog sender: Shutdown signal received and queue is empty.");
            break;
        }

        match tokio::task::spawn_blocking(move || receiver_clone_for_blocking.recv_timeout(Duration::from_millis(100))).await {
            Ok(Ok(log_message)) => {
                debug!(
                    "Wazuh enhanced syslog sender: Sending enhanced log to Wazuh ({} bytes). Queue size: {}",
                    log_message.len(),
                    receiver.len()
                );
                if let Err(e) = wazuh_socket.send_to(log_message.as_bytes(), wazuh_syslog_addr).await {
                    error!(
                        "Failed to forward enhanced log to Wazuh at {}: {}. Log: '{}'",
                        wazuh_syslog_addr, e, log_message
                    );
                } else {
                    debug!("Successfully forwarded enhanced log to Wazuh.");
                }
            },
            Ok(Err(crossbeam_channel::RecvTimeoutError::Timeout)) => {
                debug!("Wazuh enhanced syslog sender: No new logs in queue.");
            },
            Ok(Err(e)) => {
                info!(
                    "Wazuh enhanced syslog sender: Channel disconnected: {}. Exiting thread loop.",
                    e
                );
                break;
            },
            Err(e) => { // This is a tokio::task::JoinError if spawn_blocking panicked.
                error!("Wazuh enhanced syslog sender: Error from blocking task: {}. Exiting thread loop.", e);
                break;
            }
        }
    }
    info!("Wazuh enhanced syslog sender task shut down gracefully.");
    Ok(())
}

// ==============================================================================
// --- Wazuh Raw Syslog Sender Thread (Async) ---
// This thread sends the raw, non-enriched Fortigate logs to Wazuh.
// ==============================================================================
pub async fn wazuh_raw_syslog_sender_thread(
    wazuh_raw_rx: Receiver<String>, // Channel to receive raw logs.
    shutdown: Arc<AtomicBool>,      // Atomic flag for graceful shutdown.
) -> Result<()> {
    let wazuh_syslog_addr: SocketAddr =
        format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT)
            .parse()
            .with_context(|| {
                format!(
                    "Failed to parse Wazuh local syslog address: {}:{}",
                    WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT
                )
            })?;
    let wazuh_socket = UdpSocket::bind("0.0.0.0:0") // Bind to any available local port
        .await
        .context("Failed to bind UDP socket for Wazuh raw forwarding")?;

    info!("Wazuh raw log forwarding configured to {}.", wazuh_syslog_addr);

    loop {
        let receiver_clone_for_blocking = wazuh_raw_rx.clone();
        if shutdown.load(Ordering::Relaxed) && wazuh_raw_rx.is_empty() {
            info!("Wazuh raw syslog sender: Shutdown signal received and queue is empty.");
            break;
        }

        match tokio::task::spawn_blocking(move || receiver_clone_for_blocking.recv_timeout(Duration::from_millis(100))).await {
            Ok(Ok(log_message)) => {
                debug!(
                    "Wazuh raw syslog sender: Sending raw log to Wazuh ({} bytes). Queue size: {}",
                    log_message.len(),
                    wazuh_raw_rx.len()
                );
                if let Err(e) = wazuh_socket.send_to(log_message.as_bytes(), wazuh_syslog_addr).await {
                    error!(
                        "Failed to forward raw log to Wazuh at {}: {}. Log: '{}'",
                        wazuh_syslog_addr, e, log_message
                    );
                } else {
                    debug!("Successfully forwarded raw log to Wazuh.");
                }
            },
            Ok(Err(crossbeam_channel::RecvTimeoutError::Timeout)) => {
                debug!("Wazuh raw syslog sender: No new logs in queue.");
            },
            Ok(Err(e)) => {
                info!(
                    "Wazuh raw syslog sender: Channel disconnected: {}. Exiting thread loop.",
                    e
                );
                break;
            },
            Err(e) => { // This is a tokio::task::JoinError if spawn_blocking panicked.
                error!("Wazuh raw syslog sender: Error from blocking task: {}. Exiting thread loop.", e);
                break;
            }
        }
    }
    info!("Wazuh raw syslog sender task shut down gracefully.");
    Ok(())
}

// ==============================================================================
// --- Initial Connection Test (Async) ---
// Performs a quick test to ensure the ELK server is reachable at startup.
// ==============================================================================
pub async fn test_initial_connection() -> Result<()> {
    info!(
        "Performing initial connection test to ELK at {}:{}...",
        ELK_HOST, ELK_PORT
    );
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT)
        .parse()
        .with_context(|| {
            format!(
                "Failed to parse ELK address for initial connection test: {}:{}",
                ELK_HOST, ELK_PORT
            )
        })?;

    match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            info!("✅ Initial ELK connection test successful. ELK is reachable.");
            Ok(())
        }
        Ok(Err(e)) => {
            let msg = format!("🚨 Initial ELK connection test FAILED: {}\nCheck firewall rules, ELK server status, and connectivity to {}:{}", e, ELK_HOST, ELK_PORT);
            error!("{}", msg);
            tokio::spawn(send_telegram_message(msg.clone())); // Pass owned String
            Err(anyhow!(msg)) // Pass owned String
        }
        Err(_) => {
            let msg = format!("🚨 Initial ELK connection test TIMED OUT.\nCheck firewall rules, ELK server status, and connectivity to {}:{}.", ELK_HOST, ELK_PORT);
            error!("{}", msg);
            tokio::spawn(send_telegram_message(msg.clone())); // Pass owned String
            Err(anyhow!(msg)) // Pass owned String
        }
    }
}