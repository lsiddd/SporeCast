use anyhow::{anyhow, Context, Result};
use crossbeam_channel::Receiver;
use log::{debug, error, info, warn};
use serde_json::Value;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{io::AsyncWriteExt, task, time::timeout};

use crate::performance::{get_circuit_breaker, ConnectionPool};
use crate::unified_config::CONNECTION_POOL_SIZE;

mod wazuh;
pub use wazuh::{wazuh_enriched_syslog_sender_thread, wazuh_raw_syslog_sender_thread};

const ELK_BATCH_ITEM_CAPACITY_ESTIMATE: usize = 512;

/// Batches enriched logs and sends them to Logstash/ELK over pooled TCP connections.
#[tracing::instrument(skip(elk_rx, shutdown))]
pub async fn elk_sender_thread(
    elk_rx: Receiver<Value>,
    shutdown: Arc<AtomicBool>,
    elk_host: String,
    elk_port: u16,
    batch_size: usize,
    flush_interval_secs: u64,
) -> Result<()> {
    info!("Logstash sender task started with connection pooling and batching.");

    let connection_pool = Arc::new(ConnectionPool::new(
        elk_host,
        elk_port,
        CONNECTION_POOL_SIZE,
    ));
    let circuit_breaker = get_circuit_breaker("elk_sender");

    let mut retry_delay = 5u64;
    let mut batch_buffer: Vec<Value> = Vec::with_capacity(batch_size);
    let mut last_batch_flush = std::time::Instant::now();
    let flush_interval = Duration::from_secs(flush_interval_secs);

    while !shutdown.load(Ordering::Relaxed) || !elk_rx.is_empty() {
        if !circuit_breaker.can_execute() {
            warn!("ELK circuit breaker is OPEN, skipping batch processing");
            tokio::time::sleep(Duration::from_secs(retry_delay)).await;
            continue;
        }

        let elk_rx_clone = elk_rx.clone();
        let recv_result =
            task::spawn_blocking(move || elk_rx_clone.recv_timeout(Duration::from_secs(1))).await?;

        match recv_result {
            Ok(log_json) => {
                batch_buffer.push(log_json);

                if batch_buffer.len() >= batch_size || last_batch_flush.elapsed() >= flush_interval
                {
                    if let Err(e) =
                        flush_batch_to_elk(&batch_buffer, &connection_pool, &circuit_breaker).await
                    {
                        error!("Failed to flush batch to ELK: {}", e);
                        circuit_breaker.record_failure();
                        retry_delay = retry_delay.saturating_mul(2).min(60);
                    } else {
                        circuit_breaker.record_success();
                        retry_delay = 5;
                    }
                    batch_buffer.clear();
                    last_batch_flush = std::time::Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !batch_buffer.is_empty() && last_batch_flush.elapsed() >= flush_interval {
                    if let Err(e) =
                        flush_batch_to_elk(&batch_buffer, &connection_pool, &circuit_breaker).await
                    {
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
        if let Err(e) = flush_batch_to_elk(&batch_buffer, &connection_pool, &circuit_breaker).await
        {
            error!("Failed to flush final batch to ELK: {}", e);
        }
    }

    info!("Logstash sender thread shutting down.");
    Ok(())
}

/// Checks whether the Logstash/ELK TCP endpoint is reachable at startup.
#[tracing::instrument]
pub async fn test_initial_connection(elk_host: &str, elk_port: u16) -> Result<()> {
    info!(
        "Testing initial connection to Logstash TCP input at {}:{}",
        elk_host, elk_port
    );

    let connection_pool = ConnectionPool::new(elk_host, elk_port, 1);

    match connection_pool.get_connection().await {
        Ok(_) => {
            info!("Logstash TCP connection test passed.");
            Ok(())
        }
        Err(e) => Err(anyhow!("Logstash connection test failed: {}", e)),
    }
}

#[tracing::instrument(skip(batch, pool, circuit_breaker), fields(batch_len = batch.len()))]
async fn flush_batch_to_elk(
    batch: &[Value],
    pool: &Arc<ConnectionPool>,
    circuit_breaker: &Arc<crate::performance::CircuitBreaker>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    if !circuit_breaker.can_execute() {
        return Err(anyhow!("Circuit breaker is open"));
    }

    let mut stream = pool
        .get_connection()
        .await
        .context("Failed to get connection from pool")?;

    let mut payload =
        String::with_capacity(batch.len().saturating_mul(ELK_BATCH_ITEM_CAPACITY_ESTIMATE));
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

    match timeout(
        Duration::from_secs(10),
        stream.write_all(payload.as_bytes()),
    )
    .await
    {
        Ok(Ok(_)) => {
            debug!("Successfully sent batch of {} logs to ELK", batch.len());
            pool.return_connection(stream);
            Ok(())
        }
        Ok(Err(e)) => Err(anyhow!("Failed to write to ELK stream: {}", e)),
        Err(_) => Err(anyhow!("ELK write operation timed out")),
    }
}
