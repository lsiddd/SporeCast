use anyhow::{Context, Result};
use crossbeam_channel::Receiver;
use log::{info, warn};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::UdpSocket, task, time::timeout};

use crate::performance::get_circuit_breaker;

#[allow(dead_code)]
pub async fn wazuh_raw_syslog_sender_thread(
    wazuh_raw_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
    wazuh_host: String,
    wazuh_port: u16,
) -> Result<()> {
    info!("Starting Wazuh raw syslog sender thread with circuit breaker");

    let wazuh_addr = format!("{}:{}", wazuh_host, wazuh_port);
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
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
        let recv_result =
            task::spawn_blocking(move || wazuh_raw_rx_clone.recv_timeout(Duration::from_secs(1)))
                .await?;

        match recv_result {
            Ok(raw_log) => {
                match timeout(
                    Duration::from_secs(5),
                    socket.send_to(raw_log.as_bytes(), &wazuh_addr),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        sent_count = sent_count.saturating_add(1);
                        circuit_breaker.record_success();
                    }
                    Ok(Err(e)) => {
                        failed_count = failed_count.saturating_add(1);
                        circuit_breaker.record_failure();
                        warn!(
                            "Failed to send raw log to Wazuh: {}. Total failed: {}",
                            e, failed_count
                        );
                    }
                    Err(_) => {
                        failed_count = failed_count.saturating_add(1);
                        circuit_breaker.record_failure();
                        warn!(
                            "Failed to send raw log to Wazuh: timeout. Total failed: {}",
                            failed_count
                        );
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

    info!(
        "Wazuh raw syslog sender shutting down. Sent: {}, Failed: {}",
        sent_count, failed_count
    );
    Ok(())
}

pub async fn wazuh_enriched_syslog_sender_thread(
    wazuh_enriched_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
    wazuh_host: String,
    wazuh_port: u16,
) -> Result<()> {
    info!("Starting Wazuh enriched syslog sender thread with circuit breaker");

    let wazuh_addr = format!("{}:{}", wazuh_host, wazuh_port);
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
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
        })
        .await?;

        match recv_result {
            Ok(enriched_log) => {
                match timeout(
                    Duration::from_secs(5),
                    socket.send_to(enriched_log.as_bytes(), &wazuh_addr),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        sent_count = sent_count.saturating_add(1);
                        circuit_breaker.record_success();
                        if sent_count.is_multiple_of(100) {
                            info!("Sent {} enriched logs to Wazuh", sent_count);
                        }
                    }
                    Ok(Err(e)) => {
                        failed_count = failed_count.saturating_add(1);
                        circuit_breaker.record_failure();
                        warn!(
                            "Failed to send enriched log to Wazuh: {}. Total failed: {}",
                            e, failed_count
                        );
                    }
                    Err(_) => {
                        failed_count = failed_count.saturating_add(1);
                        circuit_breaker.record_failure();
                        warn!(
                            "Failed to send enriched log to Wazuh: timeout. Total failed: {}",
                            failed_count
                        );
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

    info!(
        "Wazuh enriched syslog sender shutting down. Sent: {}, Failed: {}",
        sent_count, failed_count
    );
    Ok(())
}
