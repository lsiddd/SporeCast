use anyhow::{anyhow, Context, Result};
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

use crate::infrastructure::performance::get_circuit_breaker;
use crate::infrastructure::performance::CircuitBreaker;

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct WazuhSendOutcome {
    pub sent: bool,
}

pub(crate) async fn send_wazuh_enriched_log(
    socket: &UdpSocket,
    wazuh_addr: &str,
    enriched_log: &str,
    circuit_breaker: &CircuitBreaker,
) -> Result<WazuhSendOutcome> {
    match timeout(
        Duration::from_secs(5),
        socket.send_to(enriched_log.as_bytes(), wazuh_addr),
    )
    .await
    {
        Ok(Ok(_)) => {
            circuit_breaker.record_success();
            Ok(WazuhSendOutcome { sent: true })
        }
        Ok(Err(e)) => {
            circuit_breaker.record_failure();
            Err(anyhow!("Failed to send enriched log to Wazuh: {}", e))
        }
        Err(_) => {
            circuit_breaker.record_failure();
            Err(anyhow!("Failed to send enriched log to Wazuh: timeout"))
        }
    }
}

/// Sends enriched syslog lines to the local Wazuh syslog endpoint over UDP.
#[tracing::instrument(skip(wazuh_enriched_rx, shutdown))]
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
                match send_wazuh_enriched_log(&socket, &wazuh_addr, &enriched_log, &circuit_breaker)
                    .await
                {
                    Ok(WazuhSendOutcome { sent: true }) => {
                        sent_count = sent_count.saturating_add(1);
                        if sent_count.is_multiple_of(100) {
                            info!("Sent {} enriched logs to Wazuh", sent_count);
                        }
                    }
                    Ok(WazuhSendOutcome { sent: false }) => {}
                    Err(e) => {
                        failed_count = failed_count.saturating_add(1);
                        warn!("{}. Total failed: {}", e, failed_count);
                    }
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

    info!(
        "Wazuh enriched syslog sender shutting down. Sent: {}, Failed: {}",
        sent_count, failed_count
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::bounded;

    #[tokio::test]
    async fn send_wazuh_enriched_log_sends_udp_payload_to_local_socket() {
        let receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("local UDP receiver should bind");
        let addr = receiver
            .local_addr()
            .expect("local UDP receiver address should be available");
        let sender = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("local UDP sender should bind");
        let breaker = CircuitBreaker::new("wazuh_unit_send");

        let outcome =
            send_wazuh_enriched_log(&sender, &addr.to_string(), "enriched syslog", &breaker)
                .await
                .expect("UDP send should succeed");

        assert_eq!(outcome, WazuhSendOutcome { sent: true });
        let mut buf = [0_u8; 128];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get UDP payload");
        assert_eq!(&buf[..len], b"enriched syslog");
    }

    #[tokio::test]
    async fn wazuh_sender_loop_drains_queued_message_until_channel_disconnects() {
        let receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("local UDP receiver should bind");
        let addr = receiver
            .local_addr()
            .expect("local UDP receiver address should be available");
        let (tx, rx) = bounded(1);
        tx.try_send("loop syslog".to_string())
            .expect("sender queue should accept fixture");
        drop(tx);
        let shutdown = Arc::new(AtomicBool::new(false));

        wazuh_enriched_syslog_sender_thread(rx, shutdown, addr.ip().to_string(), addr.port())
            .await
            .expect("sender loop should drain and exit on disconnect");

        let mut buf = [0_u8; 128];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get UDP payload");
        assert_eq!(&buf[..len], b"loop syslog");
    }
}
