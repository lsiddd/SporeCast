use anyhow::{anyhow, Context, Result};
use chrono::Local;
use clap::Parser;
use crossbeam_channel::bounded;
use log::{error, info, warn};
use serde_json::Value;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use wazuh_forwarder::{
    application::runtime::{spawn_tshark_signal_handler, state_merger_queue_size},
    application::state::StateManager,
    application::threat_intel::threat_intel_updater_thread,
    application::workers::{
        elk_sender_thread, state_merger_thread, test_initial_connection,
        tshark_enrichment_worker_thread, tshark_stdin_receiver_thread,
    },
    domain::indicators::ThreatIntel,
    infrastructure::config::ForwarderConfig,
    infrastructure::geoip::GeoIpEnricher,
    infrastructure::logging::configure_logging_with_opts,
};

#[derive(Parser)]
#[command(
    name = "tshark_forwarder",
    about = "Forward tshark EK JSON (stdin) to ELK with GeoIP and threat-intel enrichment.\n\
             Production: sudo tshark -i any -n -l -f \"ip or ip6\" -T ek | tshark_forwarder\n\
             Dev/test:   cat capture.json | tshark_forwarder --stdout"
)]
struct Cli {
    #[arg(short, long, default_value = "forwarder-config.toml")]
    config: String,

    /// Print enriched JSON to stdout instead of sending to ELK (dev/test mode).
    /// Disables threat-intel downloads and ELK connection.
    #[arg(long)]
    stdout: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config =
        ForwarderConfig::load_from_file(&cli.config).unwrap_or_else(|_| ForwarderConfig::default());

    let elk_host = config.network.elk_host.clone();
    let elk_port = config.network.elk_port;
    let enrichment_worker_count = config.performance.enrichment_worker_count;
    let batch_size = config.performance.elk_batch_size;
    let flush_interval_secs = config.performance.elk_batch_flush_interval_secs;
    let max_receiver_queue = config.performance.max_receiver_queue_size;
    let max_enrichment_queue = config.performance.max_enrichment_queue_size;

    // Redirect system paths (/var/...) to user-local dir so binary runs without root.
    let data_dir = {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let d = format!("{}/.local/share/sporecast", home);
        std::fs::create_dir_all(&d).ok();
        d
    };
    let state_file = if config.logging.state_file.starts_with("/var/") {
        format!("{}/state.json", data_dir)
    } else {
        config.logging.state_file.clone()
    };

    // In --stdout mode, logs go to stderr so JSON on stdout stays clean.
    configure_logging_with_opts(&config, cli.stdout)?;

    info!("==============================================");
    info!("     Tshark EK Stream Forwarder (Rust)      ");
    info!("==============================================");
    info!(
        "Service starting. {}",
        Local::now().format("%Y-%m-%d %H:%M:%S %Z")
    );

    if cli.stdout {
        info!("Mode: stdout (enriched JSON printed to stdout, no ELK)");
    } else {
        info!("Mode: ELK at {}:{}", elk_host, elk_port);
        if let Err(e) = test_initial_connection(&elk_host, elk_port).await {
            warn!(
                "Initial ELK connection test failed. Will retry as needed: {}",
                e
            );
        }
    }

    // Signal handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let _signal_handler = spawn_tshark_signal_handler(shutdown.clone())?;

    let (parsed_tx, parsed_rx) = bounded(max_receiver_queue);
    let (elk_tx, elk_rx) = bounded::<Value>(max_enrichment_queue);
    let (state_merger_tx, state_merger_rx) =
        bounded(state_merger_queue_size(enrichment_worker_count)?);

    // State Manager
    let mut state_manager_instance = StateManager::new(&state_file);
    if let Err(e) = state_manager_instance.load() {
        info!("No prior state at {}: {}. Starting fresh.", state_file, e);
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance));

    // GeoIP
    let geoip_enricher: Option<Arc<GeoIpEnricher>> = if config.geoip.enabled {
        GeoIpEnricher::open(&config.geoip.database_path).map(Arc::new)
    } else {
        None
    };

    // Threat Intel — skip in stdout mode to avoid downloads during dev
    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    let threat_intel_handle = if config.threat_intelligence.enable_threat_intel_feeds && !cli.stdout
    {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        Some(tokio::spawn(async move {
            threat_intel_updater_thread(intel_clone, shutdown_clone).await;
        }))
    } else {
        None
    };

    // State Merger Thread
    let state_merger_handle = thread::Builder::new()
        .name("state_merger".to_string())
        .spawn({
            let shutdown_clone = shutdown.clone();
            let state_manager_clone = state_manager.clone();
            move || {
                if let Err(e) =
                    state_merger_thread(state_merger_rx, state_manager_clone, shutdown_clone)
                {
                    error!("State merger thread error: {}", e);
                }
            }
        })?;

    // Stdin Receiver Task
    let stdin_receiver_handle = tokio::spawn({
        let shutdown_clone = shutdown.clone();
        let tx = parsed_tx.clone();
        async move {
            if let Err(e) = tshark_stdin_receiver_thread(tx, shutdown_clone).await {
                error!("Tshark stdin receiver error: {}", e);
            }
        }
    });

    // Enrichment Workers
    let mut enrichment_handles = Vec::new();
    for i in 0..enrichment_worker_count {
        let handle = thread::Builder::new()
            .name(format!("tshark_enrich_worker_{}", i))
            .spawn({
                let parsed_rx_clone = parsed_rx.clone();
                let elk_tx_clone = elk_tx.clone();
                let intel_db_clone = threat_intel_db.clone();
                let state_merger_tx_clone = state_merger_tx.clone();
                let shutdown_clone = shutdown.clone();
                let geoip_clone = geoip_enricher.clone();
                move || {
                    if let Err(e) = tshark_enrichment_worker_thread(
                        i,
                        parsed_rx_clone,
                        elk_tx_clone,
                        intel_db_clone,
                        state_merger_tx_clone,
                        shutdown_clone,
                        geoip_clone,
                    ) {
                        error!("[TsharkWorker {}] Critical error: {}", i, e);
                    }
                }
            })?;
        enrichment_handles.push(handle);
    }
    info!(
        "Spawned {} enrichment worker threads.",
        enrichment_worker_count
    );

    // Output: ELK sender or stdout printer
    let elk_sender_handle = if cli.stdout {
        let elk_rx_clone = elk_rx.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            let stdout = io::stdout();
            while !shutdown_clone.load(Ordering::Relaxed) || !elk_rx_clone.is_empty() {
                let elk_rx_c = elk_rx_clone.clone();
                match tokio::task::spawn_blocking(move || {
                    elk_rx_c.recv_timeout(Duration::from_secs(1))
                })
                .await
                {
                    Ok(Ok(value)) => {
                        if let Ok(line) = serde_json::to_string(&value) {
                            let mut out = stdout.lock();
                            let _ = writeln!(out, "{}", line);
                        }
                    }
                    Ok(Err(_)) => {} // timeout or closed
                    Err(_) => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    } else {
        tokio::spawn(elk_sender_thread(
            elk_rx,
            shutdown.clone(),
            elk_host.clone(),
            elk_port,
            batch_size,
            flush_interval_secs,
        ))
    };

    stdin_receiver_handle
        .await
        .context("Tshark stdin receiver task panicked")?;

    info!("Stdin closed. Draining enrichment queue.");
    drop(parsed_tx);
    for handle in enrichment_handles {
        handle
            .join()
            .map_err(|_| anyhow!("Enrichment worker thread panicked"))?;
    }

    drop(elk_tx);
    elk_sender_handle
        .await
        .context("Output sender task panicked")?
        .context("Output sender task failed")?;

    if let Some(handle) = threat_intel_handle {
        handle.await.context("Threat intel updater task panicked")?;
    }

    drop(state_merger_tx);
    state_merger_handle
        .join()
        .map_err(|_| anyhow!("State merger thread panicked"))?;

    info!("All tasks finished.");
    Ok(())
}
