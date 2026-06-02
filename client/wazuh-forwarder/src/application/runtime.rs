//! Shared binary runtime setup helpers.

use anyhow::{anyhow, Context, Result};
use log::{info, warn};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

/// Calculates the bounded channel size used for worker state merge updates.
pub fn state_merger_queue_size(enrichment_worker_count: usize) -> Result<usize> {
    enrichment_worker_count
        .checked_mul(2)
        .ok_or_else(|| anyhow!("enrichment worker count is too large"))
}

/// Installs the Palo Alto binary's shutdown signal handler.
pub fn spawn_palo_alto_signal_handler(shutdown: Arc<AtomicBool>) -> Result<thread::JoinHandle<()>> {
    let mut signals =
        Signals::new([SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
    thread::Builder::new()
        .name("signal_handler".to_string())
        .spawn(move || {
            info!("Signal handler thread started. Waiting for SIGINT or SIGTERM.");
            if let Some(sig) = signals.forever().next() {
                warn!(
                    "Received OS signal {:?}. Initiating graceful shutdown sequence...",
                    sig
                );
                shutdown.store(true, Ordering::Release);
            }
            info!("Signal handler thread finished.");
        })
        .context("Failed to spawn signal handler thread")
}

/// Installs the tshark binary's shutdown signal handler.
pub fn spawn_tshark_signal_handler(shutdown: Arc<AtomicBool>) -> Result<thread::JoinHandle<()>> {
    let mut signals =
        Signals::new([SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
    thread::Builder::new()
        .name("signal_handler".to_string())
        .spawn(move || {
            if signals.forever().next().is_some() {
                warn!("Received shutdown signal. Initiating graceful shutdown.");
                shutdown.store(true, Ordering::Release);
            }
        })
        .context("Failed to spawn signal handler thread")
}
