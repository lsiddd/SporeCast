//! Shared binary runtime setup helpers.

use anyhow::{anyhow, Context, Result};
use log::warn;
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

/// Installs a graceful shutdown signal handler for SIGINT/SIGTERM.
pub fn spawn_signal_handler(shutdown: Arc<AtomicBool>) -> Result<thread::JoinHandle<()>> {
    let mut signals =
        Signals::new([SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
    thread::Builder::new()
        .name("signal_handler".to_string())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                warn!(
                    "Received OS signal {:?}. Initiating graceful shutdown.",
                    sig
                );
                shutdown.store(true, Ordering::Release);
            }
        })
        .context("Failed to spawn signal handler thread")
}
