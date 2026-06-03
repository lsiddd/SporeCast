use dashmap::DashMap;
use log::{info, warn};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::infrastructure::defaults::{
    CIRCUIT_BREAKER_FAILURE_THRESHOLD, CIRCUIT_BREAKER_SUCCESS_THRESHOLD,
    CIRCUIT_BREAKER_TIMEOUT_SECS, HIGH_WORKLOAD_THRESHOLD, QUEUE_MONITORING_INTERVAL_SECS,
};

mod connection_pool;
mod string_pool;
pub use connection_pool::ConnectionPool;
pub use string_pool::{StringPool, STRING_POOL};

// ==============================================================================
// --- Circuit Breaker Pattern ---
// Prevents cascading failures when downstream services are unavailable
// ==============================================================================

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Current state of a downstream circuit breaker.
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failures detected, blocking calls
    HalfOpen, // Testing if service recovered
}

/// Circuit breaker for downstream services that may fail or become unavailable.
pub struct CircuitBreaker {
    state: AtomicUsize, // 0=Closed, 1=Open, 2=HalfOpen
    failure_count: AtomicUsize,
    success_count: AtomicUsize,
    last_failure_time: Mutex<Option<Instant>>,
    name: String,
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            state: AtomicUsize::new(0), // Start closed
            failure_count: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            last_failure_time: Mutex::new(None),
            name: name.into(),
        }
    }

    pub fn state(&self) -> CircuitState {
        match self.state.load(Ordering::Acquire) {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    pub fn can_execute(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check if timeout period has passed
                let last_failure = self.last_failure_time.lock();
                if let Some(last_time) = *last_failure {
                    if last_time.elapsed() > Duration::from_secs(CIRCUIT_BREAKER_TIMEOUT_SECS) {
                        drop(last_failure);
                        self.transition_to_half_open();
                        info!(
                            "Circuit breaker [{}] transitioning to HALF_OPEN after timeout",
                            self.name
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    pub fn record_success(&self) {
        let current_state = self.state();
        increment_saturating(&self.success_count, Ordering::AcqRel);
        self.failure_count.store(0, Ordering::Release);

        if current_state == CircuitState::HalfOpen
            && self.success_count.load(Ordering::Acquire) >= CIRCUIT_BREAKER_SUCCESS_THRESHOLD
        {
            self.transition_to_closed();
            info!(
                "Circuit breaker [{}] closed after {} successes",
                self.name, CIRCUIT_BREAKER_SUCCESS_THRESHOLD
            );
        }
    }

    pub fn record_failure(&self) {
        let failures = increment_saturating(&self.failure_count, Ordering::AcqRel);
        self.success_count.store(0, Ordering::Release);

        {
            let mut last_failure = self.last_failure_time.lock();
            *last_failure = Some(Instant::now());
        }

        if failures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            match self.state() {
                CircuitState::Closed | CircuitState::HalfOpen => {
                    self.transition_to_open();
                    warn!(
                        "Circuit breaker [{}] OPENED after {} failures",
                        self.name, failures
                    );
                }
                _ => {}
            }
        }
    }

    fn transition_to_closed(&self) {
        self.state.store(0, Ordering::Release);
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
    }

    fn transition_to_open(&self) {
        self.state.store(1, Ordering::Release);
    }

    fn transition_to_half_open(&self) {
        self.state.store(2, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
    }
}

// Global circuit breaker registry
pub static CIRCUIT_BREAKERS: Lazy<DashMap<String, Arc<CircuitBreaker>>> = Lazy::new(DashMap::new);

pub fn get_circuit_breaker(name: &str) -> Arc<CircuitBreaker> {
    CIRCUIT_BREAKERS
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(CircuitBreaker::new(name)))
        .clone()
}

// ==============================================================================
// --- Queue Monitoring ---
// Tracks queue utilization and triggers degradation modes
// ==============================================================================

/// Tracks queue utilization and exposes a global high-load signal.
pub struct QueueMonitor {
    is_high_load: AtomicBool,
    last_report: Mutex<Instant>,
}

impl QueueMonitor {
    pub fn new() -> Self {
        Self {
            is_high_load: AtomicBool::new(false),
            last_report: Mutex::new(Instant::now()),
        }
    }

    pub fn check_queue_health(
        &self,
        queue_len: usize,
        queue_capacity: usize,
        queue_name: &str,
    ) -> bool {
        if queue_capacity == 0 {
            warn!(
                "Queue [{}] has zero capacity configured; treating as high load",
                queue_name
            );
            self.is_high_load.store(true, Ordering::Relaxed);
            return true;
        }

        let utilization = queue_len as f64 / queue_capacity as f64;
        let is_high = utilization >= HIGH_WORKLOAD_THRESHOLD;

        // Update global high load state
        self.is_high_load.store(is_high, Ordering::Relaxed);

        // Periodic reporting
        let mut last_report = self.last_report.lock();
        if last_report.elapsed() >= Duration::from_secs(QUEUE_MONITORING_INTERVAL_SECS) {
            if is_high {
                warn!(
                    "Queue [{}] HIGH LOAD: {}/{} ({:.1}% capacity) - degradation mode active",
                    queue_name,
                    queue_len,
                    queue_capacity,
                    utilization * 100.0
                );
            } else {
                info!(
                    "Queue [{}] status: {}/{} ({:.1}% capacity)",
                    queue_name,
                    queue_len,
                    queue_capacity,
                    utilization * 100.0
                );
            }
            *last_report = Instant::now();
        }

        is_high
    }

    pub fn is_high_load(&self) -> bool {
        self.is_high_load.load(Ordering::Relaxed)
    }
}

impl Default for QueueMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// Global queue monitor
pub static QUEUE_MONITOR: Lazy<QueueMonitor> = Lazy::new(QueueMonitor::new);

pub(super) fn increment_saturating(counter: &AtomicUsize, ordering: Ordering) -> usize {
    match counter.fetch_update(ordering, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    }) {
        Ok(previous) | Err(previous) => previous.saturating_add(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_breaker_opens_after_failure_threshold_and_blocks_execution() {
        let breaker = CircuitBreaker::new("test_downstream");

        for _ in 0..CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            breaker.record_failure();
        }

        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.can_execute());
    }

    #[test]
    fn queue_monitor_treats_zero_capacity_as_high_load() {
        let monitor = QueueMonitor::new();

        let is_high = monitor.check_queue_health(1, 0, "test_queue");

        assert_eq!(is_high, true);
        assert_eq!(monitor.is_high_load(), true);
    }

    #[test]
    fn queue_monitor_marks_threshold_utilization_as_high_load() {
        let monitor = QueueMonitor::new();

        let below_threshold = monitor.check_queue_health(79, 100, "test_queue");
        let at_threshold = monitor.check_queue_health(80, 100, "test_queue");

        assert_eq!(below_threshold, false);
        assert_eq!(at_threshold, true);
        assert_eq!(monitor.is_high_load(), true);
    }
}
