use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use dashmap::DashMap;
use log::{debug, info, warn};
use tokio::time::timeout;

use crate::unified_config::*;

// ==============================================================================
// --- Memory Pool for String Reuse ---
// Reduces allocation overhead for high-throughput log processing
// ==============================================================================

pub struct StringPool {
    pool: Mutex<VecDeque<String>>,
    max_size: usize,
    allocated: AtomicUsize,
    reused: AtomicUsize,
}

impl StringPool {
    fn new(max_size: usize) -> Self {
        Self {
            pool: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            allocated: AtomicUsize::new(0),
            reused: AtomicUsize::new(0),
        }
    }

    pub fn get_string(&self) -> String {
        let mut pool = self.pool.lock();
        if let Some(mut s) = pool.pop_front() {
            s.clear();
            self.reused.fetch_add(1, Ordering::Relaxed);
            debug!("Reused string from pool, reuse count: {}", self.reused.load(Ordering::Relaxed));
            s
        } else {
            self.allocated.fetch_add(1, Ordering::Relaxed);
            debug!("Allocated new string, allocation count: {}", self.allocated.load(Ordering::Relaxed));
            String::with_capacity(2048) // Pre-allocate reasonable capacity for log messages
        }
    }

    pub fn return_string(&self, mut s: String) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size && s.capacity() <= 4096 {
            s.clear();
            pool.push_back(s);
            debug!("Returned string to pool, pool size: {}", pool.len());
        }
        // If pool is full or string is too large, just drop it
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.allocated.load(Ordering::Relaxed), self.reused.load(Ordering::Relaxed))
    }
}

// Global string pool instance
pub static STRING_POOL: Lazy<StringPool> = Lazy::new(|| StringPool::new(10000));

// ==============================================================================
// --- Circuit Breaker Pattern ---
// Prevents cascading failures when downstream services are unavailable
// ==============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,    // Normal operation
    Open,      // Failures detected, blocking calls
    HalfOpen,  // Testing if service recovered
}

pub struct CircuitBreaker {
    state: AtomicUsize, // 0=Closed, 1=Open, 2=HalfOpen
    failure_count: AtomicUsize,
    success_count: AtomicUsize,
    last_failure_time: Mutex<Option<Instant>>,
    name: String,
}

impl CircuitBreaker {
    pub fn new(name: String) -> Self {
        Self {
            state: AtomicUsize::new(0), // Start closed
            failure_count: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            last_failure_time: Mutex::new(None),
            name,
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
                        info!("Circuit breaker [{}] transitioning to HALF_OPEN after timeout", self.name);
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
        self.success_count.fetch_add(1, Ordering::Release);
        self.failure_count.store(0, Ordering::Release);

        match current_state {
            CircuitState::HalfOpen => {
                if self.success_count.load(Ordering::Acquire) >= CIRCUIT_BREAKER_SUCCESS_THRESHOLD {
                    self.transition_to_closed();
                    info!("Circuit breaker [{}] closed after {} successes", self.name, CIRCUIT_BREAKER_SUCCESS_THRESHOLD);
                }
            }
            _ => {}
        }
    }

    pub fn record_failure(&self) {
        let failures = self.failure_count.fetch_add(1, Ordering::Release) + 1;
        self.success_count.store(0, Ordering::Release);
        
        {
            let mut last_failure = self.last_failure_time.lock();
            *last_failure = Some(Instant::now());
        }

        if failures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            match self.state() {
                CircuitState::Closed | CircuitState::HalfOpen => {
                    self.transition_to_open();
                    warn!("Circuit breaker [{}] OPENED after {} failures", self.name, failures);
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
        .or_insert_with(|| Arc::new(CircuitBreaker::new(name.to_string())))
        .clone()
}

// ==============================================================================
// --- Queue Monitoring ---
// Tracks queue utilization and triggers degradation modes
// ==============================================================================

pub struct QueueMonitor {
    pub is_high_load: AtomicBool,
    pub last_report: Mutex<Instant>,
}

impl QueueMonitor {
    pub fn new() -> Self {
        Self {
            is_high_load: AtomicBool::new(false),
            last_report: Mutex::new(Instant::now()),
        }
    }

    pub fn check_queue_health(&self, queue_len: usize, queue_capacity: usize, queue_name: &str) -> bool {
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
                    queue_name, queue_len, queue_capacity, utilization * 100.0
                );
            } else {
                info!(
                    "Queue [{}] status: {}/{} ({:.1}% capacity)",
                    queue_name, queue_len, queue_capacity, utilization * 100.0
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

// Global queue monitor
pub static QUEUE_MONITOR: Lazy<QueueMonitor> = Lazy::new(QueueMonitor::new);

// ==============================================================================
// --- Connection Pool ---
// Manages multiple TCP connections for better throughput
// ==============================================================================

use tokio::net::TcpStream;
// VecDeque already imported above

pub struct ConnectionPool {
    connections: Mutex<VecDeque<TcpStream>>,
    host: String,
    port: u16,
    max_size: usize,
    active_count: AtomicUsize,
}

impl ConnectionPool {
    pub fn new(host: String, port: u16, max_size: usize) -> Self {
        Self {
            connections: Mutex::new(VecDeque::with_capacity(max_size)),
            host,
            port,
            max_size,
            active_count: AtomicUsize::new(0),
        }
    }

    pub async fn get_connection(&self) -> Result<TcpStream, std::io::Error> {
        // Try to get existing connection from pool
        {
            let mut pool = self.connections.lock();
            if let Some(stream) = pool.pop_front() {
                debug!("Reused connection from pool, active: {}", self.active_count.load(Ordering::Relaxed));
                return Ok(stream);
            }
        }

        // Create new connection if pool is empty
        let addr = format!("{}:{}", self.host, self.port);
        match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                self.active_count.fetch_add(1, Ordering::Relaxed);
                debug!("Created new connection to {}, active: {}", addr, self.active_count.load(Ordering::Relaxed));
                Ok(stream)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout")),
        }
    }

    pub fn return_connection(&self, stream: TcpStream) {
        let mut pool = self.connections.lock();
        if pool.len() < self.max_size {
            pool.push_back(stream);
            debug!("Returned connection to pool, pool size: {}", pool.len());
        } else {
            // Pool is full, connection will be dropped
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            debug!("Dropped excess connection, active: {}", self.active_count.load(Ordering::Relaxed));
        }
    }

    pub fn stats(&self) -> (usize, usize) {
        let pool = self.connections.lock();
        (pool.len(), self.active_count.load(Ordering::Relaxed))
    }
}