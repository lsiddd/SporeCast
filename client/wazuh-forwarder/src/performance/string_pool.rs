use log::debug;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
};

const STRING_POOL_MAX_SIZE: usize = 10_000;
const INITIAL_STRING_CAPACITY: usize = 2_048;
const MAX_REUSABLE_STRING_CAPACITY: usize = 4_096;

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
            increment_saturating(&self.reused, Ordering::Relaxed);
            debug!(
                "Reused string from pool, reuse count: {}",
                self.reused.load(Ordering::Relaxed)
            );
            s
        } else {
            increment_saturating(&self.allocated, Ordering::Relaxed);
            debug!(
                "Allocated new string, allocation count: {}",
                self.allocated.load(Ordering::Relaxed)
            );
            String::with_capacity(INITIAL_STRING_CAPACITY)
        }
    }

    pub fn return_string(&self, mut s: String) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size && s.capacity() <= MAX_REUSABLE_STRING_CAPACITY {
            s.clear();
            pool.push_back(s);
            debug!("Returned string to pool, pool size: {}", pool.len());
        }
    }

    pub fn stats(&self) -> (usize, usize) {
        (
            self.allocated.load(Ordering::Relaxed),
            self.reused.load(Ordering::Relaxed),
        )
    }
}

pub static STRING_POOL: once_cell::sync::Lazy<StringPool> =
    once_cell::sync::Lazy::new(|| StringPool::new(STRING_POOL_MAX_SIZE));

fn increment_saturating(counter: &AtomicUsize, ordering: Ordering) -> usize {
    match counter.fetch_update(ordering, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    }) {
        Ok(previous) | Err(previous) => previous.saturating_add(1),
    }
}
