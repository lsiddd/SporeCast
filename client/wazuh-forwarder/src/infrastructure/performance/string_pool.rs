use log::debug;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
};

const STRING_POOL_MAX_SIZE: usize = 10_000;
const INITIAL_STRING_CAPACITY: usize = 2_048;
const MAX_REUSABLE_STRING_CAPACITY: usize = 4_096;

/// Reuses bounded-size `String` allocations in hot parsing paths.
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

    /// Returns a cleared string from the pool or allocates a new one.
    pub fn get_string(&self) -> String {
        let mut pool = self.pool.lock();
        if let Some(mut s) = pool.pop_front() {
            s.clear();
            super::increment_saturating(&self.reused, Ordering::Relaxed);
            debug!(
                "Reused string from pool, reuse count: {}",
                self.reused.load(Ordering::Relaxed)
            );
            s
        } else {
            super::increment_saturating(&self.allocated, Ordering::Relaxed);
            debug!(
                "Allocated new string, allocation count: {}",
                self.allocated.load(Ordering::Relaxed)
            );
            String::with_capacity(INITIAL_STRING_CAPACITY)
        }
    }

    /// Returns a string to the pool if its capacity is within the reusable limit.
    pub fn return_string(&self, mut s: String) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size && s.capacity() <= MAX_REUSABLE_STRING_CAPACITY {
            s.clear();
            pool.push_back(s);
            debug!("Returned string to pool, pool size: {}", pool.len());
        }
    }

    /// Returns `(allocated_count, reused_count)`.
    pub fn stats(&self) -> (usize, usize) {
        (
            self.allocated.load(Ordering::Relaxed),
            self.reused.load(Ordering::Relaxed),
        )
    }
}

pub static STRING_POOL: once_cell::sync::Lazy<StringPool> =
    once_cell::sync::Lazy::new(|| StringPool::new(STRING_POOL_MAX_SIZE));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_small_string_is_cleared_and_reused() {
        let pool = StringPool::new(1);
        let mut reusable = pool.get_string();
        reusable.push_str("payload");

        pool.return_string(reusable);
        let reused = pool.get_string();

        assert_eq!(reused, "");
        assert_eq!(pool.stats(), (1, 1));
    }

    #[test]
    fn oversized_string_is_not_reused() {
        let pool = StringPool::new(1);
        let oversized = String::with_capacity(MAX_REUSABLE_STRING_CAPACITY + 1);

        pool.return_string(oversized);
        let fresh = pool.get_string();

        assert_eq!(fresh.capacity(), INITIAL_STRING_CAPACITY);
        assert_eq!(pool.stats(), (1, 0));
    }

    #[test]
    fn pool_never_stores_more_than_max_size() {
        let pool = StringPool::new(1);
        let first = pool.get_string();
        let second = pool.get_string();

        pool.return_string(first);
        pool.return_string(second);
        let _reused = pool.get_string();
        let _allocated = pool.get_string();

        assert_eq!(pool.stats(), (3, 1));
    }
}
