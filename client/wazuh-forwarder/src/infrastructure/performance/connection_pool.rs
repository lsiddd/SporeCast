use log::debug;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};

/// Small async TCP connection pool used by ELK senders.
pub struct ConnectionPool {
    connections: Mutex<VecDeque<TcpStream>>,
    host: String,
    port: u16,
    max_size: usize,
    active_count: AtomicUsize,
}

impl ConnectionPool {
    /// Creates a pool for `host:port` with at most `max_size` idle connections.
    pub fn new(host: impl Into<String>, port: u16, max_size: usize) -> Self {
        Self {
            connections: Mutex::new(VecDeque::with_capacity(max_size)),
            host: host.into(),
            port,
            max_size,
            active_count: AtomicUsize::new(0),
        }
    }

    /// Returns an idle connection or opens a new TCP connection.
    pub async fn get_connection(&self) -> Result<TcpStream, std::io::Error> {
        {
            let mut pool = self.connections.lock();
            if let Some(stream) = pool.pop_front() {
                super::increment_saturating(&self.active_count, Ordering::Relaxed);
                debug!(
                    "Reused connection from pool, active: {}",
                    self.active_count.load(Ordering::Relaxed)
                );
                return Ok(stream);
            }
        }

        let addr = format!("{}:{}", self.host, self.port);
        match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                super::increment_saturating(&self.active_count, Ordering::Relaxed);
                debug!(
                    "Created new connection to {}, active: {}",
                    addr,
                    self.active_count.load(Ordering::Relaxed)
                );
                Ok(stream)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Connection timeout",
            )),
        }
    }

    /// Returns a usable connection to the idle pool.
    pub fn return_connection(&self, stream: TcpStream) {
        let mut pool = self.connections.lock();
        if pool.len() < self.max_size {
            pool.push_back(stream);
            decrement_saturating(&self.active_count, Ordering::Relaxed);
            debug!("Returned connection to pool, pool size: {}", pool.len());
        } else {
            decrement_saturating(&self.active_count, Ordering::Relaxed);
            debug!(
                "Dropped excess connection, active: {}",
                self.active_count.load(Ordering::Relaxed)
            );
        }
    }

    /// Returns `(idle_connections, active_connections)`.
    pub fn stats(&self) -> (usize, usize) {
        let pool = self.connections.lock();
        (pool.len(), self.active_count.load(Ordering::Relaxed))
    }
}

fn decrement_saturating(counter: &AtomicUsize, ordering: Ordering) -> usize {
    match counter.fetch_update(ordering, Ordering::Acquire, |value| {
        Some(value.saturating_sub(1))
    }) {
        Ok(previous) | Err(previous) => previous.saturating_sub(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn local_listener(accept_count: usize) -> (String, u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local TCP listener should bind");
        let addr = listener
            .local_addr()
            .expect("local listener address should be available");
        let handle = tokio::spawn(async move {
            for _ in 0..accept_count {
                let _accepted = listener
                    .accept()
                    .await
                    .expect("pool should connect to local listener");
            }
        });
        (addr.ip().to_string(), addr.port(), handle)
    }

    #[tokio::test]
    async fn returned_connection_counts_as_idle_not_active() {
        let (host, port, accept_task) = local_listener(1).await;
        let pool = ConnectionPool::new(host, port, 1);

        let stream = pool
            .get_connection()
            .await
            .expect("pool should open a local connection");
        assert_eq!(pool.stats(), (0, 1));

        pool.return_connection(stream);

        assert_eq!(pool.stats(), (1, 0));
        accept_task.await.expect("accept task should not panic");
    }

    #[tokio::test]
    async fn reused_idle_connection_counts_as_active_until_returned_again() {
        let (host, port, accept_task) = local_listener(1).await;
        let pool = ConnectionPool::new(host, port, 1);
        let stream = pool
            .get_connection()
            .await
            .expect("pool should open a local connection");
        pool.return_connection(stream);

        let reused = pool
            .get_connection()
            .await
            .expect("pool should reuse idle connection");

        assert_eq!(pool.stats(), (0, 1));
        pool.return_connection(reused);
        assert_eq!(pool.stats(), (1, 0));
        accept_task.await.expect("accept task should not panic");
    }

    #[tokio::test]
    async fn returning_more_than_max_idle_drops_excess_connection() {
        let (host, port, accept_task) = local_listener(2).await;
        let pool = ConnectionPool::new(host, port, 1);
        let first = pool
            .get_connection()
            .await
            .expect("first local connection should open");
        let second = pool
            .get_connection()
            .await
            .expect("second local connection should open");
        assert_eq!(pool.stats(), (0, 2));

        pool.return_connection(first);
        pool.return_connection(second);

        assert_eq!(pool.stats(), (1, 0));
        accept_task.await.expect("accept task should not panic");
    }
}
