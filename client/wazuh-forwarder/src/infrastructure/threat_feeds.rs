use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use reqwest::Client;
use std::{collections::HashSet, fs, path::Path, time::Duration};

use crate::infrastructure::defaults::THREAT_INTEL_REFRESH_INTERVAL_SECS;

fn get_cache_filepath(cache_dir: &str, url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    let filepath = format!("{}/{:x}.json", cache_dir, result);
    debug!("Generated cache filepath for URL '{}': {}", url, filepath);
    filepath
}

fn is_cache_valid(filepath: &str) -> bool {
    debug!("Checking cache validity for: {}", filepath);
    if let Ok(metadata) = fs::metadata(filepath) {
        if let Ok(last_modified) = metadata.modified() {
            let elapsed = last_modified.elapsed().unwrap_or(Duration::MAX);
            let is_valid = elapsed < Duration::from_secs(THREAT_INTEL_REFRESH_INTERVAL_SECS);
            if is_valid {
                debug!(
                    "Cache for {} is still valid ({}s old, expires in {}s).",
                    filepath,
                    elapsed.as_secs(),
                    THREAT_INTEL_REFRESH_INTERVAL_SECS - elapsed.as_secs()
                );
            } else {
                info!(
                    "Cache for {} is expired ({}s old).",
                    filepath,
                    elapsed.as_secs()
                );
            }
            return is_valid;
        } else {
            warn!(
                "Could not get last modified time for cache file: {}",
                filepath
            );
        }
    } else {
        info!("Cache file does not exist: {}", filepath);
    }
    false
}

pub(crate) async fn download_feed_to_cache_dir(
    url: &str,
    cache_dir: &str,
) -> Result<HashSet<String>> {
    let cache_filepath = get_cache_filepath(cache_dir, url);
    if is_cache_valid(&cache_filepath) {
        info!("Using cached feed for {}.", url);
        let local_cache_filepath = cache_filepath.clone();
        let items: HashSet<String> = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&local_cache_filepath).with_context(|| {
                format!("Failed to open cached feed file: {}", local_cache_filepath)
            })?;
            serde_json::from_reader(file).with_context(|| {
                format!(
                    "Failed to parse cached feed from {}. It might be corrupted.",
                    local_cache_filepath
                )
            })
        })
        .await
        .with_context(|| format!("Blocking task failed for reading cache: {}", cache_filepath))??;

        debug!("Loaded {} items from cache for {}.", items.len(), url);
        return Ok(items);
    }

    info!("Downloading new feed from {}.", url);
    let client = Client::new();
    let response = client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .with_context(|| format!("Failed to send HTTP request to {}", url))?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP error {} for {}", response.status(), url));
    }

    let text = response
        .text()
        .await
        .with_context(|| format!("Failed to get response body from {}", url))?;
    let items: HashSet<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with(['#', ';', '/']) && !line.is_empty())
        .map(str::to_string)
        .collect();

    if let Some(parent) = Path::new(&cache_filepath).parent() {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "Failed to create parent directory for cache file: {:?}",
                parent
            )
        })?;
        debug!(
            "Ensured parent directory for cache file exists: {:?}",
            parent
        );
    }

    let items_clone = items.clone();
    let local_cache_filepath_clone = cache_filepath.clone();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::create(&local_cache_filepath_clone).with_context(|| {
            format!(
                "Failed to create cache file: {}",
                local_cache_filepath_clone
            )
        })?;
        serde_json::to_writer(file, &items_clone).with_context(|| {
            format!(
                "Failed to write feed data to cache file: {}",
                local_cache_filepath_clone
            )
        })
    })
    .await
    .with_context(|| format!("Blocking task failed for writing cache: {}", cache_filepath))??;

    info!(
        "Successfully downloaded and cached {} items from {}.",
        items.len(),
        url
    );
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::ErrorKind,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn unique_cache_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wazuh_forwarder_{name}_{}_{}",
            std::process::id(),
            nanos
        ))
    }

    async fn one_response_server(body: &'static str) -> (String, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local HTTP fixture should bind");
        let addr = listener
            .local_addr()
            .expect("local HTTP fixture address should be available");
        let url = format!("http://{}/feed.txt", addr);
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("HTTP fixture should receive one request");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("HTTP fixture should write response");
            1
        });
        (url, handle)
    }

    async fn no_request_server() -> (String, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local HTTP fixture should bind");
        let addr = listener
            .local_addr()
            .expect("local HTTP fixture address should be available");
        let url = format!("http://{}/feed.txt", addr);
        let handle = tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_millis(200), listener.accept()).await {
                Ok(Ok(_)) => 1,
                Ok(Err(err)) if err.kind() == ErrorKind::Interrupted => 0,
                Ok(Err(_)) => 1,
                Err(_) => 0,
            }
        });
        (url, handle)
    }

    #[tokio::test]
    async fn download_feed_filters_comments_blank_lines_and_slash_prefixed_lines() {
        let cache_dir = unique_cache_dir("feed_download");
        let (url, server) = one_response_server(
            "# comment\n; another comment\n/metadata\n\n8.8.8.8\n8.8.8.8\nexample.com\n",
        )
        .await;

        let items = download_feed_to_cache_dir(&url, cache_dir.to_str().expect("valid temp path"))
            .await
            .expect("feed should download");

        assert_eq!(
            items,
            ["8.8.8.8".to_string(), "example.com".to_string()]
                .into_iter()
                .collect()
        );
        assert_eq!(server.await.expect("server task should complete"), 1);

        let _ = fs::remove_dir_all(cache_dir);
    }

    #[tokio::test]
    async fn valid_cache_is_used_without_http_request() {
        let cache_dir = unique_cache_dir("feed_cache");
        let (url, server) = no_request_server().await;
        let cache_path = get_cache_filepath(cache_dir.to_str().expect("valid temp path"), &url);
        fs::create_dir_all(cache_dir.as_path()).expect("cache dir should be created");
        let cached: HashSet<String> = ["cached.example".to_string()].into_iter().collect();
        let file = fs::File::create(&cache_path).expect("cache file should be created");
        serde_json::to_writer(file, &cached).expect("cache fixture should be written");

        let items = download_feed_to_cache_dir(&url, cache_dir.to_str().expect("valid temp path"))
            .await
            .expect("valid cache should load");

        assert_eq!(items, cached);
        assert_eq!(server.await.expect("server task should complete"), 0);

        let _ = fs::remove_dir_all(cache_dir);
    }
}
