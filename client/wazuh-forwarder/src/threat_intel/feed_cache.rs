use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use reqwest::Client;
use std::{collections::HashSet, fs, path::Path, time::Duration};

use crate::unified_config::{THREAT_INTEL_CACHE_DIR, THREAT_INTEL_REFRESH_INTERVAL_SECS};

fn get_cache_filepath(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    let filepath = format!("{}/{:x}.json", THREAT_INTEL_CACHE_DIR, result);
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

pub(super) async fn download_feed(url: &str) -> Result<HashSet<String>> {
    let cache_filepath = get_cache_filepath(url);
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
