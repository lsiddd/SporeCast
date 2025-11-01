use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use reqwest::Client;
use serde_json;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::Ipv4Addr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::task::JoinSet;

use crate::unified_config::*;
use crate::telegram::send_telegram_message;

// ==============================================================================
// --- Threat Intelligence Database Structure ---
// This struct holds all loaded threat intelligence indicators.
// ==============================================================================
#[derive(Default, Clone)]
pub struct ThreatIntel {
    pub malicious_ips: Arc<HashMap<String, Vec<String>>>, // Stores malicious IPs and the list of feeds they appeared in.
    pub malicious_domains: Arc<HashSet<String>>,           // Stores unique malicious domains.
    pub malicious_hashes: Arc<HashSet<String>>,            // Stores unique malicious file hashes.
    pub malicious_urls: Arc<HashSet<String>>,              // Stores unique malicious URLs.
    pub last_updated: DateTime<Utc>,                       // Timestamp of the last successful update.
}

impl ThreatIntel {
    // Constructor for ThreatIntel, also initializes hardcoded suspicious patterns.
    pub fn new() -> Self {
        ThreatIntel {
            last_updated: Utc::now(),
            malicious_ips: Arc::new(HashMap::new()),
            malicious_domains: Arc::new(HashSet::new()),
            malicious_hashes: Arc::new(HashSet::new()),
            malicious_urls: Arc::new(HashSet::new()),
        }
    }

    // Returns the total count of all loaded indicators.
    pub fn indicator_count(&self) -> usize {
        self.malicious_ips.len()
            + self.malicious_domains.len()
            + self.malicious_hashes.len()
            + self.malicious_urls.len()
    }
}

// ==============================================================================
// --- Threat Intelligence Feed Management ---
// Functions for downloading, caching, and managing threat intelligence feeds.
// ==============================================================================

// Generates a unique filename for a cached feed based on its URL (using SHA256 hash).
fn get_cache_filepath(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    let filepath = format!("{}/{:x}.json", THREAT_INTEL_CACHE_DIR, result);
    debug!("Generated cache filepath for URL '{}': {}", url, filepath);
    filepath
}

// Checks if a cached feed file is still valid (not expired based on refresh interval).
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
    false // Cache is not valid if file doesn't exist or modified time is unavailable/expired.
}

// Downloads a threat intelligence feed from a given URL and caches it.
async fn download_feed(url: &str) -> Result<HashSet<String>> {
    let cache_filepath = get_cache_filepath(url);
    if is_cache_valid(&cache_filepath) {
        info!("Using cached feed for {}.", url);
        // The tokio::fs::File::open().await already yields a tokio::fs::File.
        // We need to move this into spawn_blocking immediately to convert and read.
        let local_cache_filepath = cache_filepath.clone(); // Clone for the closure
        let items: HashSet<String> = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&local_cache_filepath)
                .with_context(|| format!("Failed to open cached feed file: {}", local_cache_filepath))?;
            serde_json::from_reader(file).with_context(|| {
                format!("Failed to parse cached feed from {}. It might be corrupted.", local_cache_filepath)
            })
        })
        .await
        .with_context(|| format!("Blocking task failed for reading cache: {}", cache_filepath))??; // Note the double '??' for nested Result

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
        .map(|line| line.trim())
        .filter(|line| !line.starts_with(&['#', ';', '/']) && !line.is_empty()) // Filter out comments and empty lines.
        .map(|s| s.to_string())
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

    // Now, create the file and write to it within a blocking task.
    let items_clone = items.clone(); // Clone items to move into the blocking task
    let local_cache_filepath_clone = cache_filepath.clone(); // Clone for the closure
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::create(&local_cache_filepath_clone)
            .with_context(|| format!("Failed to create cache file: {}", local_cache_filepath_clone))?;
        serde_json::to_writer(file, &items_clone).with_context(|| {
            format!(
                "Failed to write feed data to cache file: {}",
                local_cache_filepath_clone
            )
        })
    })
    .await
    .with_context(|| format!("Blocking task failed for writing cache: {}", cache_filepath))??; // Double '??' for nested Result

    info!(
        "Successfully downloaded and cached {} items from {}.",
        items.len(),
        url
    );
    Ok(items)
}

// Checks if an IP address is a public IP (i.e., not private, loopback, etc.).
pub fn is_public_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        let is_public = !ip.is_private()
            && !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_documentation();
        debug!("Checking IP '{}': is_private={}, is_loopback={}, is_unspecified={}, is_multicast={}, is_documentation={}, result={}",
                ip_str, ip.is_private(), ip.is_loopback(), ip.is_unspecified(), ip.is_multicast(), ip.is_documentation(), is_public);
        is_public
    } else {
        debug!("IP '{}' is not a valid Ipv4Addr.", ip_str);
        false
    }
}

// This thread is responsible for periodically updating the threat intelligence databases.
pub async fn threat_intel_updater_thread(intel_db: Arc<Mutex<ThreatIntel>>, shutdown: Arc<AtomicBool>) {
    info!(
        "Threat intelligence updater task started. Will refresh every {} seconds.",
        THREAT_INTEL_REFRESH_INTERVAL_SECS
    );
    // Initial sleep to allow other components to start up, and prevent immediate burst of downloads.
    tokio::time::sleep(Duration::from_secs(5)).await;

    loop {
        // Check for shutdown signal more frequently, without relying on long sleeps
        if shutdown.load(Ordering::Relaxed) {
            info!("Threat intel updater received shutdown signal.");
            break;
        }

        info!("Initiating threat intelligence database update cycle.");
        tokio::spawn(send_telegram_message("⏳ Starting threat intelligence database update...".to_string()));

        let mut new_intel = ThreatIntel::new(); // Create a new intel object to build up.
        let mut join_set = JoinSet::new();

        // --- Fetch Malicious IPs ---
        info!("Fetching malicious IP feeds...");
        let ip_futures: Vec<_> = IP_FEED_URLS.iter().map(|url| {
            let url_str = url.to_string();
            async move {
                (url_str.clone(), download_feed(&url_str).await)
            }
        }).collect();
        for fut in ip_futures {
            join_set.spawn(fut);
        }

        let mut all_ips: HashMap<String, Vec<String>> = HashMap::new();
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((url, Ok(items))) => {
                    info!("Successfully downloaded {} IPs from {}.", items.len(), url);
                    for ip in items {
                        if is_public_ip(&ip) {
                            all_ips.entry(ip.to_string()).or_default().push(url.to_string());
                        } else {
                            debug!("Skipping private/special IP from feed '{}': {}", url, ip);
                        }
                    }
                }
                Ok((url, Err(e))) => error!("Failed to download IP feed {}: {}", url, e),
                Err(e) => error!("Join error in IP feed download: {}", e),
            }
        }
        new_intel.malicious_ips = Arc::new(all_ips);
        info!(
            "Completed IP feed fetching. Loaded {} unique public malicious IPs.",
            new_intel.malicious_ips.len()
        );

        // --- Fetch other feeds concurrently using a new JoinSet ---
        let mut other_join_set = JoinSet::new();

        for url in URL_FEED_URLS.iter() {
            let url_str = url.to_string();
            other_join_set.spawn(async move {
                (url_str.clone(), download_feed(&url_str).await, "url")
            });
        }
        for url in HASH_FEED_URLS.iter() {
            let url_str = url.to_string();
            other_join_set.spawn(async move {
                (url_str.clone(), download_feed(&url_str).await, "hash")
            });
        }
        for url in DOMAIN_FEED_URLS.iter() {
            let url_str = url.to_string();
            other_join_set.spawn(async move {
                (url_str.clone(), download_feed(&url_str).await, "domain")
            });
        }

        while let Some(res) = other_join_set.join_next().await {
            match res {
                Ok((url, Ok(items), feed_type)) => {
                    info!("Successfully downloaded {} {}s from {}.", items.len(), feed_type, url);
                    // Update new_intel directly, not the shared one until fully built.
                    let target_arc_ref = match feed_type {
                        "url" => &mut new_intel.malicious_urls,
                        "hash" => &mut new_intel.malicious_hashes,
                        "domain" => &mut new_intel.malicious_domains,
                        _ => unreachable!(), // Should not happen with current logic
                    };
                    // Replace the Arc with a new one that contains the extended items
                    let mut current_map = (**target_arc_ref).clone(); // Clone the inner map/set
                    current_map.extend(items);
                    *target_arc_ref = Arc::new(current_map);
                }
                Ok((url, Err(e), feed_type)) => error!("Failed to download {} feed {}: {}", feed_type, url, e),
                Err(e) => error!("Join error in other feed download: {}", e),
            }
        }
        info!(
            "Completed URL feed fetching. Loaded {} malicious URLs.",
            new_intel.malicious_urls.len()
        );
        info!(
            "Completed Hash feed fetching. Loaded {} malicious hashes.",
            new_intel.malicious_hashes.len()
        );
        info!(
            "Completed Domain feed fetching. Loaded {} malicious domains.",
            new_intel.malicious_domains.len()
        );

        new_intel.last_updated = Utc::now();
        let total_indicators = new_intel.indicator_count();

        // Acquire a lock on the shared threat intelligence database and update it.
        info!("Acquiring lock on shared threat intelligence database for update.");
        *intel_db.lock().unwrap() = new_intel; // This will replace the old Arc'd data with new Arc'd data.
        info!(
            "Threat intelligence databases updated. Total indicators: {}",
            total_indicators
        );
        tokio::spawn(send_telegram_message(format!(
            // Cloned String here
            "✅ Threat intelligence databases updated. Total indicators loaded: {}.",
            total_indicators
        )));

        // Sleep until next refresh, but check shutdown flag every second.
        debug!(
            "Threat intelligence updater sleeping for {} seconds until next refresh.",
            THREAT_INTEL_REFRESH_INTERVAL_SECS
        );
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        for _ in 0..THREAT_INTEL_REFRESH_INTERVAL_SECS {
            interval.tick().await; // Wait for the next tick, non-blocking
            if shutdown.load(Ordering::Relaxed) {
                info!("Threat intel updater received shutdown signal during sleep.");
                break;
            }
        }
    }
    info!("Threat intelligence updater task shutting down gracefully.");
}