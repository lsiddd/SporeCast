use chrono::{DateTime, Utc};
use log::{debug, error, info};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::task::JoinSet;

use crate::unified_config::*;

mod feed_cache;
use feed_cache::download_feed;

#[derive(Clone)]
pub struct ThreatIntel {
    pub malicious_ips: Arc<HashMap<String, Vec<String>>>, // Stores malicious IPs and the list of feeds they appeared in.
    pub malicious_domains: Arc<HashSet<String>>,          // Stores unique malicious domains.
    pub malicious_hashes: Arc<HashSet<String>>,           // Stores unique malicious file hashes.
    pub malicious_urls: Arc<HashSet<String>>,             // Stores unique malicious URLs.
    pub last_updated: DateTime<Utc>, // Timestamp of the last successful update.
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
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
pub async fn threat_intel_updater_thread(
    intel_db: Arc<Mutex<ThreatIntel>>,
    shutdown: Arc<AtomicBool>,
) {
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

        let mut new_intel = ThreatIntel::new(); // Create a new intel object to build up.
        let mut join_set = JoinSet::new();

        // --- Fetch Malicious IPs ---
        info!("Fetching malicious IP feeds...");
        for url in IP_FEED_URLS.iter() {
            let url_str = url.to_string();
            join_set.spawn(async move { (url_str.clone(), download_feed(&url_str).await) });
        }

        let mut all_ips: HashMap<String, Vec<String>> = HashMap::new();
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((url, Ok(items))) => {
                    info!("Successfully downloaded {} IPs from {}.", items.len(), url);
                    for ip in items {
                        if is_public_ip(&ip) {
                            all_ips.entry(ip).or_default().push(url.clone());
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
            other_join_set
                .spawn(async move { (url_str.clone(), download_feed(&url_str).await, "url") });
        }
        for url in HASH_FEED_URLS.iter() {
            let url_str = url.to_string();
            other_join_set
                .spawn(async move { (url_str.clone(), download_feed(&url_str).await, "hash") });
        }
        for url in DOMAIN_FEED_URLS.iter() {
            let url_str = url.to_string();
            other_join_set
                .spawn(async move { (url_str.clone(), download_feed(&url_str).await, "domain") });
        }

        while let Some(res) = other_join_set.join_next().await {
            match res {
                Ok((url, Ok(items), feed_type)) => {
                    info!(
                        "Successfully downloaded {} {}s from {}.",
                        items.len(),
                        feed_type,
                        url
                    );
                    // Update new_intel directly, not the shared one until fully built.
                    let target_arc_ref = match feed_type {
                        "url" => &mut new_intel.malicious_urls,
                        "hash" => &mut new_intel.malicious_hashes,
                        "domain" => &mut new_intel.malicious_domains,
                        other => {
                            error!("Unexpected threat intelligence feed type: {}", other);
                            continue;
                        }
                    };
                    // Replace the Arc with a new one that contains the extended items
                    let mut current_map = (**target_arc_ref).clone(); // Clone the inner map/set
                    current_map.extend(items);
                    *target_arc_ref = Arc::new(current_map);
                }
                Ok((url, Err(e), feed_type)) => {
                    error!("Failed to download {} feed {}: {}", feed_type, url, e)
                }
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
        match intel_db.lock() {
            Ok(mut intel) => {
                *intel = new_intel;
            }
            Err(e) => {
                error!(
                    "Threat intelligence mutex poisoned; stopping updater: {}",
                    e
                );
                break;
            }
        }
        info!(
            "Threat intelligence databases updated. Total indicators loaded: {}.",
            total_indicators
        );

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
