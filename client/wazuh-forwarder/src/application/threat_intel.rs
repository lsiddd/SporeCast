//! Threat intelligence updater orchestration.

use chrono::Utc;
use log::{debug, error, info};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::task::JoinSet;

use crate::domain::indicators::{is_public_ip, ThreatIntel};
use crate::infrastructure::defaults::{
    DOMAIN_FEED_URLS, HASH_FEED_URLS, IP_FEED_URLS, THREAT_INTEL_REFRESH_INTERVAL_SECS,
    URL_FEED_URLS,
};
use crate::infrastructure::threat_feeds::download_feed;

/// Periodically refreshes the shared threat intelligence database until shutdown.
pub async fn threat_intel_updater_thread(
    intel_db: Arc<Mutex<ThreatIntel>>,
    shutdown: Arc<AtomicBool>,
) {
    info!(
        "Threat intelligence updater task started. Will refresh every {} seconds.",
        THREAT_INTEL_REFRESH_INTERVAL_SECS
    );
    tokio::time::sleep(Duration::from_secs(5)).await;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("Threat intel updater received shutdown signal.");
            break;
        }

        info!("Initiating threat intelligence database update cycle.");

        let mut new_intel = ThreatIntel::new();
        let mut join_set = JoinSet::new();

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
                    let target_arc_ref = match feed_type {
                        "url" => &mut new_intel.malicious_urls,
                        "hash" => &mut new_intel.malicious_hashes,
                        "domain" => &mut new_intel.malicious_domains,
                        other => {
                            error!("Unexpected threat intelligence feed type: {}", other);
                            continue;
                        }
                    };
                    let mut current_map = (**target_arc_ref).clone();
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

        debug!(
            "Threat intelligence updater sleeping for {} seconds until next refresh.",
            THREAT_INTEL_REFRESH_INTERVAL_SECS
        );
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        for _ in 0..THREAT_INTEL_REFRESH_INTERVAL_SECS {
            interval.tick().await;
            if shutdown.load(Ordering::Relaxed) {
                info!("Threat intel updater received shutdown signal during sleep.");
                break;
            }
        }
    }
    info!("Threat intelligence updater task shutting down gracefully.");
}
