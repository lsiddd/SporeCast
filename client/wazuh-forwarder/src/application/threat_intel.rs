//! Threat intelligence updater orchestration.

use chrono::Utc;
use log::{debug, error, info};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::task::JoinSet;

use crate::domain::indicators::{is_public_ip, ThreatIntel};
use crate::infrastructure::defaults::{
    DOMAIN_FEED_URLS, HASH_FEED_URLS, IP_FEED_URLS, THREAT_INTEL_CACHE_DIR,
    THREAT_INTEL_REFRESH_INTERVAL_SECS, URL_FEED_URLS,
};
use crate::infrastructure::threat_feeds::download_feed_to_cache_dir;

#[derive(Clone, Copy)]
pub(crate) struct ThreatFeedSources<'a> {
    pub ip: &'a [&'a str],
    pub url: &'a [&'a str],
    pub hash: &'a [&'a str],
    pub domain: &'a [&'a str],
}

fn default_threat_feed_sources() -> ThreatFeedSources<'static> {
    ThreatFeedSources {
        ip: &IP_FEED_URLS,
        url: &URL_FEED_URLS,
        hash: &HASH_FEED_URLS,
        domain: &DOMAIN_FEED_URLS,
    }
}

pub(crate) async fn refresh_threat_intel_once(
    feed_sources: ThreatFeedSources<'_>,
    cache_dir: &str,
) -> ThreatIntel {
    info!("Initiating threat intelligence database update cycle.");

    let mut new_intel = ThreatIntel::new();
    let mut join_set = JoinSet::new();

    info!("Fetching malicious IP feeds...");
    for url in feed_sources.ip.iter() {
        let url_str = url.to_string();
        let cache_dir = cache_dir.to_string();
        join_set.spawn(async move {
            (
                url_str.clone(),
                download_feed_to_cache_dir(&url_str, &cache_dir).await,
            )
        });
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

    for url in feed_sources.url.iter() {
        let url_str = url.to_string();
        let cache_dir = cache_dir.to_string();
        other_join_set.spawn(async move {
            (
                url_str.clone(),
                download_feed_to_cache_dir(&url_str, &cache_dir).await,
                "url",
            )
        });
    }
    for url in feed_sources.hash.iter() {
        let url_str = url.to_string();
        let cache_dir = cache_dir.to_string();
        other_join_set.spawn(async move {
            (
                url_str.clone(),
                download_feed_to_cache_dir(&url_str, &cache_dir).await,
                "hash",
            )
        });
    }
    for url in feed_sources.domain.iter() {
        let url_str = url.to_string();
        let cache_dir = cache_dir.to_string();
        other_join_set.spawn(async move {
            (
                url_str.clone(),
                download_feed_to_cache_dir(&url_str, &cache_dir).await,
                "domain",
            )
        });
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
    new_intel
}

/// Periodically refreshes the shared threat intelligence database until shutdown.
/// Sets `intel_ready` to true after the first load cycle completes.
pub async fn threat_intel_updater_thread(
    intel_db: Arc<Mutex<ThreatIntel>>,
    shutdown: Arc<AtomicBool>,
    intel_ready: Arc<AtomicBool>,
) {
    info!(
        "Threat intelligence updater task started. Will refresh every {} seconds.",
        THREAT_INTEL_REFRESH_INTERVAL_SECS
    );

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("Threat intel updater received shutdown signal.");
            break;
        }

        let new_intel =
            refresh_threat_intel_once(default_threat_feed_sources(), THREAT_INTEL_CACHE_DIR).await;
        let total_indicators = new_intel.indicator_count();

        info!("Acquiring lock on shared threat intelligence database for update.");
        *intel_db.lock() = new_intel;
        intel_ready.store(true, Ordering::Release);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
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

    async fn one_response_server(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
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
        });
        (url, handle)
    }

    #[tokio::test]
    async fn refresh_threat_intel_once_loads_injected_local_feeds() {
        let cache_dir = unique_cache_dir("threat_intel_refresh");
        let (ip_url, ip_server) = one_response_server("8.8.8.8\n10.0.0.1\n").await;
        let (url_url, url_server) = one_response_server("http://malicious.example/path\n").await;
        let (hash_url, hash_server) =
            one_response_server("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").await;
        let (domain_url, domain_server) = one_response_server("malicious.example\n").await;
        let ip_feeds = [ip_url.as_str()];
        let url_feeds = [url_url.as_str()];
        let hash_feeds = [hash_url.as_str()];
        let domain_feeds = [domain_url.as_str()];
        let sources = ThreatFeedSources {
            ip: &ip_feeds,
            url: &url_feeds,
            hash: &hash_feeds,
            domain: &domain_feeds,
        };

        let intel =
            refresh_threat_intel_once(sources, cache_dir.to_str().expect("valid temp path")).await;

        assert_eq!(intel.malicious_ips.get("8.8.8.8"), Some(&vec![ip_url]));
        assert!(!intel.malicious_ips.contains_key("10.0.0.1"));
        assert!(intel
            .malicious_urls
            .contains("http://malicious.example/path"));
        assert!(intel
            .malicious_hashes
            .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(intel.malicious_domains.contains("malicious.example"));
        assert_eq!(intel.indicator_count(), 4);

        ip_server.await.expect("IP server should complete");
        url_server.await.expect("URL server should complete");
        hash_server.await.expect("hash server should complete");
        domain_server.await.expect("domain server should complete");
        let _ = fs::remove_dir_all(cache_dir);
    }
}
