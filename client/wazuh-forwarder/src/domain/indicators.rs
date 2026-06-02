//! Threat indicator domain model and lookup helpers.

use chrono::{DateTime, Utc};
use log::debug;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
};

#[derive(Clone)]
/// In-memory threat intelligence indicators shared by enrichment workers.
pub struct ThreatIntel {
    pub malicious_ips: Arc<HashMap<String, Vec<String>>>,
    pub malicious_domains: Arc<HashSet<String>>,
    pub malicious_hashes: Arc<HashSet<String>>,
    pub malicious_urls: Arc<HashSet<String>>,
    pub last_updated: DateTime<Utc>,
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntel {
    /// Creates an empty threat intelligence database with a fresh update timestamp.
    pub fn new() -> Self {
        ThreatIntel {
            last_updated: Utc::now(),
            malicious_ips: Arc::new(HashMap::new()),
            malicious_domains: Arc::new(HashSet::new()),
            malicious_hashes: Arc::new(HashSet::new()),
            malicious_urls: Arc::new(HashSet::new()),
        }
    }

    /// Returns the total count of loaded indicators across all indicator types.
    pub fn indicator_count(&self) -> usize {
        self.malicious_ips.len()
            + self.malicious_domains.len()
            + self.malicious_hashes.len()
            + self.malicious_urls.len()
    }
}

/// Returns true when `ip_str` is a public IPv4 address.
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

#[cfg(test)]
mod tests {
    use super::is_public_ip;

    #[test]
    fn public_ip_filter_rejects_private_and_accepts_public_ipv4() {
        assert!(!is_public_ip("10.0.0.1"));
        assert!(!is_public_ip("127.0.0.1"));
        assert!(is_public_ip("8.8.8.8"));
    }
}
