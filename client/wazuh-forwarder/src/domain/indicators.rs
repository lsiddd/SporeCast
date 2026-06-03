//! Threat indicator domain model and lookup helpers.

use chrono::{DateTime, Utc};
use log::debug;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

#[derive(Clone)]
/// In-memory threat intelligence indicators shared by enrichment workers.
pub struct ThreatIntel {
    pub(crate) malicious_ips: Arc<HashMap<String, Vec<String>>>,
    pub(crate) malicious_domains: Arc<HashSet<String>>,
    pub(crate) malicious_hashes: Arc<HashSet<String>>,
    pub(crate) malicious_urls: Arc<HashSet<String>>,
    pub(crate) last_updated: DateTime<Utc>,
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

/// Returns true when `ip_str` is a public routable IP address (IPv4 or IPv6).
pub fn is_public_ip(ip_str: &str) -> bool {
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let is_public = !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_documentation();
            debug!("Checking IPv4 '{}': public={}", ip_str, is_public);
            is_public
        }
        Ok(IpAddr::V6(ip)) => {
            let is_public = !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !is_ipv6_link_local(&ip)
                && !is_ipv6_unique_local(&ip)
                && !is_ipv6_documentation(&ip);
            debug!("Checking IPv6 '{}': public={}", ip_str, is_public);
            is_public
        }
        Err(_) => {
            debug!("'{}' is not a valid IP address.", ip_str);
            false
        }
    }
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    // fe80::/10
    let octets = ip.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    // fc00::/7
    ip.octets()[0] & 0xfe == 0xfc
}

fn is_ipv6_documentation(ip: &Ipv6Addr) -> bool {
    // 2001:db8::/32
    let octets = ip.octets();
    octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8
}

#[cfg(test)]
mod tests {
    use super::is_public_ip;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    #[test]
    fn public_ip_filter_rejects_private_and_accepts_public_ipv4() {
        assert!(!is_public_ip("10.0.0.1"));
        assert!(!is_public_ip("172.16.0.1"));
        assert!(!is_public_ip("192.168.1.1"));
        assert!(!is_public_ip("127.0.0.1"));
        assert!(!is_public_ip("0.0.0.0"));
        assert!(is_public_ip("8.8.8.8"));
        assert!(is_public_ip("1.1.1.1"));
        assert!(is_public_ip("9.9.9.9"));
    }

    #[test]
    fn public_ip_filter_handles_ipv6() {
        // loopback
        assert!(!is_public_ip("::1"));
        // link-local
        assert!(!is_public_ip("fe80::1"));
        // unique-local
        assert!(!is_public_ip("fc00::1"));
        assert!(!is_public_ip("fd00::1"));
        // global unicast (real tshark addresses)
        assert!(is_public_ip("2a04:4e42:3b::820"));
        assert!(is_public_ip("2804:1434:1de:2000:a34b:2c44:98ac:570c"));
        assert!(is_public_ip("2800:3f0:4001:815::200a"));
    }

    #[test]
    fn public_ip_filter_rejects_ipv6_documentation_range() {
        assert!(!is_public_ip("2001:db8::1"));
    }

    #[test]
    fn public_ip_filter_rejects_invalid_strings() {
        assert!(!is_public_ip("not-an-ip"));
        assert!(!is_public_ip(""));
        assert!(!is_public_ip("example.com"));
    }

    proptest! {
        #[test]
        fn public_ip_filter_rejects_std_special_ipv4_ranges(octets in any::<[u8; 4]>()) {
            let ip = Ipv4Addr::from(octets);

            if ip.is_private()
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_documentation()
            {
                prop_assert!(!is_public_ip(&ip.to_string()));
            }
        }
    }
}
