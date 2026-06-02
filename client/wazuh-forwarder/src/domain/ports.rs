//! Domain-facing ports for infrastructure-backed lookups.

use serde_json::Value;

pub(crate) trait GeoIpLookup {
    fn lookup(&self, ip_str: &str) -> Option<Value>;
}
