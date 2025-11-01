// ==============================================================================
// --- Fortigate-Specific Configuration ---
// This module defines Fortigate-specific configuration constants.
// For shared threat intelligence and behavioral analysis, see unified_config.rs
// ==============================================================================

// Re-export unified configuration for backward compatibility and shared settings
pub use crate::unified_config::*;
use regex::Regex;

// Fortigate-specific settings
pub const FORTIGATE_SYSLOG_PORT: u16 = 514; // UDP port for receiving Fortigate syslog messages
pub const ELK_HOST: &str = "68.168.216.248"; // Logstash server IP for Fortigate logs
pub const ELK_PORT: u16 = 5140; // TCP port for Logstash
pub const LOG_FILE: &str = "/var/log/fortigate_forwarder.log"; // Fortigate forwarder log file
pub const STATE_FILE: &str = "/var/lib/fortigate-forwarder/forwarder_state.json"; // State persistence file

// Fortigate-specific regex patterns
lazy_static::lazy_static! {
    // Regex to extract Fortigate key=value pairs
    pub static ref FORTIGATE_KV_REGEX: Regex = Regex::new(r#"(\w+)=((?:"((?:[^"\\]|\\.)*)"|([^"\s]+)))"#).unwrap();
}