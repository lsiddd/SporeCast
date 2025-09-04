// ==============================================================================
// --- Palo Alto Configuration Constants ---
// Configuration specific to Palo Alto PAN-OS log forwarding
// For shared threat intelligence and behavioral analysis, see unified_config.rs
// ==============================================================================

// Re-export unified configuration for shared settings
pub use crate::unified_config::*;

// Palo Alto-specific settings
pub const PALO_ALTO_SYSLOG_PORT: u16 = 514; // UDP port for receiving Palo Alto syslog messages
pub const ELK_HOST: &str = "127.0.0.1"; // Logstash server IP for Palo Alto logs
pub const ELK_PORT: u16 = 5142; // TCP port for Logstash (different from Fortigate to avoid conflicts)
pub const LOG_FILE: &str = "/var/log/palo_alto_forwarder.log"; // Palo Alto forwarder log file
pub const STATE_FILE: &str = "/var/lib/palo-alto-forwarder/forwarder_state.json"; // State persistence file
pub const NO_LOG_FILE: bool = true; // Disable log file writes when set to true
