use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

// ==============================================================================
// --- Palo Alto Configuration Constants ---
// Configuration specific to Palo Alto PAN-OS log forwarding
// ==============================================================================

// Network Configuration
pub const PALO_ALTO_SYSLOG_PORT: u16 = 5514; // Different port from Fortigate
pub const WAZUH_LOCAL_SYSLOG_HOST: &str = "127.0.0.1"; 
pub const WAZUH_LOCAL_SYSLOG_PORT: u16 = 1514;

// ELK Configuration (same as Fortigate)
pub const ELK_HOST: &str = "127.0.0.1";
pub const ELK_PORT: u16 = 9200;
pub const ELK_INDEX_NAME: &str = "palo-alto-logs";

// Application Configuration
pub const LOG_FILE: &str = "/var/log/palo_alto_forwarder.log";
pub const STATE_FILE: &str = "/tmp/palo_alto_forwarder_state.json";

// Thread and Queue Configuration
pub const MAX_RECEIVER_QUEUE_SIZE: usize = 10000;
pub const MAX_ENRICHMENT_QUEUE_SIZE: usize = 5000;
pub const MAX_WAZUH_QUEUE_SIZE: usize = 5000;
pub const ENRICHMENT_WORKER_COUNT: usize = 4;

// Behavioral Analysis Configuration
pub const ENABLE_BEHAVIORAL_ANALYSIS: bool = true;
pub const ENABLE_THREAT_INTEL_FEEDS: bool = true;

// Threat Intelligence Feed URLs (reuse from Fortigate config)
pub const THREAT_INTEL_FEEDS: &[&str] = &[
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://threatfox.abuse.ch/downloads/hostfile.txt",
];
pub const THREAT_INTEL_UPDATE_INTERVAL_HOURS: u64 = 24;

// Telegram Configuration for Alerts (same as Fortigate)
pub const TELEGRAM_BOT_TOKEN: &str = "YOUR_BOT_TOKEN_HERE";
pub const TELEGRAM_CHAT_ID: &str = "YOUR_CHAT_ID_HERE";

// ==============================================================================
// --- Palo Alto Specific Patterns ---
// Regex patterns for threat hunting in Palo Alto logs
// ==============================================================================

lazy_static! {
    // IP Address Regex (IPv4 and IPv6)
    pub static ref IP_REGEX: Regex = Regex::new(
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    ).unwrap();

    // Domain Name Regex
    pub static ref DOMAIN_REGEX: Regex = Regex::new(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    ).unwrap();

    // Hash Regex (MD5, SHA1, SHA256, SHA512)
    pub static ref HASH_REGEX: Regex = Regex::new(
        r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b"
    ).unwrap();

    // URL Regex
    pub static ref URL_REGEX: Regex = Regex::new(
        r"(?i)https?://[^\s/$.?#].[^\s]*"
    ).unwrap();

    // Palo Alto specific suspicious patterns
    pub static ref SUSPICIOUS_PATTERNS_COMPILED: HashMap<String, Regex> = {
        let mut patterns = HashMap::new();
        patterns.insert("base64_payload".to_string(), Regex::new(r"(?i)[a-zA-Z0-9+/]{20,}={0,2}").unwrap());
        patterns.insert("suspicious_user_agent".to_string(), Regex::new(r"(?i)(curl|wget|python|powershell|cmd)").unwrap());
        patterns.insert("command_injection".to_string(), Regex::new(r"(?i)(;|&&|\|\||`|\$\(|%[0-9a-f]{2})").unwrap());
        patterns.insert("sql_injection".to_string(), Regex::new(r"(?i)(union\s+select|drop\s+table|insert\s+into|update\s+set)").unwrap());
        patterns.insert("xss_attempt".to_string(), Regex::new(r"(?i)(<script|javascript:|onload=|onerror=)").unwrap());
        patterns.insert("file_inclusion".to_string(), Regex::new(r"(?i)(\.\.\/|\.\.\\|\/etc\/|c:\\)").unwrap());
        patterns.insert("crypto_mining".to_string(), Regex::new(r"(?i)(stratum|mining|coinminer|cryptonight)").unwrap());
        patterns
    };

    // Correlation rules for Palo Alto specific threats
    pub static ref CORRELATION_RULES_COMPILED: HashMap<String, Regex> = {
        let mut rules = HashMap::new();
        rules.insert("high_risk_application".to_string(), Regex::new(r"(?i)(p2p|file-sharing|proxy|tunnel)").unwrap());
        rules.insert("suspicious_traffic_pattern".to_string(), Regex::new(r"(?i)(large volume|bandwidth abuse|connection flood)").unwrap());
        rules.insert("policy_violation".to_string(), Regex::new(r"(?i)(deny|block|reject|drop)").unwrap());
        rules.insert("threat_detected".to_string(), Regex::new(r"(?i)(malware|virus|trojan|backdoor|exploit)").unwrap());
        rules.insert("data_exfiltration".to_string(), Regex::new(r"(?i)(upload|ftp|sftp|scp|large outbound)").unwrap());
        rules
    };
}

// Suspicious processes for Palo Alto analysis
pub const SUSPICIOUS_PROCESSES: &[&str] = &[
    "powershell",
    "cmd.exe", 
    "psexec",
    "wmic",
    "rundll32",
    "regsvr32",
    "mshta",
    "bitsadmin",
    "certutil",
    "netsh",
    "taskkill",
    "schtasks",
    "whoami",
    "ipconfig",
    "netstat",
    "systeminfo"
];

// Critical assets keywords for Palo Alto environments
pub const CRITICAL_ASSETS: &[&str] = &[
    "domain controller",
    "active directory",
    "database server",
    "file server",
    "backup server",
    "email server",
    "web server",
    "application server",
    "firewall",
    "switch",
    "router",
    "vpn",
    "certificate authority",
    "ldap"
];

// Palo Alto specific application categories to monitor
pub const HIGH_RISK_APP_CATEGORIES: &[&str] = &[
    "peer-to-peer",
    "file-sharing",
    "proxy",
    "anonymizer", 
    "tunneling",
    "hacking-tools",
    "malware",
    "command-and-control",
    "cryptocurrency"
];