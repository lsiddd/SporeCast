use regex::Regex;
use std::collections::HashMap;

// ==============================================================================
// --- Configuration ---
// These constants define the core operational parameters of the forwarder.
// ==============================================================================
pub const FORTIGATE_SYSLOG_PORT: u16 = 514; // The UDP port the forwarder will listen on for Fortigate Syslog messages.
                                         // IMPORTANT: This application will bind exclusively to this port.
                                         // Wazuh MUST be configured to listen on a different port (e.g., 1514)
                                         // for the forwarded logs.

pub const WAZUH_LOCAL_SYSLOG_HOST: &str = "127.0.0.1"; // The IP address where Wazuh's internal Syslog listener is.
pub const WAZUH_LOCAL_SYSLOG_PORT: u16 = 1514; // The UDP port Wazuh will be reconfigured to listen on.

pub const ELK_HOST: &str = "68.168.216.248"; // The IP address or hostname of the Logstash server in your ELK stack.
pub const ELK_PORT: u16 = 5140; // The TCP port on which your Logstash service is listening.
pub const SOCKET_TIMEOUT_SECS: u64 = 10; // Timeout in seconds for network socket operations (e.g., connecting to ELK).
pub const LOG_FILE: &str = "/var/log/fortigate_forwarder.log"; // Path where the forwarder will write its own operational logs.
pub const STATE_FILE: &str = "/var/lib/fortigate-forwarder/forwarder_state.json"; // Path to store the behavioral analysis state for persistence across restarts.
pub const MAX_RECEIVER_QUEUE_SIZE: usize = 50000; // Max logs buffered between receiver and enrichment threads. Increased for high throughput.
pub const MAX_ENRICHMENT_QUEUE_SIZE: usize = 40000; // Max logs buffered between enrichment and sender threads. Increased for high throughput.
pub const MAX_WAZUH_QUEUE_SIZE: usize = 40000; // Max logs buffered for Wazuh sender. Added for new channel.
pub const ENRICHMENT_WORKER_COUNT: usize = 8; // Number of threads to process and enrich logs concurrently. Adjust based on CPU cores.
pub const ELK_BATCH_SIZE: usize = 1000; // Number of logs to batch before sending to ELK. Increased for efficiency.
pub const ELK_BATCH_FLUSH_INTERVAL_SECS: u64 = 1; // Max time to wait (in seconds) before flushing a partial ELK batch.

// --- Telegram Notification Configuration ---
pub const ENABLE_TELEGRAM: bool = true; // Set to `true` to enable Telegram status notifications.
pub const TELEGRAM_TOKEN: &str = "YOUR_TELEGRAM_BOT_TOKEN"; // Your Telegram Bot Token from BotFather. **MUST BE REPLACED!**
pub const TELEGRAM_CHAT_ID: &str = "YOUR_TELEGRAM_CHAT_ID"; // The chat ID to which the bot should send messages. **MUST BE REPLACED!**
pub const HEARTBEAT_INTERVAL_SECS: u64 = 3600; // How often (in seconds) to send a heartbeat message to Telegram (e.g., 3600s = 1 hour).

// --- Threat Intelligence Configuration ---
pub const ENABLE_THREAT_INTEL_FEEDS: bool = true; // Set to `true` to enable external threat intelligence feed fetching and enrichment.
pub const THREAT_INTEL_REFRESH_INTERVAL_SECS: u64 = 86400; // How often (in seconds) the threat intelligence feeds are re-downloaded (e.g., 86400s = 24 hours).
pub const THREAT_INTEL_CACHE_DIR: &str = "/var/lib/fortigate-forwarder/threat_intel_cache"; // Directory to store cached copies of the downloaded threat intel feeds.

// IP Feeds (Blocklists) - URLs for various IP blocklist sources.
pub const IP_FEED_URLS: [&str; 12] = [
    "https://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "https://www.binarydefense.com/banlist.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://raw.githubusercontent.com/abuseipdb/blacklist/master/abuseipdb-s100-all.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/ips.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1",
];

// Malicious URL Feeds - URLs for sources of malicious URLs.
pub const URL_FEED_URLS: [&str; 1] = ["https://urlhaus.abuse.ch/downloads/text/"];

// Malicious Hash Feeds (e.g., SHA256) - URLs for sources of malicious file hashes.
pub const HASH_FEED_URLS: [&str; 1] = ["https://bazaar.abuse.ch/export/txt/sha256/full/"];

// Malicious Domain Feeds - URLs for sources of malicious domains.
pub const DOMAIN_FEED_URLS: [&str; 2] = [
    "https://www.malwaredomainlist.com/hostslist/domains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
];

// --- Threat hunting configurations ---
pub const ENABLE_BEHAVIORAL_ANALYSIS: bool = true; // Enables custom behavioral analysis rules.
pub const BEHAVIOR_WINDOW_MINUTES: i64 = 5; // Time window in minutes for behavioral anomaly detection (e.g., 5 minutes for "high frequency" alerts).
pub const HIGH_SEVERITY_THRESHOLD: u32 = 10; // Number of events within `BEHAVIOR_WINDOW_MINUTES` to trigger a high-frequency anomaly.
pub const SUSPICIOUS_PROCESSES: [&str; 15] = [
    // Keywords to look for in command lines or messages indicating suspicious activity.
    "meterpreter",
    "cobaltstrike",
    "powershell -e",
    "powershell -enc",
    "certutil",
    "bitsadmin",
    "wmic",
    "mshta",
    "rundll32",
    "regsvr32",
    "schtasks",
    "psexec",
    "netcat",
    "nc",
    "ncat",
];
pub const CRITICAL_ASSETS: [&str; 5] = [
    // Keywords to identify access to critical assets.
    "domain-controller",
    "database-server",
    "payment-gateway",
    "erp-system",
    "scada-system",
];

// CORRELATION_RULES definition needed for lazy_static
pub const CORRELATION_RULES: [(&str, &str); 10] = [
    ("brute_force", r"authentication failure"),
    ("port_scan", r"scan detected|port scan"),
    ("malware_exec", r"malware|virus|trojan"),
    ("suspicious_login", r"login outside business hours"),
    ("data_exfiltration", r"large data transfer|exfiltration"),
    ("privilege_escalation", r"sudo|su|privilege escalation"),
    ("config_change", r"configuration changed"),
    ("critical_service_stop", r"service stopped|terminated"),
    ("new_service", r"new service installed"),
    ("persistence", r"persistence mechanism|startup item"),
];

// Lazy static Regex objects for efficient pattern matching across the application.
lazy_static::lazy_static! {
    pub static ref IP_REGEX: Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(); // Regex to find IP addresses.
    pub static ref DOMAIN_REGEX: Regex = Regex::new(r"\b(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}\b").unwrap(); // Regex to find domain names.
    pub static ref HASH_REGEX: Regex = Regex::new(r"\b[a-f0-9]{32,128}\b").unwrap(); // Regex to find hashes (e.g., MD5, SHA1, SHA256).
    pub static ref URL_REGEX: Regex = Regex::new(r#"(https?://[^\s"<>]+|www\.[^\s"<>]+\.[^\s"<>]+)"#).unwrap(); // Regex to find URLs.
    // Regex to extract Fortigate key=value pairs.
    pub static ref FORTIGATE_KV_REGEX: Regex = Regex::new(r#"(\w+)=((?:"((?:[^"\\]|\\.)*)"|([^"\s]+)))"#).unwrap();

    pub static ref CORRELATION_RULES_COMPILED: Vec<(&'static str, Regex)> = CORRELATION_RULES.iter().map(|(name, pattern)| {
        (*name, Regex::new(pattern).expect("Failed to compile correlation rule regex"))
    }).collect();

    // Additional Suspicious Patterns (pre-compiled)
    pub static ref SUSPICIOUS_PATTERNS_COMPILED: HashMap<String, Regex> = {
        let mut map = HashMap::new();
        map.insert("obfuscated_powershell".to_string(), Regex::new(r#"(?:['"])*[a-z0-9]{20,}(?:['"])*"#).unwrap());
        map.insert("base64_encoded".to_string(), Regex::new(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap());
        map.insert("hex_encoded".to_string(), Regex::new(r"(\\x[0-9a-f]{2}){10,}").unwrap());
        map
    };
}