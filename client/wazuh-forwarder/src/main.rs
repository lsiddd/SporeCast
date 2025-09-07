use anyhow::{anyhow, Context, Result};
use chrono::prelude::*;
use crossbeam_channel::{bounded, Receiver, Sender};
use log::{debug, error, info, warn, LevelFilter};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

// ==============================================================================
// --- Configuration ---
// These constants define the core operational parameters of the forwarder.
// ==============================================================================
const FORTIGATE_SYSLOG_PORT: u16 = 514; // The UDP port the forwarder will listen on for Fortigate Syslog messages.
                                         // IMPORTANT: This application will bind exclusively to this port.
                                         // Wazuh MUST be configured to listen on a different port (e.g., 1514)
                                         // for the forwarded logs.

const WAZUH_LOCAL_SYSLOG_HOST: &str = "127.0.0.1"; // The IP address where Wazuh's internal Syslog listener is.
const WAZUH_LOCAL_SYSLOG_PORT: u16 = 1514;         // The UDP port Wazuh will be reconfigured to listen on.

const ELK_HOST: &str = "68.168.216.248"; // The IP address or hostname of the Logstash server in your ELK stack.
const ELK_PORT: u16 = 5140; // The TCP port on which your Logstash service is listening.
const SOCKET_TIMEOUT: u64 = 10; // Timeout in seconds for network socket operations (e.g., connecting to ELK).
const LOG_FILE: &str = "/var/log/fortigate_forwarder.log"; // Path where the forwarder will write its own operational logs.
const STATE_FILE: &str = "/var/lib/fortigate-forwarder/forwarder_state.json"; // Path to store the behavioral analysis state for persistence across restarts.
const MAX_QUEUE_SIZE: usize = 10000; // Maximum number of logs to buffer in the in-memory queue between receiver and sender threads.
const ELK_BATCH_SIZE: usize = 100; // Number of logs to batch before sending to ELK.
const ELK_BATCH_FLUSH_INTERVAL_SECS: u64 = 1; // Max time to wait (in seconds) before flushing a partial ELK batch.

// --- Telegram Notification Configuration ---
const ENABLE_TELEGRAM: bool = true; // Set to `true` to enable Telegram status notifications.
const TELEGRAM_TOKEN: &str = "YOUR_TELEGRAM_BOT_TOKEN"; // Your Telegram Bot Token from BotFather. **MUST BE REPLACED!**
const TELEGRAM_CHAT_ID: &str = "YOUR_TELEGRAM_CHAT_ID"; // The chat ID to which the bot should send messages. **MUST BE REPLACED!**
const HEARTBEAT_INTERVAL: u64 = 3600; // How often (in seconds) to send a heartbeat message to Telegram (e.g., 3600s = 1 hour).

// --- Threat Intelligence Configuration ---
const ENABLE_THREAT_INTEL_FEEDS: bool = true; // Set to `true` to enable external threat intelligence feed fetching and enrichment.
const THREAT_INTEL_REFRESH_INTERVAL_SECS: u64 = 86400; // How often (in seconds) the threat intelligence feeds are re-downloaded (e.g., 86400s = 24 hours).
const THREAT_INTEL_CACHE_DIR: &str = "/var/lib/fortigate-forwarder/threat_intel_cache"; // Directory to store cached copies of the downloaded threat intel feeds.

// IP Feeds (Blocklists) - URLs for various IP blocklist sources.
const IP_FEED_URLS: [&str; 12] = [
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
const URL_FEED_URLS: [&str; 1] = [
    "https://urlhaus.abuse.ch/downloads/text/",
];

// Malicious Hash Feeds (e.g., SHA256) - URLs for sources of malicious file hashes.
const HASH_FEED_URLS: [&str; 1] = [
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
];

// Malicious Domain Feeds - URLs for sources of malicious domains.
const DOMAIN_FEED_URLS: [&str; 2] = [
    "https://www.malwaredomainlist.com/hostslist/domains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
];


// --- Threat hunting configurations ---
const ENABLE_BEHAVIORAL_ANALYSIS: bool = true; // Enables custom behavioral analysis rules.
const BEHAVIOR_WINDOW_MINUTES: i64 = 5; // Time window in minutes for behavioral anomaly detection (e.g., 5 minutes for "high frequency" alerts).
const HIGH_SEVERITY_THRESHOLD: u32 = 10; // Number of events within `BEHAVIOR_WINDOW_MINUTES` to trigger a high-frequency anomaly.
const SUSPICIOUS_PROCESSES: [&str; 15] = [ // Keywords to look for in command lines or messages indicating suspicious activity.
    "meterpreter", "cobaltstrike", "powershell -e", "powershell -enc",
    "certutil", "bitsadmin", "wmic", "mshta", "rundll32", "regsvr32",
    "schtasks", "psexec", "netcat", "nc", "ncat"
];
const CRITICAL_ASSETS: [&str; 5] = [ // Keywords to identify access to critical assets.
    "domain-controller", "database-server", "payment-gateway",
    "erp-system", "scada-system"
];
// Moved CORRELATION_RULES to lazy_static to compile regexes once.

// Lazy static Regex objects for efficient pattern matching across the application.
lazy_static::lazy_static! {
    static ref IP_REGEX: Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(); // Regex to find IP addresses.
    static ref DOMAIN_REGEX: Regex = Regex::new(r"\b(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}\b").unwrap(); // Regex to find domain names.
    static ref HASH_REGEX: Regex = Regex::new(r"\b[a-f0-9]{32,128}\b").unwrap(); // Regex to find hashes (e.g., MD5, SHA1, SHA256).
    static ref URL_REGEX: Regex = Regex::new(r#"(https?://[^\s"<>]+|www\.[^\s"<>]+\.[^\s"<>]+)"#).unwrap(); // Regex to find URLs.
    // Regex to extract Fortigate key=value pairs.
    static ref FORTIGATE_KV_REGEX: Regex = Regex::new(r#"(\w+)=((?:"((?:[^"\\]|\\.)*)"|([^"\s]+)))"#).unwrap();

    static ref CORRELATION_RULES_COMPILED: Vec<(&'static str, Regex)> = CORRELATION_RULES.iter().map(|(name, pattern)| {
        (*name, Regex::new(pattern).expect("Failed to compile correlation rule regex"))
    }).collect();
}

// CORRELATION_RULES definition needed for lazy_static
const CORRELATION_RULES: [(&str, &str); 10] = [
    ("brute_force", r"authentication failure"),
    ("port_scan", r"scan detected|port scan"),
    ("malware_exec", r"malware|virus|trojan"),
    ("suspicious_login", r"login outside business hours"),
    ("data_exfiltration", r"large data transfer|exfiltration"),
    ("privilege_escalation", r"sudo|su|privilege escalation"),
    ("config_change", r"configuration changed"),
    ("critical_service_stop", r"service stopped|terminated"),
    ("new_service", r"new service installed"),
    ("persistence", r"persistence mechanism|startup item")
];

// ==============================================================================
// --- Threat Intelligence Database Structure ---
// This struct holds all loaded threat intelligence indicators.
// ==============================================================================
#[derive(Serialize, Deserialize, Default, Clone)]
struct ThreatIntel {
    malicious_ips: HashMap<String, Vec<String>>, // Stores malicious IPs and the list of feeds they appeared in.
    malicious_domains: HashSet<String>,            // Stores unique malicious domains.
    malicious_hashes: HashSet<String>,             // Stores unique malicious file hashes.
    malicious_urls: HashSet<String>,               // Stores unique malicious URLs.
    suspicious_patterns: HashMap<String, String>, // Custom regex patterns for threat hunting.
    last_updated: DateTime<Utc>,                   // Timestamp of the last successful update.
}

impl ThreatIntel {
    // Constructor for ThreatIntel, also initializes hardcoded suspicious patterns.
    fn new() -> Self {
        let mut intel = ThreatIntel {
            last_updated: Utc::now(),
            ..Default::default() // Initializes all HashMaps/HashSets as empty
        };

        // Initialize suspicious patterns that are not fetched from external feeds.
        debug!("Initializing suspicious patterns for threat intelligence.");
        intel.suspicious_patterns.insert(
            "obfuscated_powershell".to_string(),
            r#"(?:['"])*[a-z0-9]{20,}(?:['"])*"#.to_string(),
        );
        intel.suspicious_patterns.insert(
            "base64_encoded".to_string(),
            r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?".to_string(),
        );
        intel.suspicious_patterns.insert(
            "hex_encoded".to_string(),
            r"(\\x[0-9a-f]{2}){10,}".to_string(),
        );
        debug!("Suspicious patterns initialized.");
        intel
    }

    // Returns the total count of all loaded indicators.
    fn indicator_count(&self) -> usize {
        self.malicious_ips.len()
            + self.malicious_domains.len()
            + self.malicious_hashes.len()
            + self.malicious_urls.len()
    }
}


// ==============================================================================
// --- Behavioral Analysis Engine Structure ---
// This struct tracks historical log data for anomaly detection.
// ==============================================================================
#[derive(Serialize, Deserialize, Clone, Debug)]
struct AlertHistory {
    src_ips: HashMap<String, u32>,  // Counts of source IPs within the behavior window.
    users: HashMap<String, u32>,    // Counts of users within the behavior window.
    rules: HashMap<u32, u32>,       // Counts of Fortigate `logid`s within the behavior window.
    last_alert_time: DateTime<Utc>, // Timestamp of the last processed log. Used to reset the window.
}

impl Default for AlertHistory {
    // Provides a default, empty state for AlertHistory.
    fn default() -> Self {
        Self {
            src_ips: HashMap::new(),
            users: HashMap::new(),
            rules: HashMap::new(),
            last_alert_time: Utc::now(),
        }
    }
}

impl AlertHistory {
    // Updates the behavioral history with data from the current log.
    fn update(&mut self, log_data: &Value) {
        let now = Utc::now();

        // If the last log was processed outside the defined behavior window, reset all counts.
        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            info!("Behavioral analysis window expired ({} minutes). Resetting history counts.", BEHAVIOR_WINDOW_MINUTES);
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now; // Update last processed time to current time.

        // Increment count for source IP. Checks both 'srcip' and 'src' fields.
        if let Some(src_ip) = log_data.get("srcip").or_else(|| log_data.get("src")).and_then(Value::as_str) {
            *self.src_ips.entry(src_ip.to_string()).or_insert(0) += 1;
            debug!("Updated src_ip history for {}: count = {}", src_ip, self.src_ips[src_ip]);
        }
        // Increment count for user. Fortigate logs might not consistently have a 'user' field in all log types.
        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
            *self.users.entry(user.to_string()).or_insert(0) += 1;
            debug!("Updated user history for {}: count = {}", user, self.users[user]);
        }
        // Increment count for Fortigate 'logid'. This acts as a unique identifier for log types.
        if let Some(logid) = log_data.get("logid").and_then(Value::as_u64) {
            *self.rules.entry(logid as u32).or_insert(0) += 1;
            debug!("Updated logid history for {}: count = {}", logid, self.rules[&(logid as u32)]);
        }
    }

    // Checks if the current log, in context of history, indicates suspicious activity.
    fn is_suspicious_activity(&self, log_data: &Value) -> Option<Value> {
        let mut anomalies = json!({});
        let mut found_anomaly = false;

        // Check for high frequency from the same source IP.
        if let Some(src_ip) = log_data.get("srcip").or_else(|| log_data.get("src")).and_then(Value::as_str) {
            if let Some(&count) = self.src_ips.get(src_ip) {
                if count > HIGH_SEVERITY_THRESHOLD {
                    warn!("High frequency IP detected: {} has {} events in last {} minutes.", src_ip, count, BEHAVIOR_WINDOW_MINUTES);
                    anomalies["high_frequency_ip"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }
        // Check for suspicious user activity frequency.
        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
            if let Some(&count) = self.users.get(user) {
                if count > HIGH_SEVERITY_THRESHOLD {
                    warn!("High frequency user detected: {} has {} events in last {} minutes.", user, count, BEHAVIOR_WINDOW_MINUTES);
                    anomalies["high_frequency_user"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }
        // Check for specific Fortigate log ID flooding.
        if let Some(logid) = log_data.get("logid").and_then(Value::as_u64) {
            if let Some(&count) = self.rules.get(&(logid as u32)) {
                if count > HIGH_SEVERITY_THRESHOLD {
                    warn!("High frequency Log ID detected: {} has {} events in last {} minutes.", logid, count, BEHAVIOR_WINDOW_MINUTES);
                    anomalies["high_frequency_logid"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }

        // Return anomalies if any were found, otherwise None.
        if found_anomaly { Some(anomalies) } else { None }
    }
}

// ==============================================================================
// --- State Management ---
// Handles loading and saving the forwarder's persistent state (behavioral history).
// ==============================================================================
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct State {
    inode: Option<u64>, // Not used for syslog, kept for potential future file-based features
    offset: u64,        // Not used for syslog, kept for potential future file-based features
    alert_history: AlertHistory, // The behavioral analysis history.
}

struct StateManager {
    state_file: String, // Path to the state file.
    state: State,       // The current state object.
}

impl StateManager {
    // Creates a new StateManager instance with a default empty state.
    fn new(state_file: &str) -> Self {
        debug!("Creating new StateManager for file: {}", state_file);
        let state = State::default();
        Self { state_file: state_file.to_string(), state }
    }

    // Attempts to load the state from the configured state file.
    fn load(&mut self) -> Result<()> {
        info!("Attempting to load state from: {}", self.state_file);
        if !Path::new(&self.state_file).exists() {
            info!("State file not found at {}. Using default state for first run.", self.state_file);
            return Ok(()); // No error, just a new start.
        }
        let contents = fs::read_to_string(&self.state_file)
            .with_context(|| format!("Failed to read state file {}", self.state_file))?;
        self.state = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file {}", self.state_file))?;
        info!("Successfully loaded state from {}. Behavioral analysis history: {:?}", self.state_file, self.state.alert_history);
        Ok(())
    }

    // Saves the current state to the configured state file.
    fn save(&self) -> Result<()> {
        debug!("Attempting to save state to: {}", self.state_file);
        let serialized = serde_json::to_string(&self.state)
            .context("Failed to serialize state to JSON")?;
        if let Some(parent) = Path::new(&self.state_file).parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create parent directory for state file: {:?}", parent))?;
            debug!("Ensured parent directory for state file exists: {:?}", parent);
        }
        fs::write(&self.state_file, serialized)
            .with_context(|| format!("Failed to write state to file {}", self.state_file))?;
        debug!("Successfully saved state.");
        Ok(())
    }
}


// ==============================================================================
// --- Telegram Notifications ---
// Handles sending messages to a Telegram bot.
// ==============================================================================
fn send_telegram_message(message: &str) {
    if !ENABLE_TELEGRAM {
        debug!("Telegram notifications are disabled. Skipping message: {}", message);
        return;
    }
    if TELEGRAM_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN" || TELEGRAM_CHAT_ID == "YOUR_TELEGRAM_CHAT_ID" {
        warn!("Telegram token or chat ID is not configured. Cannot send message: {}", message);
        return;
    }

    debug!("Attempting to send Telegram message.");
    let client = Client::new();
    let url = format!("https://api.telegram.org/bot{}/sendMessage", TELEGRAM_TOKEN);
    let params = [
        ("chat_id", TELEGRAM_CHAT_ID),
        ("text", &format!("[Fortigate-Forwarder]\n{}", message)),
        ("parse_mode", "Markdown") // Allows basic formatting in Telegram messages.
    ];
    if let Err(e) = client.post(&url).form(&params).send() {
        error!("Failed to send Telegram message: {}. Check token, chat ID, and network connectivity.", e);
    } else {
        debug!("Telegram message sent successfully.");
    }
}


// ==============================================================================
// --- Threat Hunting & Enrichment ---
// Functions to extract Indicators of Compromise (IOCs) and enrich logs.
// ==============================================================================

// Extracts common IOCs (IPs, domains, hashes, URLs) from all string fields in a JSON log.
fn extract_iocs(log_data: &Value) -> HashMap<&'static str, Vec<String>> {
    debug!("Extracting IOCs from log data.");
    let mut iocs = HashMap::new();
    
    // Helper closure to collect matches from a string
    let mut collect_matches = |s: &str| {
        iocs.entry("ip").or_insert_with(Vec::new).extend(IP_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
        iocs.entry("domain").or_insert_with(Vec::new).extend(DOMAIN_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
        iocs.entry("hash").or_insert_with(Vec::new).extend(HASH_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
        iocs.entry("url").or_insert_with(Vec::new).extend(URL_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
    };

    // Recursively traverse the JSON value to find all string fields.
    // This is now a closure that can capture `collect_matches` and `iocs` indirectly.
    let find_in_value_recursive_and_collect = |value: &Value, f: &mut dyn FnMut(&str)| {
        fn inner(value: &Value, f: &mut dyn FnMut(&str)) {
            match value {
                Value::Object(map) => {
                    for (_, val) in map {
                        inner(val, f);
                    }
                }
                Value::Array(arr) => {
                    for val in arr {
                        inner(val, f);
                    }
                }
                Value::String(s) => {
                    f(s);
                }
                _ => {} // Do nothing for other types (Number, Bool, Null).
            }
        }
        inner(value, f);
    };

    find_in_value_recursive_and_collect(log_data, &mut collect_matches);
    debug!("Extracted IOCs: {:?}", iocs);
    iocs
}

// Main function for enriching and analyzing a single Fortigate log.
fn enrich_and_analyze_log(log_data: &mut Value, intel: &ThreatIntel, state: &mut AlertHistory) {
    debug!("Starting enrichment and analysis for log.");
    let iocs = extract_iocs(log_data); // Extract IOCs from the current log.
    let mut enrichment_data = json!({}); // Accumulates all enrichment findings.
    let mut found_enrichment = false; // Flag to track if any enrichment occurred.

    // --- 1. Threat Intelligence IOC Matching ---
    let mut ioc_matches = json!({}); // Stores specific IOC matches.
    let mut found_ioc_match = false; // Flag for IOC matches.
    
    // IP Reputation Check: Checks extracted IPs against the malicious IP database.
    if let Some(ips) = iocs.get("ip") {
        let mut malicious_ip_hits = Vec::new();
        for ip in ips {
            if let Some(sources) = intel.malicious_ips.get(ip) {
                info!("Threat Intel Match: Malicious IP '{}' detected from feeds: {:?}", ip, sources);
                malicious_ip_hits.push(json!({
                    "ip": ip, "status": "blocklisted", "sources": sources, "source_count": sources.len()
                }));
            } else {
                debug!("IP '{}' not found in malicious IP feeds.", ip);
            }
        }
        if !malicious_ip_hits.is_empty() {
            ioc_matches["malicious_ips"] = Value::Array(malicious_ip_hits);
            found_ioc_match = true;
        } else {
            debug!("No IP addresses extracted for IOC check.");
        }
    }

    // Domain, Hash, and URL checks: Checks extracted domains, hashes, and URLs against their respective databases.
    if let Some(domains) = iocs.get("domain") {
        let hits: Vec<_> = domains.iter().filter(|d| intel.malicious_domains.contains(*d)).collect();
        if !hits.is_empty() { 
            info!("Threat Intel Match: Malicious domain(s) detected: {:?}", hits);
            ioc_matches["malicious_domains"] = json!(hits); 
            found_ioc_match = true; 
        } else {
            debug!("No malicious domains found among extracted domains: {:?}", domains);
        }
    }
    if let Some(hashes) = iocs.get("hash") {
        let hits: Vec<_> = hashes.iter().filter(|h| intel.malicious_hashes.contains(*h)).collect();
        if !hits.is_empty() { 
            info!("Threat Intel Match: Malicious hash(es) detected: {:?}", hits);
            ioc_matches["malicious_hashes"] = json!(hits); 
            found_ioc_match = true; 
        } else {
            debug!("No malicious hashes found among extracted hashes: {:?}", hashes);
        }
    }
    if let Some(urls) = iocs.get("url") {
        let hits: Vec<_> = urls.iter().filter(|u| intel.malicious_urls.contains(*u)).collect();
        if !hits.is_empty() { 
            info!("Threat Intel Match: Malicious URL(s) detected: {:?}", hits);
            ioc_matches["malicious_urls"] = json!(hits); 
            found_ioc_match = true; 
        } else {
            debug!("No malicious URLs found among extracted URLs: {:?}", urls);
        }
    }
    
    if found_ioc_match { 
        enrichment_data["ioc_matches"] = ioc_matches; 
        found_enrichment = true; 
        debug!("IOC matches added to enrichment data.");
    } else {
        debug!("No IOC matches found for this log.");
    }

    // --- 2. Other Threat Hunting Detections ---
    let mut hunt_detections = json!({}); // Stores custom threat hunting findings.
    let mut found_hunt_detection = false; // Flag for custom hunt detections.

    // Suspicious Patterns: Looks for specific regex patterns within any string field.
    let mut suspicious_patterns_found = Vec::new();

    // Now a closure, capturing `intel` from the outer scope
    let check_suspicious_patterns = |value: &Value, path: String, f: &mut dyn FnMut(&str, &str, &str)| {
        fn inner(value: &Value, path: String, intel_patterns: &HashMap<String, String>, f: &mut dyn FnMut(&str, &str, &str)) {
            match value {
                Value::Object(map) => {
                    for (key, val) in map {
                        let new_path = if path.is_empty() { key.clone() } else { format!("{}.{}", path, key) };
                        inner(val, new_path, intel_patterns, f);
                    }
                }
                Value::Array(arr) => {
                    for (index, val) in arr.iter().enumerate() {
                        let new_path = format!("{}[{}]", path, index);
                        inner(val, new_path, intel_patterns, f);
                    }
                }
                Value::String(s) => {
                    for (name, pattern) in intel_patterns { // Access intel_patterns via argument
                        // Optimization: For a large number of suspicious_patterns,
                        // compiling them once into a lazy_static! would be more efficient,
                        // similar to CORRELATION_RULES_COMPILED.
                        // For now, given it's a small hardcoded map, we keep it as is.
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(s) {
                                f(name, &path, s);
                            }
                        } else {
                            error!("Failed to compile regex pattern: {}", pattern);
                        }
                    }
                }
                _ => {}
            }
        }
        inner(value, path, &intel.suspicious_patterns, f); // Pass intel.suspicious_patterns
    };
    
    let mut collect_suspicious = |name: &str, path: &str, s: &str| {
        warn!("Threat Hunt: Suspicious pattern '{}' found in field '{}'. Sample: '{}'.", name, path, s.chars().take(100).collect::<String>());
        suspicious_patterns_found.push(json!({"pattern": name, "field_path": path, "sample": s.chars().take(100).collect::<String>()}));
        found_hunt_detection = true;
    };
    check_suspicious_patterns(log_data, String::new(), &mut collect_suspicious);

    if !suspicious_patterns_found.is_empty() { 
        hunt_detections["suspicious_patterns"] = Value::Array(suspicious_patterns_found); 
        found_hunt_detection = true; 
        debug!("Suspicious patterns added to threat hunting data.");
    } else {
        debug!("No suspicious patterns found in log.");
    }

    // Suspicious Processes: Checks for known suspicious process names in relevant Fortigate log fields.
    if let Some(cmd) = log_data.get("msg").or_else(|| log_data.get("eventdescription")).and_then(Value::as_str) {
        debug!("Checking for suspicious processes in command/message: {}", cmd);
        let lower_cmd = cmd.to_lowercase(); // Convert once
        for process in SUSPICIOUS_PROCESSES.iter() {
            if lower_cmd.contains(process) { 
                warn!("Threat Hunt: Suspicious process keyword '{}' detected in log.", process);
                hunt_detections["suspicious_process"] = json!(process); 
                found_hunt_detection = true; 
                break; // Only need to find one match.
            }
        }
    } else {
        debug!("No command line or event description field found for suspicious process check.");
    }

    // Critical Asset Access: Checks for keywords indicating access to predefined critical assets.
    if let Some(desc) = log_data.get("msg").or_else(|| log_data.get("logdesc")).and_then(Value::as_str) {
        debug!("Checking for critical asset access in message/log description: {}", desc);
        let lower_desc = desc.to_lowercase(); // Convert once
        for asset in CRITICAL_ASSETS.iter() {
            if lower_desc.contains(asset) { 
                warn!("Threat Hunt: Critical asset access keyword '{}' detected in log.", asset);
                hunt_detections["critical_asset_access"] = json!(asset); 
                found_hunt_detection = true; 
                break; 
            }
        }
    } else {
        debug!("No message or log description field found for critical asset access check.");
    }
    
    // Correlation Rules: Applies custom correlation rules (simple regex matches) to log descriptions.
    if let Some(desc) = log_data.get("msg").or_else(|| log_data.get("logdesc")).and_then(Value::as_str) {
        debug!("Checking correlation rules against message/log description: {}", desc);
        let mut matches = Vec::new();
        for (name, re) in CORRELATION_RULES_COMPILED.iter() { // Use pre-compiled regexes
            if re.is_match(desc) { 
                info!("Threat Hunt: Correlation rule '{}' matched with pattern '{}'.", name, re.as_str());
                matches.push(json!({ "rule": name, "pattern": re.as_str() })); 
            }
        }
        if !matches.is_empty() { 
            hunt_detections["correlation_rules"] = Value::Array(matches); 
            found_hunt_detection = true; 
            debug!("Correlation rule matches added to threat hunting data.");
        }
    } else {
        debug!("No message or log description field found for correlation rules check.");
    }

    if found_hunt_detection { 
        enrichment_data["threat_hunting"] = hunt_detections; 
        found_enrichment = true; 
        debug!("Threat hunting detections added to enrichment data.");
    } else {
        debug!("No custom threat hunting detections found for this log.");
    }

    // --- 3. Behavioral Analysis ---
    if ENABLE_BEHAVIORAL_ANALYSIS {
        debug!("Performing behavioral analysis.");
        // Update the state with the current log's details *before* checking for anomalies
        // for this log, so that this log contributes to the history for *future* anomaly checks.
        state.update(log_data); 
        if let Some(anomalies) = state.is_suspicious_activity(log_data) {
            warn!("Behavioral anomalies detected: {:?}", anomalies);
            enrichment_data["behavioral_anomalies"] = anomalies;
            found_enrichment = true;
            debug!("Behavioral anomalies added to enrichment data.");
        } else {
            debug!("No behavioral anomalies detected for this log.");
        }
    } else {
        info!("Behavioral analysis is disabled by configuration.");
    }
    
    // Add all aggregated enrichment data to the original log data under a specific key.
    if found_enrichment {
        if let Some(obj) = log_data.as_object_mut() {
            // Add the last update time of the intel feeds for context.
            enrichment_data["intel_last_updated"] = json!(intel.last_updated.to_rfc3339());
            obj.insert("forwarder_enrichment".to_string(), enrichment_data);
            info!("Log successfully enriched with forwarder_enrichment data.");
        } else {
            warn!("Could not add enrichment data: Log data is not a JSON object.");
        }
    } else {
        debug!("Log not enriched, no matches or anomalies found.");
    }
}


// ==============================================================================
// --- Threat Intelligence Feed Management ---
// Functions for downloading, caching, and managing threat intelligence feeds.
// ==============================================================================

// Generates a unique filename for a cached feed based on its URL (using SHA256 hash).
fn get_cache_filepath(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    let filepath = format!("{}/{:x}.json", THREAT_INTEL_CACHE_DIR, result);
    debug!("Generated cache filepath for URL '{}': {}", url, filepath);
    filepath
}

// Checks if a cached feed file is still valid (not expired based on refresh interval).
fn is_cache_valid(filepath: &str) -> bool {
    debug!("Checking cache validity for: {}", filepath);
    if let Ok(metadata) = fs::metadata(filepath) {
        if let Ok(last_modified) = metadata.modified() {
            let elapsed = last_modified.elapsed().unwrap_or(Duration::MAX);
            let is_valid = elapsed < Duration::from_secs(THREAT_INTEL_REFRESH_INTERVAL_SECS);
            if is_valid {
                debug!("Cache for {} is still valid ({}s old, expires in {}s).", filepath, elapsed.as_secs(), THREAT_INTEL_REFRESH_INTERVAL_SECS - elapsed.as_secs());
            } else {
                info!("Cache for {} is expired ({}s old).", filepath, elapsed.as_secs());
            }
            return is_valid;
        } else {
            warn!("Could not get last modified time for cache file: {}", filepath);
        }
    } else {
        info!("Cache file does not exist: {}", filepath);
    }
    false // Cache is not valid if file doesn't exist or modified time is unavailable/expired.
}

// Downloads a threat intelligence feed from a given URL and caches it.
fn download_feed(url: &str) -> Result<HashSet<String>> {
    let cache_filepath = get_cache_filepath(url);
    if is_cache_valid(&cache_filepath) {
        info!("Using cached feed for {}.", url);
        let file = File::open(&cache_filepath)
            .with_context(|| format!("Failed to open cached feed file: {}", cache_filepath))?;
        let items: HashSet<String> = serde_json::from_reader(file)
            .with_context(|| format!("Failed to parse cached feed from {}. It might be corrupted.", cache_filepath))?;
        debug!("Loaded {} items from cache for {}.", items.len(), url);
        return Ok(items);
    }

    info!("Downloading new feed from {}.", url);
    let client = Client::new();
    let response = client.get(url).timeout(Duration::from_secs(30)).send()
        .with_context(|| format!("Failed to send HTTP request to {}", url))?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP error {} for {}", response.status(), url));
    }

    let text = response.text()
        .with_context(|| format!("Failed to get response body from {}", url))?;
    let items: HashSet<String> = text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with(&['#', ';', '/']) && !line.is_empty()) // Filter out comments and empty lines.
        .map(|s| s.to_string())
        .collect();

    if let Some(parent) = Path::new(&cache_filepath).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory for cache file: {:?}", parent))?;
        debug!("Ensured parent directory for cache file exists: {:?}", parent);
    }
    let file = File::create(&cache_filepath)
        .with_context(|| format!("Failed to create cache file: {}", cache_filepath))?;
    serde_json::to_writer(file, &items)
        .with_context(|| format!("Failed to write feed data to cache file: {}", cache_filepath))?;
    info!("Successfully downloaded and cached {} items from {}.", items.len(), url);
    Ok(items)
}

// Checks if an IP address is a public IP (i.e., not private, loopback, etc.).
fn is_public_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        let is_public = !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_documentation();
        debug!("Checking IP '{}': is_private={}, is_loopback={}, is_unspecified={}, is_multicast={}, is_documentation={}, result={}",
               ip_str, ip.is_private(), ip.is_loopback(), ip.is_unspecified(), ip.is_multicast(), ip.is_documentation(), is_public);
        is_public
    } else {
        debug!("IP '{}' is not a valid Ipv4Addr.", ip_str);
        false
    }
}

// This thread is responsible for periodically updating the threat intelligence databases.
fn threat_intel_updater_thread(intel_db: Arc<Mutex<ThreatIntel>>, shutdown: Arc<AtomicBool>) {
    info!("Threat intelligence updater thread started. Will refresh every {} seconds.", THREAT_INTEL_REFRESH_INTERVAL_SECS);
    // Initial sleep to allow other components to start up, and prevent immediate burst of downloads.
    thread::sleep(Duration::from_secs(5));

    while !shutdown.load(Ordering::Relaxed) {
        info!("Initiating threat intelligence database update cycle.");
        send_telegram_message("⏳ Starting threat intelligence database update...");

        let mut new_intel = ThreatIntel::new(); // Create a new intel object to build up.

        // --- Fetch Malicious IPs ---
        info!("Fetching malicious IP feeds...");
        let mut all_ips: HashMap<String, Vec<String>> = HashMap::new();
        for url in IP_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => {
                    info!("Successfully downloaded {} IPs from {}.", items.len(), url);
                    for ip in items {
                        if is_public_ip(&ip) { 
                            all_ips.entry(ip).or_default().push(url.to_string()); 
                        } else {
                            debug!("Skipping private/special IP from feed '{}': {}", url, ip);
                        }
                    }
                },
                Err(e) => error!("Failed to download IP feed {}: {}", url, e),
            }
        }
        new_intel.malicious_ips = all_ips;
        info!("Completed IP feed fetching. Loaded {} unique public malicious IPs.", new_intel.malicious_ips.len());

        // --- Fetch Malicious URLs ---
        info!("Fetching malicious URL feeds...");
        let mut all_urls = HashSet::new();
        for url in URL_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => {
                    info!("Successfully downloaded {} URLs from {}.", items.len(), url);
                    all_urls.extend(items)
                },
                Err(e) => error!("Failed to download URL feed {}: {}", url, e),
            }
        }
        new_intel.malicious_urls = all_urls;
        info!("Completed URL feed fetching. Loaded {} malicious URLs.", new_intel.malicious_urls.len());
        
        // --- Fetch Malicious Hashes ---
        info!("Fetching malicious Hash feeds...");
        for url in HASH_FEED_URLS.iter() { // Corrected: HASH_FEED_URLS (was HASH_FEED_URLs)
            match download_feed(url) {
                Ok(items) => {
                    info!("Successfully downloaded {} Hashes from {}.", items.len(), url);
                    new_intel.malicious_hashes.extend(items)
                },
                Err(e) => error!("Failed to download hash feed {}: {}", url, e),
            }
        }
        info!("Completed Hash feed fetching. Loaded {} malicious hashes.", new_intel.malicious_hashes.len());

        // --- Fetch Malicious Domains ---
        info!("Fetching malicious Domain feeds...");
        let mut all_domains = HashSet::new();
        for url in DOMAIN_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => {
                    info!("Successfully downloaded {} Domains from {}.", items.len(), url);
                    all_domains.extend(items)
                },
                Err(e) => error!("Failed to download domain feed {}: {}", url, e),
            }
        }
        new_intel.malicious_domains = all_domains;
        info!("Completed Domain feed fetching. Loaded {} malicious domains.", new_intel.malicious_domains.len());

        new_intel.last_updated = Utc::now();
        let total_indicators = new_intel.indicator_count();
        
        // Acquire a lock on the shared threat intelligence database and update it.
        info!("Acquiring lock on shared threat intelligence database for update.");
        *intel_db.lock().unwrap() = new_intel;
        info!("Threat intelligence databases updated. Total indicators: {}", total_indicators);
        send_telegram_message(&format!("✅ Threat intelligence databases updated. Total indicators loaded: {}.", total_indicators));

        // Sleep until next refresh, but check shutdown flag every second.
        debug!("Threat intelligence updater sleeping for {} seconds until next refresh.", THREAT_INTEL_REFRESH_INTERVAL_SECS);
        for _ in 0..THREAT_INTEL_REFRESH_INTERVAL_SECS {
            if shutdown.load(Ordering::Relaxed) { 
                info!("Threat intel updater received shutdown signal during sleep.");
                break; 
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
    info!("Threat intelligence updater thread shutting down gracefully.");
}

// ==============================================================================
// --- Fortigate Syslog Parser ---
// This function parses a raw Fortigate Syslog string into a structured JSON object.
// It's designed to be robust but may need further refinement for edge cases
// or highly complex Fortigate log variations.
// ==============================================================================
fn parse_fortigate_log_to_json(raw_log: &str) -> Result<Value> {
    debug!("Attempting to parse raw Fortigate log: '{}'", raw_log);
    let mut json_map = HashMap::new();

    // 1. Basic Syslog header parsing (e.g., "<PRI>MESSAGE").
    let log_content_start_idx;
    if let Some(angle_bracket_end) = raw_log.find('>') {
        debug!("Syslog priority header found at index {}.", angle_bracket_end);
        if let Some(priority_str) = raw_log.get(1..angle_bracket_end) {
            if let Ok(priority) = priority_str.parse::<u8>() {
                json_map.insert("syslog_priority".to_string(), Value::Number(priority.into()));
                let facility = priority / 8;
                let severity = priority % 8;
                json_map.insert("syslog_facility".to_string(), Value::Number(facility.into()));
                json_map.insert("syslog_severity".to_string(), Value::Number(severity.into()));
                debug!("Parsed Syslog priority: {}, facility: {}, severity: {}", priority, facility, severity);
            } else {
                warn!("Failed to parse syslog priority string '{}'.", priority_str);
            }
        } else {
            warn!("Could not extract priority string from syslog header.");
        }
        log_content_start_idx = angle_bracket_end + 1; // Content starts after '>'
    } else {
        info!("No Syslog priority header found. Assuming full log is content.");
        log_content_start_idx = 0; // Content starts from the beginning.
    }
    let log_content = &raw_log[log_content_start_idx..];
    debug!("Log content for KV parsing: '{}'", log_content);

    // 2. Parse key=value pairs from the extracted log content.
    for cap in FORTIGATE_KV_REGEX.captures_iter(log_content) {
        let key = cap.get(1).map_or("", |m| m.as_str()).to_string(); // Get the key name.
        
        let value_cow: Cow<'_, str> = if let Some(quoted_match) = cap.get(3) {
            // Quoted value, unescape it
            let unescaped = quoted_match.as_str().replace("\\\"", "\""); // Basic unescaping
            Cow::Owned(unescaped)
        } else if let Some(unquoted_match) = cap.get(4) {
            // Unquoted value, use directly
            Cow::Borrowed(unquoted_match.as_str())
        } else {
            // Should not happen given regex structure, but handle defensively
            Cow::Borrowed("")
        };

        let value_str = value_cow.as_ref();
        debug!("Extracted key-value pair: key='{}', value_str='{}'", key, value_str);

        // Attempt to parse known numeric fields to actual numbers in JSON.
        // If parsing fails, store as a string.
        let parsed_value = match key.as_str() {
            // Fields typically expected to be strings.
            "date" | "time" | "devname" | "devid" | "tz" | "type" | "subtype" | "eventtype" | "level" | "vd" |
            "srccountry" | "dstcountry" | "srcintf" | "srcintfrole" | "dstintf" | "dstintfrole" |
            "proto" | "service" | "direction" | "policytype" | "applist" | "action" | "appcat" | "app" |
            "msg" | "apprisk" | "policyname" | "trandisp" | "vwlquality" | "vwlname" | "utmaction" |
            "srchwvendor" | "devtype" | "osname" | "mastersrcmac" | "srcmac" | "srcserver" |
            "dstdevtype" | "masterdstmac" | "dstmac" | "dstserver" | "hostname" | "profile" |
            "reqtype" | "url" | "method" | "catdesc" => {
                debug!("Key '{}' identified as string type.", key);
                Value::String(value_str.to_string())
            },
            // Fields typically expected to be numbers (integers or floats).
            "eventtime" | "logid" | "appid" | "srcport" | "dstport" | "policyid" | "sessionid" |
            "incidentserialno" | "sentbyte" | "rcvdbyte" | "duration" | "sentpkt" | "rcvdpkt" |
            "countapp" | "cat" => {
                if let Ok(num) = value_str.parse::<i64>() {
                    debug!("Key '{}' parsed as integer: {}", key, num);
                    Value::Number(num.into())
                } else if let Ok(num) = value_str.parse::<f64>() {
                    debug!("Key '{}' parsed as float: {}", key, num);
                    Value::Number(serde_json::Number::from_f64(num).unwrap_or_else(|| 0.into()))
                } else {
                    warn!("Key '{}' expected to be numeric, but parsing failed. Storing as string: '{}'", key, value_str);
                    Value::String(value_str.to_string()) // Fallback to string if numeric parsing fails.
                }
            },
            // Fields for IP addresses, typically stored as strings.
            "srcip" | "dstip" | "transip" => {
                debug!("Key '{}' identified as IP address string.", key);
                Value::String(value_str.to_string())
            },
            // Default case: if key is not specifically matched, store as string.
            _ => {
                debug!("Key '{}' not explicitly handled. Storing as string: '{}'", key, value_str);
                Value::String(value_str.to_string())
            },
        };
        json_map.insert(key, parsed_value); // Insert the parsed key-value pair into the map.
    }

    // Add original raw log for debugging/completeness in the final JSON.
    json_map.insert("fortigate_raw_log".to_string(), Value::String(raw_log.to_string()));
    
    // Add current timestamp for ingestion into ELK.
    json_map.insert("@timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));

    debug!("Finished parsing log. Resulting JSON: {:?}", json_map);
    Ok(Value::Object(json_map.into_iter().collect())) // Return the constructed JSON object as a Result.
}


// ==============================================================================
// --- Syslog Receiver Thread ---
// This thread binds to a UDP port and listens for incoming Fortigate Syslog messages.
// It then forwards a raw copy to Wazuh and sends a parsed/enriched JSON copy to ELK.
// ==============================================================================
fn syslog_receiver_thread(
    state_manager: Arc<Mutex<StateManager>>,     // Shared StateManager for behavioral history.
    elk_sender: Sender<String>,                  // Channel to send processed JSON logs to the ELK sender thread.
    threat_intel_db: Arc<Mutex<ThreatIntel>>,    // Shared Threat Intelligence database.
    shutdown: Arc<AtomicBool>,                   // Atomic flag for graceful shutdown.
) -> Result<()> {
    info!("Syslog receiver thread starting. Will bind to UDP port {}.", FORTIGATE_SYSLOG_PORT);
    let bind_addr = format!("0.0.0.0:{}", FORTIGATE_SYSLOG_PORT);
    let socket = UdpSocket::bind(&bind_addr)
        .with_context(|| format!("Failed to bind UDP socket to {}. This likely means another process (like Wazuh) is already listening on this port. Please reconfigure Wazuh to listen on a different port (e.g., 1514) and ensure this application is the only one on {}.", bind_addr, FORTIGATE_SYSLOG_PORT))?;
    
    // Set a read timeout to prevent blocking indefinitely, allowing the thread to check the shutdown flag.
    socket.set_read_timeout(Some(Duration::from_secs(1)))
        .context("Failed to set read timeout on UDP socket")?;
    info!("Successfully bound UDP socket to {}.", bind_addr);

    // Prepare the UDP socket for forwarding raw logs to Wazuh
    let wazuh_syslog_addr: SocketAddr = format!("{}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT).parse()
        .with_context(|| format!("Failed to parse Wazuh local syslog address: {}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT))?;
    let wazuh_forward_socket = UdpSocket::bind("0.0.0.0:0") // Bind to any available local port
        .context("Failed to bind UDP socket for Wazuh forwarding")?;
    info!("Wazuh raw log forwarding configured to {}.", wazuh_syslog_addr);

    let mut buf = [0; 2048]; // Buffer for incoming UDP packets. Standard Syslog messages are usually <= 1024 bytes.

    while !shutdown.load(Ordering::Relaxed) {
        debug!("Syslog receiver: Waiting for incoming UDP packets.");
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let raw_log_bytes = &buf[..len];
                let raw_log = String::from_utf8_lossy(raw_log_bytes).trim().to_string();
                if raw_log.is_empty() {
                    debug!("Received empty UDP packet from {}. Skipping.", src_addr);
                    continue;
                }
                info!("Received raw Fortigate log ({} bytes) from {}.", len, src_addr);
                debug!("Raw log content: '{}'", raw_log);

                // --- FORWARD RAW LOG TO WAZUH ---
                debug!("Attempting to forward raw log to Wazuh at {}.", wazuh_syslog_addr);
                if let Err(e) = wazuh_forward_socket.send_to(raw_log_bytes, wazuh_syslog_addr) {
                    error!("Failed to forward raw log to Wazuh at {}: {}. Raw log: '{}'", wazuh_syslog_addr, e, raw_log);
                } else {
                    debug!("Successfully forwarded raw log to Wazuh at {}.", wazuh_syslog_addr);
                }

                // --- PROCESS FOR ELK (Parse, Enrich, Send) ---
                match parse_fortigate_log_to_json(&raw_log) {
                    Ok(mut log_json) => {
                        debug!("Successfully parsed raw log to JSON for ELK.");
                        // Acquire locks for shared resources.
                        // IMPORTANT: Acquire locks only when needed and release quickly.
                        // Holding a lock across complex operations like network calls or extensive parsing
                        // can severely bottleneck performance.
                        let intel = threat_intel_db.lock().unwrap(); // Lock for read access to threat intel.
                        let mut state = state_manager.lock().unwrap(); // Lock for mutable access to state manager.

                        // Perform enrichment and behavioral analysis on the parsed log.
                        enrich_and_analyze_log(&mut log_json, &intel, &mut state.state.alert_history);
                        
                        // Save the updated state. This should be done frequently for behavioral analysis.
                        if let Err(e) = state.save() {
                            error!("Failed to save behavioral analysis state after processing log: {}", e);
                        }
                        // Explicitly drop locks to release them as soon as possible.
                        drop(state); 
                        drop(intel);

                        let enriched_line = serde_json::to_string(&log_json)
                            .context("Failed to serialize enriched log to JSON string")?;
                        
                        // Send the enriched JSON string to the ELK sender thread.
                        debug!("Sending enriched log to ELK sender channel. Queue size: {}", elk_sender.len());
                        if elk_sender.send(enriched_line).is_err() {
                            warn!("Channel to ELK sender disconnected. Initiating shutdown of syslog receiver thread.");
                            break; // Exit loop if sender channel is closed.
                        }
                    },
                    Err(e) => {
                        warn!("Failed to parse Fortigate log from {}: '{}'. Error: {}", src_addr, raw_log, e);
                    }
                }
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                // No data received within the timeout. This is expected and allows checking the shutdown flag.
                debug!("Syslog receiver: No data within timeout, re-checking shutdown flag.");
                continue;
            },
            Err(e) => {
                error!("Critical error receiving UDP packet: {}. Waiting 5 seconds before retrying.", e);
                thread::sleep(Duration::from_secs(5)); // Wait a bit before retrying on other errors.
            }
        }
    }

    info!("Syslog receiver thread received shutdown signal. Exiting loop.");
    Ok(())
}


// ==============================================================================
// --- ELK Sender Thread ---
// This thread connects to the ELK (Logstash) server and sends processed JSON logs.
// It handles reconnection logic and sends periodic heartbeats.
// ==============================================================================
fn elk_sender_thread(receiver: Receiver<String>, shutdown: Arc<AtomicBool>) -> Result<()> {
    info!("ELK sender thread started.");
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT).parse()
        .with_context(|| format!("Failed to parse ELK host:port address: {}:{}", ELK_HOST, ELK_PORT))?;
    
    let mut retry_delay = 5; // Initial reconnection delay in seconds.
    let mut last_heartbeat = Instant::now(); // Tracks time for sending heartbeats.
    let mut logs_processed_since_heartbeat = 0; // Counts logs for heartbeat message.
    let mut stream: Option<TcpStream> = None; // The TCP stream to Logstash.
    let mut batch_buffer: Vec<String> = Vec::with_capacity(ELK_BATCH_SIZE); // Buffer for batching logs
    let mut last_batch_flush = Instant::now();

    // Attempt initial connection to ELK.
    debug!("ELK sender: Attempting initial connection to {}.", addr);
    match TcpStream::connect_timeout(&addr, Duration::from_secs(SOCKET_TIMEOUT)) {
        Ok(s) => { 
            s.set_write_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT)))
                .context("Failed to set write timeout on ELK TCP stream")?;
            s.set_read_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT)))
                .context("Failed to set read timeout on ELK TCP stream")?;
            info!("ELK sender: Successfully connected to ELK at {}.", addr);
            send_telegram_message(&format!("✅ *Connection Established:* Successfully connected to ELK server at {}:{}.", ELK_HOST, ELK_PORT));
            stream = Some(s);
        }
        Err(e) => {
            error!("ELK sender: Initial connection to ELK failed: {}. Will retry as logs arrive.", e);
            send_telegram_message(&format!("🚨 *Initial ELK Connection Failed:* {}. Check firewall/connectivity.", e));
        }
    };

    // Helper function to send the current batch
    let send_batch = |stream: &mut TcpStream, buffer: &mut Vec<String>, logs_processed_count: &mut u64| -> Result<()> { 
        if buffer.is_empty() {
            return Ok(());
        }
        let payload = buffer.join("\n") + "\n"; // Join with newline and add final newline
        debug!("ELK sender: Sending batch of {} logs ({} bytes) to ELK.", buffer.len(), payload.len());
        stream.write_all(payload.as_bytes())?;
        *logs_processed_count += buffer.len() as u64;
        buffer.clear();
        Ok(())
    };

    while !shutdown.load(Ordering::Relaxed) || !receiver.is_empty() || !batch_buffer.is_empty() {
        // Send a heartbeat message periodically.
        if last_heartbeat.elapsed().as_secs() >= HEARTBEAT_INTERVAL {
            let message = format!("❤️ *Heartbeat:* Service is alive. {} logs forwarded since last heartbeat. Queue size: {}. Batch buffer: {}.", 
                                  logs_processed_since_heartbeat, receiver.len(), batch_buffer.len());
            send_telegram_message(&message);
            info!("{}", message);
            logs_processed_since_heartbeat = 0; // Reset counter.
            last_heartbeat = Instant::now(); // Reset timer.
        }

        // Try to receive a log from the channel or flush batch if timeout reached
        let recv_timeout = if batch_buffer.is_empty() {
            Duration::from_secs(1) // Wait longer if no logs in buffer
        } else {
            // Wait up to ELK_BATCH_FLUSH_INTERVAL_SECS, but no longer than needed to fill batch
            let remaining_time = Duration::from_secs(ELK_BATCH_FLUSH_INTERVAL_SECS)
                .checked_sub(last_batch_flush.elapsed())
                .unwrap_or(Duration::ZERO);
            remaining_time.min(Duration::from_millis(100)) // Poll more frequently for batching
        };

        match receiver.recv_timeout(recv_timeout) {
            Ok(message) => {
                debug!("ELK sender: Received log from channel. Queue size remaining: {}", receiver.len());
                batch_buffer.push(message);

                if batch_buffer.len() >= ELK_BATCH_SIZE {
                    debug!("Batch buffer full ({} logs). Flushing to ELK.", batch_buffer.len());
                    if let Some(ref mut s) = stream {
                        if let Err(e) = send_batch(s, &mut batch_buffer, &mut logs_processed_since_heartbeat) {
                            warn!("ELK sender: Failed to send batch to TCP stream: {}. Connection might be broken. Attempting to reconnect.", e);
                            stream = None; // Mark stream as broken.
                        }
                    } else {
                        debug!("ELK sender: No active connection, holding batch in buffer.");
                    }
                    last_batch_flush = Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // No messages in the queue for the timeout duration.
                // Check if it's time to flush partial batch.
                if !batch_buffer.is_empty() && last_batch_flush.elapsed().as_secs() >= ELK_BATCH_FLUSH_INTERVAL_SECS {
                    debug!("ELK sender: Flushing partial batch ({} logs) due to timeout.", batch_buffer.len());
                    if let Some(ref mut s) = stream {
                        if let Err(e) = send_batch(s, &mut batch_buffer, &mut logs_processed_since_heartbeat) {
                            warn!("ELK sender: Failed to send partial batch to TCP stream: {}. Connection might be broken. Attempting to reconnect.", e);
                            stream = None; // Mark stream as broken.
                        }
                    } else {
                        debug!("ELK sender: No active connection, holding partial batch in buffer.");
                    }
                    last_batch_flush = Instant::now();
                }
                debug!("ELK sender: No data in queue for timeout. Checking shutdown status.");
                continue; // Continue looping to check shutdown flag.
            }
            Err(e) => {
                // The channel has disconnected (e.g., sender thread terminated).
                info!("ELK sender: Channel to receiver disconnected: {}. Exiting thread loop.", e);
                break;
            }
        }

        // Reconnection logic if stream.is_none()
        if stream.is_none() {
            warn!("ELK sender: Not connected. Waiting {}s before next reconnection attempt.", retry_delay);
            send_telegram_message(&format!("⚠️ *ELK Connection Lost:* Retrying in {}s. Queue size: {}. Batch buffer: {}.", retry_delay, receiver.len(), batch_buffer.len()));
            thread::sleep(Duration::from_secs(retry_delay)); // Wait before retrying.

            debug!("ELK sender: Attempting to reconnect to ELK at {}.", addr);
            match TcpStream::connect_timeout(&addr, Duration::from_secs(SOCKET_TIMEOUT)) {
                Ok(s) => { 
                    s.set_write_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT)))
                        .context("Failed to set write timeout on ELK TCP stream during reconnection")?;
                    s.set_read_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT)))
                        .context("Failed to set read timeout on ELK TCP stream during reconnection")?;
                    info!("ELK sender: Successfully reconnected to ELK.");
                    send_telegram_message(&format!("✅ *Reconnected:* Successfully reconnected to ELK."));
                    stream = Some(s); // Set new stream.
                    retry_delay = 5; // Reset delay.
                }
                Err(e) => {
                    error!("ELK sender: Reconnection to ELK failed: {}. Next retry in {}s.", e, std::cmp::min(retry_delay * 2, 60));
                    retry_delay = std::cmp::min(retry_delay * 2, 60); // Exponential backoff, max 60s.
                }
            }
        }
    }

    // Attempt to flush any remaining logs in the buffer before shutting down
    if !batch_buffer.is_empty() {
        info!("ELK sender: Flushing remaining {} logs in buffer before shutting down.", batch_buffer.len());
        if let Some(ref mut s) = stream {
            if let Err(e) = send_batch(s, &mut batch_buffer, &mut logs_processed_since_heartbeat) {
                error!("ELK sender: Failed to flush final batch: {}", e);
            }
        } else {
            warn!("ELK sender: No active ELK connection to flush remaining logs.");
        }
    }

    info!("ELK sender thread received shutdown signal or queue is empty. Flushing remaining logs and shutting down.");
    // Small final delay to ensure any last-moment writes complete.
    thread::sleep(Duration::from_millis(100)); 
    info!("ELK sender thread shut down gracefully.");
    Ok(())
}


// ==============================================================================
// --- Initial Connection Test ---
// Performs a quick test to ensure the ELK server is reachable at startup.
// ==============================================================================
fn test_initial_connection() -> Result<()> {
    info!("Performing initial connection test to ELK at {}:{}...", ELK_HOST, ELK_PORT);
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT).parse()
        .with_context(|| format!("Failed to parse ELK address for initial connection test: {}:{}", ELK_HOST, ELK_PORT))?;
    
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_) => {
            info!("✅ Initial ELK connection test successful. ELK is reachable.");
            Ok(())
        }
        Err(e) => {
            let msg = format!("🚨 Initial ELK connection test FAILED: {}\nCheck firewall rules, ELK server status, and connectivity to {}:{}", e, ELK_HOST, ELK_PORT);
            error!("{}", msg);
            send_telegram_message(&msg); // Send critical error to Telegram.
            Err(anyhow!(msg)) // Return an error to propagate the failure.
        }
    }
}


// ==============================================================================
// --- Main Function ---
// The entry point of the Fortigate Log Forwarder application.
// Initializes logging, sets up threads, and manages graceful shutdown.
// ==============================================================================
fn main() -> Result<()> {
    // --- Logging Setup ---
    // Attempts to open the log file for appending. If it fails, logs to stdout only.
    let log_file_result = OpenOptions::new().create(true).append(true).open(LOG_FILE);
    let fern_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            // Define the log message format: Timestamp - Level - ThreadName - Message
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("main"), // Use "main" if thread name is not set.
                message
            ))
        })
        .level(LevelFilter::Debug) // Set default logging level to DEBUG for verbose output.
        .chain(io::stdout()); // Always log to standard output.
    
    match log_file_result {
        Ok(file) => {
            fern_dispatch.chain(file).apply()?; // Chain to file if successful.
            info!("Logging configured. Detailed logs will be written to {}.", LOG_FILE);
        },
        Err(e) => {
            eprintln!("Failed to open log file {}: {}. Logging will only go to stdout.", LOG_FILE, e);
            fern_dispatch.apply()?; // Apply dispatch only to stdout if file logging fails.
        }
    };

    info!("==============================================");
    info!("        Fortigate Raw Log Forwarder (Rust)    ");
    info!("==============================================");
    info!("Service starting up in Belém, State of Pará, Brazil. Current time: {}", Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
    info!("Configured to receive Fortigate logs on UDP port: {}", FORTIGATE_SYSLOG_PORT);
    info!("Configured to forward a copy of raw logs to Wazuh on {}:{}", WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT);
    info!("Configured to forward processed logs to ELK server at: {}:{}", ELK_HOST, ELK_PORT);

    // Perform an initial connection test to ELK.
    // The service can proceed even if this fails, as the sender thread has reconnection logic.
    if let Err(e) = test_initial_connection() {
        warn!("Initial ELK connection test failed. Service will attempt to reconnect as needed: {}", e);
    }

    // --- Signal Handling Setup ---
    // Create an atomic boolean to signal threads for shutdown.
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut signals = Signals::new(&[SIGINT, SIGTERM])
        .context("Failed to register signal handlers")?;
    let signal_shutdown = shutdown.clone(); // Clone for the signal handling thread.
    thread::Builder::new().name("signal_handler".to_string()).spawn(move || {
        info!("Signal handler thread started. Waiting for SIGINT or SIGTERM.");
        for sig in signals.forever() {
            warn!("Received OS signal {:?}. Initiating graceful shutdown sequence...", sig);
            signal_shutdown.store(true, Ordering::Relaxed); // Set shutdown flag.
            break; // Exit loop after first signal.
        }
        info!("Signal handler thread finished.");
    })?;

    // --- Channel for Inter-Thread Communication ---
    // Create a bounded channel to queue logs between the syslog receiver and ELK sender threads.
    let (tx, rx) = bounded(MAX_QUEUE_SIZE);
    info!("Created bounded channel with max capacity: {} logs.", MAX_QUEUE_SIZE);

    // --- State Manager Initialization ---
    // Initialize the StateManager for behavioral analysis history.
    let mut state_manager_instance = StateManager::new(STATE_FILE);
    if let Err(e) = state_manager_instance.load() { 
        error!("Failed to load previous state from {}: {}. Starting with fresh history.", STATE_FILE, e); 
    }
    let state_manager = Arc::new(Mutex::new(state_manager_instance)); // Wrap in Arc<Mutex> for shared mutable access.
    info!("State manager initialized. Behavioral analysis history will be saved to {}.", STATE_FILE);

    // --- Threat Intelligence Database Initialization ---
    // Initialize the shared ThreatIntel database.
    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    info!("Threat intelligence database initialized.");
    
    // --- Spawn Threat Intelligence Updater Thread ---
    if ENABLE_THREAT_INTEL_FEEDS {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        thread::Builder::new().name("intel_updater".to_string()).spawn(move || {
            threat_intel_updater_thread(intel_clone, shutdown_clone);
        })?;
        info!("Threat intelligence updater thread spawned.");
    } else {
        info!("Threat intelligence feed fetching is disabled by configuration. No updater thread spawned.");
    }

    // --- Spawn Syslog Receiver Thread ---
    let syslog_receiver_shutdown = shutdown.clone();
    let syslog_receiver_elk_sender_tx = tx.clone(); // Renamed for clarity
    let syslog_receiver_intel_db = threat_intel_db.clone();
    let syslog_receiver_state_manager = state_manager.clone();
    let syslog_receiver_handle = thread::Builder::new().name("syslog_receiver".to_string()).spawn(move || {
        if let Err(e) = syslog_receiver_thread(syslog_receiver_state_manager, syslog_receiver_elk_sender_tx, syslog_receiver_intel_db, syslog_receiver_shutdown) {
            error!("Syslog receiver thread encountered a critical error: {}", e);
        }
        info!("Syslog receiver thread has exited.");
    })?;
    info!("Syslog receiver thread spawned.");

    // --- Spawn ELK Sender Thread ---
    let elk_sender_shutdown = shutdown.clone();
    let elk_sender_handle = thread::Builder::new().name("elk_sender".to_string()).spawn(move || {
        if let Err(e) = elk_sender_thread(rx, elk_sender_shutdown) {
            error!("ELK sender thread encountered a critical error: {}", e);
        }
        info!("ELK sender thread has exited.");
    })?;
    info!("ELK sender thread spawned.");

    // --- Main Thread Waits for Other Threads ---
    // The main thread waits for the spawned threads to complete.
    // This will only happen when the shutdown flag is set (via signal).
    info!("Main thread waiting for syslog_receiver thread to complete.");
    syslog_receiver_handle.join().unwrap();
    info!("Main thread waiting for elk_sender thread to complete.");
    elk_sender_handle.join().unwrap();

    info!("All worker threads have finished. Service is performing final shutdown.");
    send_telegram_message("✅ *Shutdown Complete:* Fortigate Log Forwarder service stopped gracefully.");

    Ok(())
}