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
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::MetadataExt,
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
// ==============================================================================
const WAZUH_ALERTS_FILE: &str = "/var/ossec/logs/alerts/alerts.json";
const ELK_HOST: &str = "68.168.216.248";
const ELK_PORT: u16 = 5140;
const SOCKET_TIMEOUT: u64 = 10;
const LOG_FILE: &str = "/var/log/wazuh_forwarder.log";
const STATE_FILE: &str = "/var/lib/wazuh-forwarder/forwarder_state.json";
const MAX_QUEUE_SIZE: usize = 10000;
const READ_CHUNK_SIZE: usize = 65536;
const ENABLE_TELEGRAM: bool = true;
const TELEGRAM_TOKEN: &str = "YOUR_TELEGRAM_BOT_TOKEN";
const TELEGRAM_CHAT_ID: &str = "YOUR_TELEGRAM_CHAT_ID";
const HEARTBEAT_INTERVAL: u64 = 3600;
const PROCESS_FROM_BEGINNING_ON_FIRST_RUN: bool = true;

// --- Threat Intelligence Configuration ---
const ENABLE_THREAT_INTEL_FEEDS: bool = true;
const THREAT_INTEL_REFRESH_INTERVAL_SECS: u64 = 86400; // 24 hours
const THREAT_INTEL_CACHE_DIR: &str = "/var/lib/wazuh-forwarder/threat_intel_cache";

// IP Feeds (Blocklists)
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

// Malicious URL Feeds
const URL_FEED_URLS: [&str; 1] = [
    "https://urlhaus.abuse.ch/downloads/text/",
];

// Malicious Hash Feeds (e.g., SHA256)
const HASH_FEED_URLS: [&str; 1] = [
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
];

// Malicious Domain Feeds
const DOMAIN_FEED_URLS: [&str; 2] = [
    "https://www.malwaredomainlist.com/hostslist/domains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
];


// --- Threat hunting configurations ---
const ENABLE_BEHAVIORAL_ANALYSIS: bool = true;
const BEHAVIOR_WINDOW_MINUTES: i64 = 5;
const HIGH_SEVERITY_THRESHOLD: u8 = 10;
const SUSPICIOUS_PROCESSES: [&str; 15] = [
    "meterpreter", "cobaltstrike", "powershell -e", "powershell -enc",
    "certutil", "bitsadmin", "wmic", "mshta", "rundll32", "regsvr32",
    "schtasks", "psexec", "netcat", "nc", "ncat"
];
const CRITICAL_ASSETS: [&str; 5] = [
    "domain-controller", "database-server", "payment-gateway",
    "erp-system", "scada-system"
];
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

lazy_static::lazy_static! {
    static ref IP_REGEX: Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    static ref DOMAIN_REGEX: Regex = Regex::new(r"\b(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}\b").unwrap();
    static ref HASH_REGEX: Regex = Regex::new(r"\b[a-f0-9]{32,128}\b").unwrap();
    static ref URL_REGEX: Regex = Regex::new(r#"(https?://[^\s"<>]+|www\.[^\s"<>]+\.[^\s"<>]+)"#).unwrap();
}

// ==============================================================================
// --- Threat Intelligence Database ---
// ==============================================================================
#[derive(Serialize, Deserialize, Default, Clone)]
struct ThreatIntel {
    malicious_ips: HashMap<String, Vec<String>>, // IP -> list of source feed URLs
    malicious_domains: HashSet<String>,
    malicious_hashes: HashSet<String>,
    malicious_urls: HashSet<String>,
    suspicious_patterns: HashMap<String, String>,
    last_updated: DateTime<Utc>,
}

impl ThreatIntel {
    fn new() -> Self {
        let mut intel = ThreatIntel {
            last_updated: Utc::now(),
            ..Default::default()
        };

        // Suspicious patterns (regex) are hardcoded as they don't come from feeds
        // This is the corrected section
        intel.suspicious_patterns.insert(
            "obfuscated_powershell".to_string(),
            // CORRECTED: Removed unnecessary backslashes and restored the final '*'
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

        intel
    }

    fn indicator_count(&self) -> usize {
        self.malicious_ips.len()
            + self.malicious_domains.len()
            + self.malicious_hashes.len()
            + self.malicious_urls.len()
    }
}


// ==============================================================================
// --- Behavioral Analysis Engine ---
// ==============================================================================
#[derive(Serialize, Deserialize, Clone, Debug)] 
struct AlertHistory {
    src_ips: HashMap<String, u32>,
    users: HashMap<String, u32>,
    rules: HashMap<u32, u32>,
    last_alert_time: DateTime<Utc>,
}

impl Default for AlertHistory {
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
    fn update(&mut self, alert: &Value) {
        let now = Utc::now();

        // If the last alert was too long ago, reset the history
        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now;

        // Update counters
        if let Some(src_ip) = alert.get("srcip").and_then(Value::as_str) {
            *self.src_ips.entry(src_ip.to_string()).or_insert(0) += 1;
        }
        if let Some(user) = alert.get("data").and_then(|d| d.get("user")).and_then(Value::as_str) {
            *self.users.entry(user.to_string()).or_insert(0) += 1;
        }
        if let Some(rule_id) = alert.get("rule").and_then(|r| r.get("id")).and_then(Value::as_u64) {
            *self.rules.entry(rule_id as u32).or_insert(0) += 1;
        }
    }

    fn is_suspicious_activity(&self, alert: &Value) -> Option<Value> {
        let mut anomalies = json!({});
        let mut found_anomaly = false;

        // Check for high frequency from same source
        if let Some(src_ip) = alert.get("srcip").and_then(Value::as_str) {
            if let Some(&count) = self.src_ips.get(src_ip) {
                if count > HIGH_SEVERITY_THRESHOLD as u32 {
                    anomalies["high_frequency_ip"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }
        // Check for suspicious user activity
        if let Some(user) = alert.get("data").and_then(|d| d.get("user")).and_then(Value::as_str) {
            if let Some(&count) = self.users.get(user) {
                if count > HIGH_SEVERITY_THRESHOLD as u32 {
                    anomalies["high_frequency_user"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }
        // Check for rule flooding
        if let Some(rule_id) = alert.get("rule").and_then(|r| r.get("id")).and_then(Value::as_u64) {
            if let Some(&count) = self.rules.get(&(rule_id as u32)) {
                if count > HIGH_SEVERITY_THRESHOLD as u32 {
                    anomalies["high_frequency_rule"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }

        if found_anomaly { Some(anomalies) } else { None }
    }
}


// ==============================================================================
// --- State Management ---
// ==============================================================================
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct State {
    inode: Option<u64>,
    offset: u64,
    alert_history: AlertHistory,
}

struct StateManager {
    state_file: String,
    state: State,
}

impl StateManager {
    fn new(state_file: &str) -> Self {
        let state = State::default();
        Self { state_file: state_file.to_string(), state }
    }

    fn load(&mut self) -> Result<()> {
        if !Path::new(&self.state_file).exists() {
            info!("State file not found. Using default state.");
            return Ok(());
        }
        let contents = fs::read_to_string(&self.state_file)
            .with_context(|| format!("Failed to read state file {}", self.state_file))?;
        self.state = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file {}", self.state_file))?;
        info!("Loaded state: Inode {:?}, Offset {}", self.state.inode, self.state.offset);
        Ok(())
    }

    fn save(&self) -> Result<()> {
        let serialized = serde_json::to_string(&self.state)?;
        if let Some(parent) = Path::new(&self.state_file).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.state_file, serialized)?;
        debug!("Saved state: Inode={:?}, Offset={}", self.state.inode, self.state.offset);
        Ok(())
    }
}


// ==============================================================================
// --- Telegram Notifications ---
// ==============================================================================
fn send_telegram_message(message: &str) {
    if !ENABLE_TELEGRAM || TELEGRAM_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN" { return; }
    let client = Client::new();
    let url = format!("https://api.telegram.org/bot{}/sendMessage", TELEGRAM_TOKEN);
    let params = [("chat_id", TELEGRAM_CHAT_ID), ("text", &format!("[Wazuh-Forwarder]\n{}", message)), ("parse_mode", "Markdown")];
    if let Err(e) = client.post(&url).form(&params).send() {
        error!("Failed to send Telegram message: {}", e);
    }
}


// ==============================================================================
// --- Threat Hunting & Enrichment ---
// ==============================================================================
fn extract_iocs(alert: &Value) -> HashMap<&'static str, Vec<String>> {
    let mut iocs = HashMap::new();
    let mut results = Vec::new();
    find_in_value(alert, &mut |value, _path| {
        if let Some(s) = value.as_str() {
            results.extend(IP_REGEX.find_iter(s).map(|m| ("ip", m.as_str().to_string())));
            results.extend(DOMAIN_REGEX.find_iter(s).map(|m| ("domain", m.as_str().to_string())));
            results.extend(HASH_REGEX.find_iter(s).map(|m| ("hash", m.as_str().to_string())));
            results.extend(URL_REGEX.find_iter(s).map(|m| ("url", m.as_str().to_string())));
        }
    });
    for (ioc_type, value) in results {
        iocs.entry(ioc_type).or_insert_with(Vec::new).push(value);
    }
    iocs
}

fn find_in_value<F>(value: &Value, f: &mut F) where F: FnMut(&Value, &str) {
    find_in_value_recursive(value, String::new(), f);
}

fn find_in_value_recursive<F>(value: &Value, current_path: String, f: &mut F) where F: FnMut(&Value, &str) {
    f(value, &current_path);
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let new_path = if current_path.is_empty() { key.clone() } else { format!("{}.{}", current_path, key) };
                find_in_value_recursive(val, new_path, f);
            }
        }
        Value::Array(arr) => {
            for (index, val) in arr.iter().enumerate() {
                let new_path = format!("{}[{}]", current_path, index);
                find_in_value_recursive(val, new_path, f);
            }
        }
        _ => {}
    }
}

fn enrich_and_analyze_alert(alert: &mut Value, intel: &ThreatIntel, state: &mut AlertHistory) {
    let iocs = extract_iocs(alert);
    let mut enrichment_data = json!({});
    let mut found_enrichment = false;

    // --- 1. Threat Intelligence IOC Matching ---
    let mut ioc_matches = json!({});
    let mut found_ioc_match = false;
    
    // IP Reputation Check
    if let Some(ips) = iocs.get("ip") {
        let mut malicious_ip_hits = Vec::new();
        for ip in ips {
            if let Some(sources) = intel.malicious_ips.get(ip) {
                info!("Found blocklisted IP {} in alert", ip);
                malicious_ip_hits.push(json!({
                    "ip": ip, "status": "blocklisted", "sources": sources, "source_count": sources.len()
                }));
            }
        }
        if !malicious_ip_hits.is_empty() {
            ioc_matches["malicious_ips"] = Value::Array(malicious_ip_hits);
            found_ioc_match = true;
        }
    }

    // Domain, Hash, and URL checks
    if let Some(domains) = iocs.get("domain") {
        let hits: Vec<_> = domains.iter().filter(|d| intel.malicious_domains.contains(*d)).collect();
        if !hits.is_empty() { ioc_matches["malicious_domains"] = json!(hits); found_ioc_match = true; }
    }
    if let Some(hashes) = iocs.get("hash") {
        let hits: Vec<_> = hashes.iter().filter(|h| intel.malicious_hashes.contains(*h)).collect();
        if !hits.is_empty() { ioc_matches["malicious_hashes"] = json!(hits); found_ioc_match = true; }
    }
    if let Some(urls) = iocs.get("url") {
        let hits: Vec<_> = urls.iter().filter(|u| intel.malicious_urls.contains(*u)).collect();
        if !hits.is_empty() { ioc_matches["malicious_urls"] = json!(hits); found_ioc_match = true; }
    }
    
    if found_ioc_match { enrichment_data["ioc_matches"] = ioc_matches; found_enrichment = true; }

    // --- 2. Other Threat Hunting Detections ---
    let mut hunt_detections = json!({});
    let mut found_hunt_detection = false;

    // Suspicious Patterns
    let mut suspicious_patterns = Vec::new();
    find_in_value(alert, &mut |value, path| {
        if let Some(s) = value.as_str() {
            for (name, pattern) in &intel.suspicious_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(s) {
                        suspicious_patterns.push(json!({"pattern": name, "field_path": path, "sample": s.chars().take(100).collect::<String>()}));
                    }
                }
            }
        }
    });
    if !suspicious_patterns.is_empty() { hunt_detections["suspicious_patterns"] = Value::Array(suspicious_patterns); found_hunt_detection = true; }

    // Suspicious Processes
    if let Some(cmd) = alert.get("data").and_then(|d| d.get("win.eventdata.commandLine").or_else(|| d.get("command"))).and_then(Value::as_str) {
        for process in SUSPICIOUS_PROCESSES {
            if cmd.to_lowercase().contains(process) { hunt_detections["suspicious_process"] = json!(process); found_hunt_detection = true; break; }
        }
    }

    // Critical Asset Access
    if let Some(desc) = alert.get("rule").and_then(|r| r.get("description")).and_then(Value::as_str) {
        for asset in CRITICAL_ASSETS {
            if desc.to_lowercase().contains(asset) { hunt_detections["critical_asset_access"] = json!(asset); found_hunt_detection = true; break; }
        }
    }
    
    // Correlation Rules
    if let Some(desc) = alert.get("rule").and_then(|r| r.get("description")).and_then(Value::as_str) {
        let mut matches = Vec::new();
        for (name, pattern) in CORRELATION_RULES.iter() {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(desc) { matches.push(json!({ "rule": name, "pattern": pattern })); }
            }
        }
        if !matches.is_empty() { hunt_detections["correlation_rules"] = Value::Array(matches); found_hunt_detection = true; }
    }

    if found_hunt_detection { enrichment_data["threat_hunting"] = hunt_detections; found_enrichment = true; }

    // --- 3. Behavioral Analysis ---
    if ENABLE_BEHAVIORAL_ANALYSIS {
        if let Some(anomalies) = state.is_suspicious_activity(alert) {
            enrichment_data["behavioral_anomalies"] = anomalies;
            found_enrichment = true;
        }
    }
    
    // Add all enrichment data to the alert under a single key
    if found_enrichment {
        if let Some(obj) = alert.as_object_mut() {
            enrichment_data["intel_last_updated"] = json!(intel.last_updated.to_rfc3339());
            obj.insert("forwarder_enrichment".to_string(), enrichment_data);
        }
    }
}


// ==============================================================================
// --- Threat Intelligence Feed Management ---
// ==============================================================================
fn get_cache_filepath(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    format!("{}/{:x}.json", THREAT_INTEL_CACHE_DIR, result)
}

fn is_cache_valid(filepath: &str) -> bool {
    if let Ok(metadata) = fs::metadata(filepath) {
        if let Ok(last_modified) = metadata.modified() {
            return last_modified.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(THREAT_INTEL_REFRESH_INTERVAL_SECS);
        }
    }
    false
}

fn download_feed(url: &str) -> Result<HashSet<String>> {
    let cache_filepath = get_cache_filepath(url);
    if is_cache_valid(&cache_filepath) {
        debug!("Using cached feed for {}", url);
        let file = File::open(&cache_filepath)?;
        let items: HashSet<String> = serde_json::from_reader(file)?;
        return Ok(items);
    }

    info!("Downloading new feed from {}", url);
    let client = Client::new();
    let response = client.get(url).timeout(Duration::from_secs(30)).send()?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP error {} for {}", response.status(), url));
    }

    let text = response.text()?;
    let items: HashSet<String> = text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with(&['#', ';', '/']) && !line.is_empty())
        .map(|s| s.to_string())
        .collect();

    if let Some(parent) = Path::new(&cache_filepath).parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(&cache_filepath)?;
    serde_json::to_writer(file, &items)?;
    Ok(items)
}

fn is_public_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_documentation()
    } else {
        false
    }
}

fn threat_intel_updater_thread(intel_db: Arc<Mutex<ThreatIntel>>, shutdown: Arc<AtomicBool>) {
    info!("Threat intelligence updater thread started.");
    while !shutdown.load(Ordering::Relaxed) {
        info!("Starting threat intelligence database update...");
        send_telegram_message("⏳ Starting threat intelligence database update...");

        let mut new_intel = ThreatIntel::new(); // Starts with default patterns

        // Fetch Malicious IPs
        let mut all_ips: HashMap<String, Vec<String>> = HashMap::new();
        for url in IP_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => {
                    for ip in items {
                        if is_public_ip(&ip) { all_ips.entry(ip).or_default().push(url.to_string()); }
                    }
                },
                Err(e) => error!("Failed to download IP feed {}: {}", url, e),
            }
        }
        new_intel.malicious_ips = all_ips;
        info!("Loaded {} unique malicious IPs.", new_intel.malicious_ips.len());

        // Fetch Malicious URLs
        let mut all_urls = HashSet::new();
        for url in URL_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => all_urls.extend(items),
                Err(e) => error!("Failed to download URL feed {}: {}", url, e),
            }
        }
        new_intel.malicious_urls = all_urls;
        info!("Loaded {} malicious URLs.", new_intel.malicious_urls.len());
        
        // Fetch Malicious Hashes
        let mut all_hashes = HashSet::new();
        for url in HASH_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => all_hashes.extend(items),
                Err(e) => error!("Failed to download hash feed {}: {}", url, e),
            }
        }
        new_intel.malicious_hashes = all_hashes;
        info!("Loaded {} malicious hashes.", new_intel.malicious_hashes.len());

        // Fetch Malicious Domains
        let mut all_domains = HashSet::new();
        for url in DOMAIN_FEED_URLS.iter() {
            match download_feed(url) {
                Ok(items) => all_domains.extend(items),
                Err(e) => error!("Failed to download domain feed {}: {}", url, e),
            }
        }
        new_intel.malicious_domains = all_domains;
        info!("Loaded {} malicious domains.", new_intel.malicious_domains.len());

        new_intel.last_updated = Utc::now();
        let total_indicators = new_intel.indicator_count();
        
        // Atomically update the global threat intel database
        *intel_db.lock().unwrap() = new_intel;

        info!("Threat intelligence databases updated. Total indicators: {}", total_indicators);
        send_telegram_message(&format!("✅ Threat intelligence databases updated. Total indicators loaded: {}.", total_indicators));

        // Sleep until next refresh
        for _ in 0..THREAT_INTEL_REFRESH_INTERVAL_SECS {
            if shutdown.load(Ordering::Relaxed) { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }
    info!("Threat intelligence updater thread shutting down.");
}


// ==============================================================================
// --- File Reader Thread ---
// ==============================================================================
fn file_reader_thread(
    alert_file: &str,
    state_manager: &mut StateManager,
    sender: Sender<String>,
    threat_intel_db: Arc<Mutex<ThreatIntel>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("File reader thread started.");
    let mut line_buffer = String::new();

    if state_manager.state.inode.is_none() && Path::new(alert_file).exists() {
        if PROCESS_FROM_BEGINNING_ON_FIRST_RUN {
            warn!("First run: Flag is set to true. Reading alerts from the BEGINNING of the file.");
            send_telegram_message("ℹ️ First run: Starting from BEGINNING of log file, processing all historical data.");
            let metadata = fs::metadata(alert_file)?;
            state_manager.state.inode = Some(metadata.ino());
        } else {
            warn!("First run with existing log file. Starting from the END to process new entries only.");
            send_telegram_message("ℹ️ First run: Starting from END of log file, ignoring historical data.");
            let metadata = fs::metadata(alert_file)?;
            state_manager.state.inode = Some(metadata.ino());
            state_manager.state.offset = metadata.size();
        }
        state_manager.save()?;
    }

    while !shutdown.load(Ordering::Relaxed) {
        if !Path::new(alert_file).exists() {
            thread::sleep(Duration::from_secs(15));
            continue;
        }

        let metadata = fs::metadata(alert_file)?;
        let current_inode = state_manager.state.inode;
        let mut offset = state_manager.state.offset;

        if current_inode.is_none() || metadata.ino() != current_inode.unwrap() {
            info!("New log file or rotation detected. Resetting to start of new file.");
            state_manager.state.inode = Some(metadata.ino());
            state_manager.state.offset = 0;
            offset = 0;
            line_buffer.clear();
        }
        if metadata.size() < offset {
            warn!("Log file truncated. Resetting offset from {} to 0.", offset);
            state_manager.state.offset = 0;
            offset = 0;
            line_buffer.clear();
        }

        if offset < metadata.size() {
            let mut file = OpenOptions::new().read(true).open(alert_file)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut reader = BufReader::with_capacity(READ_CHUNK_SIZE, file);
            let mut lines_queued = 0;

            loop {
                let mut chunk = Vec::new();
                let bytes_read = reader.read_until(b'\n', &mut chunk)?;
                if bytes_read == 0 { break; }

                line_buffer.push_str(&String::from_utf8_lossy(&chunk));

                if line_buffer.ends_with('\n') {
                    let line_to_process = line_buffer.trim().to_string();
                    line_buffer.clear();
                    if line_to_process.is_empty() { continue; }

                    match serde_json::from_str::<Value>(&line_to_process) {
                        Ok(mut alert_json) => {
                            state_manager.state.alert_history.update(&alert_json);
                            
                            let intel = threat_intel_db.lock().unwrap();
                            enrich_and_analyze_alert(&mut alert_json, &intel, &mut state_manager.state.alert_history);
                            
                            let enriched_line = serde_json::to_string(&alert_json)?;
                            if sender.send(enriched_line).is_err() { break; }
                            lines_queued += 1;
                        }
                        Err(e) => warn!("Skipping malformed JSON line: {}... Error: {}", &line_to_process[..200.min(line_to_process.len())], e),
                    }
                }
            }
            state_manager.state.offset = reader.seek(SeekFrom::Current(0))?;
            if lines_queued > 0 { info!("Queued {} new alert(s).", lines_queued); }
        }

        state_manager.save()?;
        thread::sleep(Duration::from_millis(500));
    }

    info!("File reader thread shutting down.");
    state_manager.save()?;
    Ok(())
}


// ==============================================================================
// --- ELK Sender Thread ---
// ==============================================================================
fn elk_sender_thread(receiver: Receiver<String>, shutdown: Arc<AtomicBool>) -> Result<()> {
    info!("ELK sender thread started.");
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT).parse()?;
    let mut retry_delay = 5;
    let mut last_heartbeat = Instant::now();
    let mut lines_processed = 0;
    let mut stream = None;

    match TcpStream::connect_timeout(&addr, Duration::from_secs(SOCKET_TIMEOUT)) {
        Ok(s) => {
            info!("Successfully connected to ELK at {}:{}", ELK_HOST, ELK_PORT);
            send_telegram_message(&format!("✅ *Connection Established:* Successfully connected to ELK server at {}:{}.", ELK_HOST, ELK_PORT));
            stream = Some(s);
        }
        Err(e) => error!("Initial connection failed: {}", e),
    };

    while !shutdown.load(Ordering::Relaxed) || !receiver.is_empty() {
        if last_heartbeat.elapsed().as_secs() >= HEARTBEAT_INTERVAL {
            let message = format!("❤️ *Heartbeat:* Service is alive. {} alerts forwarded. Queue size: {}.", lines_processed, receiver.len());
            send_telegram_message(&message);
            info!("{}", message);
            lines_processed = 0;
            last_heartbeat = Instant::now();
        }

        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(message) => {
                let data = message + "\n";
                let mut success = false;
                while !success && !shutdown.load(Ordering::Relaxed) {
                    if let Some(ref mut s) = stream {
                        if s.write_all(data.as_bytes()).is_ok() {
                            debug!("Successfully sent alert to ELK");
                            lines_processed += 1;
                            success = true;
                        } else {
                            stream = None;
                        }
                    }
                    if !success {
                        warn!("Reconnecting to ELK...");
                        thread::sleep(Duration::from_secs(retry_delay));
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(SOCKET_TIMEOUT)) {
                            Ok(s) => {
                                info!("Reconnected to ELK");
                                stream = Some(s);
                                retry_delay = 5;
                            }
                            Err(e) => {
                                error!("Reconnection failed: {}", e);
                                retry_delay = std::cmp::min(retry_delay * 2, 60);
                            }
                        }
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    info!("ELK sender thread shutting down.");
    Ok(())
}


// ==============================================================================
// --- Initial Connection Test ---
// ==============================================================================
fn test_initial_connection() -> Result<()> {
    info!("Testing initial connection to ELK...");
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT).parse()?;
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_) => {
            info!("✅ Initial connection test successful.");
            Ok(())
        }
        Err(e) => {
            let msg = format!("🚨 Initial connection test FAILED: {}\nCheck firewall/connectivity to {}:{}", e, ELK_HOST, ELK_PORT);
            error!("{}", msg);
            send_telegram_message(&msg);
            Err(anyhow!(msg))
        }
    }
}


// ==============================================================================
// --- Main Function ---
// ==============================================================================
fn main() -> Result<()> {
    // --- Logging Setup ---
    let log_file_result = OpenOptions::new().create(true).append(true).open(LOG_FILE);
    let fern_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("unknown"),
                message
            ))
        })
        .level(LevelFilter::Info)
        .chain(io::stdout());
    
    match log_file_result {
        Ok(file) => fern_dispatch.chain(file).apply()?,
        Err(e) => {
            eprintln!("Failed to open log file: {}. Logging to stdout only.", e);
            fern_dispatch.apply()?;
        }
    };

    info!("==============================================");
    info!("      Wazuh Alert Forwarder Service (Rust)    ");
    info!("==============================================");
    info!("Forwarding to ELK server at: {}:{}", ELK_HOST, ELK_PORT);

    if let Err(e) = test_initial_connection() {
        warn!("Proceeding despite connection failure: {}", e);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
    let signal_shutdown = shutdown.clone();
    thread::spawn(move || {
        for sig in signals.forever() {
            info!("Received signal {:?}, initiating shutdown...", sig);
            signal_shutdown.store(true, Ordering::Relaxed);
        }
    });

    let (tx, rx) = bounded(MAX_QUEUE_SIZE);

    let mut state_manager = StateManager::new(STATE_FILE);
    if let Err(e) = state_manager.load() { error!("Failed to load state: {}", e); }

    // Initialize the shared threat intelligence database
    let threat_intel_db = Arc::new(Mutex::new(ThreatIntel::new()));
    
    // Spawn the threat intelligence updater thread
    if ENABLE_THREAT_INTEL_FEEDS {
        let intel_clone = threat_intel_db.clone();
        let shutdown_clone = shutdown.clone();
        thread::Builder::new().name("intel_updater".to_string()).spawn(move || {
            threat_intel_updater_thread(intel_clone, shutdown_clone);
        })?;
    } else {
        info!("Threat intelligence feed fetching is disabled by configuration.");
    }

    let file_reader_shutdown = shutdown.clone();
    let file_reader_tx = tx.clone();
    let file_reader_intel_db = threat_intel_db.clone();
    let file_reader_handle = thread::Builder::new().name("file_reader".to_string()).spawn(move || {
        if let Err(e) = file_reader_thread(WAZUH_ALERTS_FILE, &mut state_manager, file_reader_tx, file_reader_intel_db, file_reader_shutdown) {
            error!("File reader thread error: {}", e);
        }
    })?;

    let elk_sender_shutdown = shutdown.clone();
    let elk_sender_handle = thread::Builder::new().name("elk_sender".to_string()).spawn(move || {
        if let Err(e) = elk_sender_thread(rx, elk_sender_shutdown) {
            error!("ELK sender thread error: {}", e);
        }
    })?;

    file_reader_handle.join().unwrap();
    elk_sender_handle.join().unwrap();

    info!("Service stopped gracefully.");
    send_telegram_message("✅ *Shutdown Complete:* Service stopped gracefully.");

    Ok(())
}