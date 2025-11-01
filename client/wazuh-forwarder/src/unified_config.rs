use regex::Regex;
use std::collections::HashMap;

// ==============================================================================
// --- Unified Configuration for All Binaries ---
// This module provides standardized threat intelligence configuration,
// detection patterns, and behavioral analysis rules for use across
// all forwarder binaries (Palo Alto, etc.).
// ==============================================================================

// --- Network Configuration Shared Defaults ---
pub const WAZUH_LOCAL_SYSLOG_HOST: &str = "127.0.0.1";
pub const WAZUH_LOCAL_SYSLOG_PORT: u16 = 1514;
pub const SOCKET_TIMEOUT_SECS: u64 = 10;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 3600;

// --- Performance Configuration ---
pub const MAX_RECEIVER_QUEUE_SIZE: usize = 500000;  // Increased 10x for high throughput
pub const MAX_ENRICHMENT_QUEUE_SIZE: usize = 400000; // Increased 10x for high throughput
pub const MAX_WAZUH_QUEUE_SIZE: usize = 400000;      // Increased 10x for high throughput
pub const ENRICHMENT_WORKER_COUNT: usize = 16;       // Doubled for better parallelism
pub const ELK_BATCH_SIZE: usize = 5000;              // Increased batch size for efficiency
pub const ELK_BATCH_FLUSH_INTERVAL_SECS: u64 = 2;    // Slightly increased flush interval

// --- High Workload Management ---
#[allow(dead_code)]
pub const HIGH_WORKLOAD_THRESHOLD: f64 = 0.8;        // Trigger degradation at 80% queue capacity
#[allow(dead_code)]
pub const DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD: bool = true; // Auto-disable behavioral analysis under load
#[allow(dead_code)]
pub const QUEUE_MONITORING_INTERVAL_SECS: u64 = 10;  // Monitor queue sizes every 10 seconds
#[allow(dead_code)]
pub const CONNECTION_POOL_SIZE: usize = 4;           // Number of ELK connections in pool

// --- Circuit Breaker Configuration ---
#[allow(dead_code)]
pub const CIRCUIT_BREAKER_FAILURE_THRESHOLD: usize = 5;     // Failures before opening circuit
#[allow(dead_code)]
pub const CIRCUIT_BREAKER_TIMEOUT_SECS: u64 = 30;          // Time before trying to close circuit
#[allow(dead_code)]
pub const CIRCUIT_BREAKER_SUCCESS_THRESHOLD: usize = 3;     // Successes needed to close circuit

// --- Telegram Configuration ---
pub const ENABLE_TELEGRAM: bool = true;
pub const TELEGRAM_TOKEN: &str = "YOUR_TELEGRAM_BOT_TOKEN";
pub const TELEGRAM_CHAT_ID: &str = "YOUR_TELEGRAM_CHAT_ID";

// --- Unified Threat Intelligence Configuration ---
pub const ENABLE_THREAT_INTEL_FEEDS: bool = true;
pub const THREAT_INTEL_REFRESH_INTERVAL_SECS: u64 = 86400; // 24 hours
pub const THREAT_INTEL_CACHE_DIR: &str = "/var/lib/forwarder/threat_intel_cache";

// ==============================================================================
// --- Comprehensive Threat Intelligence Feeds ---
// All binaries will use the same comprehensive threat intelligence sources
// ==============================================================================

// Malicious IP Feeds - Expanded comprehensive list
pub const IP_FEED_URLS: [&str; 15] = [
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
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://www.openbl.org/lists/base.txt",
];

// Malicious Domain Feeds
pub const DOMAIN_FEED_URLS: [&str; 5] = [
    "https://www.malwaredomainlist.com/hostslist/domains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
    "https://hole.cert.pl/domains/domains.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
];

// Malicious URL Feeds
pub const URL_FEED_URLS: [&str; 3] = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://openphish.com/feed.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
];

// Malicious Hash Feeds
pub const HASH_FEED_URLS: [&str; 3] = [
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
    "https://bazaar.abuse.ch/export/txt/md5/full/",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt",
];

// ==============================================================================
// --- Unified Behavioral Analysis Configuration ---
// ==============================================================================

pub const ENABLE_BEHAVIORAL_ANALYSIS: bool = true;
pub const BEHAVIOR_WINDOW_MINUTES: i64 = 5;
pub const HIGH_SEVERITY_THRESHOLD: u32 = 10;

// Comprehensive suspicious processes list for all environments
pub const SUSPICIOUS_PROCESSES: [&str; 32] = [
    // Common attack tools
    "meterpreter", "cobaltstrike", "metasploit", "netcat", "nc", "ncat",
    // PowerShell abuse
    "powershell -e", "powershell -enc", "powershell -w hidden", "powershell -nop",
    // Living off the land binaries
    "certutil", "bitsadmin", "wmic", "mshta", "rundll32", "regsvr32",
    // Administrative tools often abused
    "schtasks", "psexec", "paexec", "winexe", "at.exe", "sc.exe",
    // Network tools
    "netsh", "ipconfig", "nslookup", "ping", "telnet",
    // System information gathering
    "whoami", "systeminfo", "tasklist", "net user", "net localgroup"
];

// Comprehensive critical assets keywords
pub const CRITICAL_ASSETS: [&str; 21] = [
    "domain-controller", "domain controller", "active directory", "ldap",
    "database-server", "database server", "mysql", "postgresql", "oracle", "mssql",
    "payment-gateway", "payment gateway", "pos system",
    "erp-system", "erp system", "sap", "oracle erp",
    "scada-system", "scada system", "hmi", "plc"
];

// Unified correlation rules for all log types
pub const CORRELATION_RULES: [(&str, &str); 15] = [
    ("brute_force", r"(?i)(authentication failure|login failed|invalid password|bad password)"),
    ("port_scan", r"(?i)(scan detected|port scan|reconnaissance|nmap)"),
    ("malware_exec", r"(?i)(malware|virus|trojan|backdoor|rootkit|ransomware)"),
    ("suspicious_login", r"(?i)(login outside business hours|unusual login time|after hours access)"),
    ("data_exfiltration", r"(?i)(large data transfer|exfiltration|data leak|file upload|ftp transfer)"),
    ("privilege_escalation", r"(?i)(sudo|su |privilege escalation|elevated privileges|admin access)"),
    ("config_change", r"(?i)(configuration changed|config modified|settings altered)"),
    ("critical_service_stop", r"(?i)(service stopped|service terminated|critical service down)"),
    ("new_service", r"(?i)(new service installed|service created|service registered)"),
    ("persistence", r"(?i)(persistence mechanism|startup item|autostart|registry run key)"),
    ("lateral_movement", r"(?i)(lateral movement|remote execution|psexec|wmi execution)"),
    ("command_and_control", r"(?i)(c2|c&c|command and control|beacon|callback)"),
    ("policy_violation", r"(?i)(policy violation|security policy|compliance violation)"),
    ("suspicious_network", r"(?i)(suspicious connection|malicious ip|blocked connection)"),
    ("crypto_mining", r"(?i)(crypto mining|cryptocurrency|bitcoin|monero|mining pool)")
];

// ==============================================================================
// --- Unified Regex Patterns ---
// ==============================================================================

lazy_static::lazy_static! {
    // Comprehensive IP regex supporting both IPv4 and IPv6
    pub static ref IP_REGEX: Regex = Regex::new(
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    ).unwrap();

    // Enhanced domain regex
    pub static ref DOMAIN_REGEX: Regex = Regex::new(
        r"(?i)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    ).unwrap();

    // Comprehensive hash regex (MD5, SHA1, SHA256, SHA384, SHA512)
    pub static ref HASH_REGEX: Regex = Regex::new(
        r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})\b"
    ).unwrap();

    // Enhanced URL regex
    pub static ref URL_REGEX: Regex = Regex::new(
        r"(?i)(?:https?|ftp)://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*"
    ).unwrap();


    // Compiled correlation rules
    pub static ref CORRELATION_RULES_COMPILED: Vec<(&'static str, Regex)> = 
        CORRELATION_RULES.iter().map(|(name, pattern)| {
            (*name, Regex::new(pattern).expect("Failed to compile correlation rule regex"))
        }).collect();

    // Comprehensive suspicious patterns
    pub static ref SUSPICIOUS_PATTERNS_COMPILED: HashMap<String, Regex> = {
        let mut patterns = HashMap::new();
        
        // Encoding patterns
        patterns.insert("base64_encoded".to_string(), 
            Regex::new(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap());
        patterns.insert("hex_encoded".to_string(), 
            Regex::new(r"(?:\\x[0-9a-fA-F]{2}){10,}").unwrap());
        patterns.insert("unicode_encoded".to_string(), 
            Regex::new(r"(?:\\u[0-9a-fA-F]{4}){5,}").unwrap());
        
        // Obfuscation patterns
        patterns.insert("obfuscated_powershell".to_string(), 
            Regex::new(r"(?i)powershell.*[-/][eE](?:ncodedcommand|nc)?\s+[a-zA-Z0-9+/=]{20,}").unwrap());
        patterns.insert("obfuscated_script".to_string(), 
            Regex::new(r"(?i)(?:cmd|powershell|bash|sh).*[{()}$`|&;]{3,}").unwrap());
        
        // Web attack patterns
        patterns.insert("sql_injection".to_string(), 
            Regex::new(r"(?i)(?:union\s+select|drop\s+table|insert\s+into|update\s+set|delete\s+from|'|\s+or\s+1=1|\s+and\s+1=1)").unwrap());
        patterns.insert("xss_attempt".to_string(), 
            Regex::new(r"(?i)(?:<script|javascript:|onload=|onerror=|onclick=|onmouseover=)").unwrap());
        patterns.insert("command_injection".to_string(), 
            Regex::new(r"(?i)(?:;|\|\||&&|`|\$\(|\$\{|%[0-9a-fA-F]\{2\})").unwrap());
        patterns.insert("directory_traversal".to_string(), 
            Regex::new(r"(?i)(?:\.\./|\.\.\\|/etc/|c:\\|%2e%2e%2f|%2e%2e%5c)").unwrap());
        
        // Suspicious user agents
        patterns.insert("suspicious_user_agent".to_string(), 
            Regex::new(r"(?i)(?:curl|wget|python-requests|urllib|httpclient|bot|scanner|crawler|sqlmap)").unwrap());
        
        // Crypto/malware patterns
        patterns.insert("crypto_mining".to_string(), 
            Regex::new(r"(?i)(?:stratum|mining|coinminer|cryptonight|xmrig|monero|bitcoin)").unwrap());
        patterns.insert("malware_family".to_string(), 
            Regex::new(r"(?i)(?:emotet|trickbot|qakbot|dridex|lokibot|azorult|formbook|hawkeye|nanocore)").unwrap());
        
        patterns
    };
}

// ==============================================================================
// --- High Risk Application Categories (for Palo Alto and other NGFW) ---
// ==============================================================================

pub const _HIGH_RISK_APP_CATEGORIES: [&str; 15] = [
    "peer-to-peer", "file-sharing", "proxy", "anonymizer", "tunneling",
    "hacking-tools", "malware", "command-and-control", "cryptocurrency",
    "gaming", "social-networking", "instant-messaging", "remote-access",
    "backup", "storage-backup"
];