mod patterns;
pub use patterns::*;

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
pub const MAX_RECEIVER_QUEUE_SIZE: usize = 250_000; // Increased 10x for high throughput
pub const MAX_ENRICHMENT_QUEUE_SIZE: usize = 200_000; // Increased 10x for high throughput
pub const MAX_WAZUH_QUEUE_SIZE: usize = 200_000; // Increased 10x for high throughput
pub const ENRICHMENT_WORKER_COUNT: usize = 16; // Doubled for better parallelism
pub const ELK_BATCH_SIZE: usize = 5000; // Increased batch size for efficiency
pub const ELK_BATCH_FLUSH_INTERVAL_SECS: u64 = 2; // Slightly increased flush interval

// --- High Workload Management ---
#[allow(dead_code)]
pub const HIGH_WORKLOAD_THRESHOLD: f64 = 0.8; // Trigger degradation at 80% queue capacity
#[allow(dead_code)]
pub const DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD: bool = true; // Auto-disable behavioral analysis under load
#[allow(dead_code)]
pub const QUEUE_MONITORING_INTERVAL_SECS: u64 = 10; // Monitor queue sizes every 10 seconds
#[allow(dead_code)]
pub const CONNECTION_POOL_SIZE: usize = 4; // Number of ELK connections in pool

// --- Circuit Breaker Configuration ---
#[allow(dead_code)]
pub const CIRCUIT_BREAKER_FAILURE_THRESHOLD: usize = 5; // Failures before opening circuit
#[allow(dead_code)]
pub const CIRCUIT_BREAKER_TIMEOUT_SECS: u64 = 30; // Time before trying to close circuit
#[allow(dead_code)]
pub const CIRCUIT_BREAKER_SUCCESS_THRESHOLD: usize = 3; // Successes needed to close circuit

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
    "meterpreter",
    "cobaltstrike",
    "metasploit",
    "netcat",
    "nc",
    "ncat",
    // PowerShell abuse
    "powershell -e",
    "powershell -enc",
    "powershell -w hidden",
    "powershell -nop",
    // Living off the land binaries
    "certutil",
    "bitsadmin",
    "wmic",
    "mshta",
    "rundll32",
    "regsvr32",
    // Administrative tools often abused
    "schtasks",
    "psexec",
    "paexec",
    "winexe",
    "at.exe",
    "sc.exe",
    // Network tools
    "netsh",
    "ipconfig",
    "nslookup",
    "ping",
    "telnet",
    // System information gathering
    "whoami",
    "systeminfo",
    "tasklist",
    "net user",
    "net localgroup",
];

// Comprehensive critical assets keywords
pub const CRITICAL_ASSETS: [&str; 21] = [
    "domain-controller",
    "domain controller",
    "active directory",
    "ldap",
    "database-server",
    "database server",
    "mysql",
    "postgresql",
    "oracle",
    "mssql",
    "payment-gateway",
    "payment gateway",
    "pos system",
    "erp-system",
    "erp system",
    "sap",
    "oracle erp",
    "scada-system",
    "scada system",
    "hmi",
    "plc",
];

// Unified correlation rules for all log types
pub const CORRELATION_RULES: [(&str, &str); 15] = [
    (
        "brute_force",
        r"(?i)(authentication failure|login failed|invalid password|bad password)",
    ),
    (
        "port_scan",
        r"(?i)(scan detected|port scan|reconnaissance|nmap)",
    ),
    (
        "malware_exec",
        r"(?i)(malware|virus|trojan|backdoor|rootkit|ransomware)",
    ),
    (
        "suspicious_login",
        r"(?i)(login outside business hours|unusual login time|after hours access)",
    ),
    (
        "data_exfiltration",
        r"(?i)(large data transfer|exfiltration|data leak|file upload|ftp transfer)",
    ),
    (
        "privilege_escalation",
        r"(?i)(sudo|su |privilege escalation|elevated privileges|admin access)",
    ),
    (
        "config_change",
        r"(?i)(configuration changed|config modified|settings altered)",
    ),
    (
        "critical_service_stop",
        r"(?i)(service stopped|service terminated|critical service down)",
    ),
    (
        "new_service",
        r"(?i)(new service installed|service created|service registered)",
    ),
    (
        "persistence",
        r"(?i)(persistence mechanism|startup item|autostart|registry run key)",
    ),
    (
        "lateral_movement",
        r"(?i)(lateral movement|remote execution|psexec|wmi execution)",
    ),
    (
        "command_and_control",
        r"(?i)(c2|c&c|command and control|beacon|callback)",
    ),
    (
        "policy_violation",
        r"(?i)(policy violation|security policy|compliance violation)",
    ),
    (
        "suspicious_network",
        r"(?i)(suspicious connection|malicious ip|blocked connection)",
    ),
    (
        "crypto_mining",
        r"(?i)(crypto mining|cryptocurrency|bitcoin|monero|mining pool)",
    ),
];

// ==============================================================================
// --- High Risk Application Categories (for Palo Alto and other NGFW) ---
// ==============================================================================

pub const _HIGH_RISK_APP_CATEGORIES: [&str; 15] = [
    "peer-to-peer",
    "file-sharing",
    "proxy",
    "anonymizer",
    "tunneling",
    "hacking-tools",
    "malware",
    "command-and-control",
    "cryptocurrency",
    "gaming",
    "social-networking",
    "instant-messaging",
    "remote-access",
    "backup",
    "storage-backup",
];
