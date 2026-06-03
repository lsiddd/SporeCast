//! Runtime and infrastructure defaults.

pub const WAZUH_LOCAL_SYSLOG_HOST: &str = "127.0.0.1";
pub const WAZUH_LOCAL_SYSLOG_PORT: u16 = 1514;
pub const SOCKET_TIMEOUT_SECS: u64 = 10;
#[allow(dead_code)]
pub const HEARTBEAT_INTERVAL_SECS: u64 = 3600;

pub const MAX_RECEIVER_QUEUE_SIZE: usize = 250_000;
pub const MAX_ENRICHMENT_QUEUE_SIZE: usize = 200_000;
pub const MAX_WAZUH_QUEUE_SIZE: usize = 200_000;
pub const ENRICHMENT_WORKER_COUNT: usize = 16;
pub const ELK_BATCH_SIZE: usize = 5000;
pub const ELK_BATCH_FLUSH_INTERVAL_SECS: u64 = 2;

pub const HIGH_WORKLOAD_THRESHOLD: f64 = 0.8;
pub const DISABLE_BEHAVIORAL_UNDER_HIGH_LOAD: bool = true;
pub const QUEUE_MONITORING_INTERVAL_SECS: u64 = 10;
pub const CONNECTION_POOL_SIZE: usize = 4;

pub const CIRCUIT_BREAKER_FAILURE_THRESHOLD: usize = 5;
pub const CIRCUIT_BREAKER_TIMEOUT_SECS: u64 = 30;
pub const CIRCUIT_BREAKER_SUCCESS_THRESHOLD: usize = 3;

pub const ENABLE_BEHAVIORAL_ANALYSIS_DEFAULT: bool = true;
pub const BEHAVIOR_WINDOW_MINUTES_DEFAULT: i64 = 5;
pub const HIGH_SEVERITY_THRESHOLD_DEFAULT: u32 = 10;

pub const ENABLE_THREAT_INTEL_FEEDS: bool = true;
pub const THREAT_INTEL_REFRESH_INTERVAL_SECS: u64 = 86400;
pub const THREAT_INTEL_CACHE_DIR: &str = "run/threat_intel_cache";

pub const IP_FEED_URLS: [&str; 12] = [
    "https://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "https://www.binarydefense.com/banlist.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
];

pub const DOMAIN_FEED_URLS: [&str; 5] = [
    "https://www.malwaredomainlist.com/hostslist/domains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
    "https://hole.cert.pl/domains/domains.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
];

pub const URL_FEED_URLS: [&str; 3] = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://openphish.com/feed.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
];

pub const HASH_FEED_URLS: [&str; 3] = [
    "https://bazaar.abuse.ch/export/txt/sha256/full/",
    "https://bazaar.abuse.ch/export/txt/md5/full/",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt",
];
