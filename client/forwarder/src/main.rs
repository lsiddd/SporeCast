use anyhow::{anyhow, Context, Result};
use chrono::prelude::*;
use crossbeam_channel::{bounded, Receiver, Sender};
use log::{debug, error, info, warn, LevelFilter};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
const ELK_PORT: u16 = 5142;
const SOCKET_TIMEOUT: u64 = 10;
const LOG_FILE: &str = "/var/log/wazuh_forwarder.log";
const STATE_FILE: &str = "/var/lib/wazuh-forwarder/forwarder_state.json";
const MAX_QUEUE_SIZE: usize = 10000;
const READ_CHUNK_SIZE: usize = 65536;
const ENABLE_TELEGRAM: bool = true;
const TELEGRAM_TOKEN: &str = "YOUR_TELEGRAM_BOT_TOKEN";
const TELEGRAM_CHAT_ID: &str = "YOUR_TELEGRAM_CHAT_ID";
const HEARTBEAT_INTERVAL: u64 = 3600;
const ENABLE_IP_REPUTATION: bool = true;
const CACHE_DIR: &str = "/var/lib/wazuh-forwarder/blocklist_cache";
const REFRESH_INTERVAL: u64 = 86400;
const BLOCKLIST_URLS: [&str; 12] = [
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
lazy_static::lazy_static! {
    static ref IP_REGEX: Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
}

// ==============================================================================
// --- State Management ---
// ==============================================================================
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct State {
    inode: Option<u64>,
    offset: u64,
}

struct StateManager {
    state_file: String,
    state: State,
}

impl StateManager {
    fn new(state_file: &str) -> Self {
        let state = State::default();
        Self {
            state_file: state_file.to_string(),
            state,
        }
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
        info!(
            "Loaded state: Inode {:?}, Offset {}",
            self.state.inode, self.state.offset
        );
        Ok(())
    }

    fn save(&self) -> Result<()> {
        let serialized = serde_json::to_string(&self.state)?;
        if let Some(parent) = Path::new(&self.state_file).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.state_file, serialized)?;
        debug!(
            "Saved state: Inode={:?}, Offset={}",
            self.state.inode, self.state.offset
        );
        Ok(())
    }
}

// ==============================================================================
// --- Telegram Notifications ---
// ==============================================================================
fn send_telegram_message(message: &str) {
    if !ENABLE_TELEGRAM || TELEGRAM_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN" {
        return;
    }

    let client = Client::new();
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        TELEGRAM_TOKEN
    );
    let params = [
        ("chat_id", TELEGRAM_CHAT_ID),
        ("text", &format!("[Wazuh-Forwarder]\n{}", message)),
        ("parse_mode", "Markdown"),
    ];

    if let Err(e) = client.post(&url).form(&params).send() {
        error!("Failed to send Telegram message: {}", e);
    }
}

// ==============================================================================
// --- IP Reputation Management ---
// ==============================================================================
fn get_cache_filepath(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let result = hasher.finalize();
    format!("{}/{:x}.json", CACHE_DIR, result)
}

fn is_cache_valid(filepath: &str) -> bool {
    if let Ok(metadata) = fs::metadata(filepath) {
        if let Ok(last_modified) = metadata.modified() {
            return last_modified.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(REFRESH_INTERVAL);
        }
    }
    false
}

fn download_list(url: &str) -> Result<HashSet<String>> {
    let cache_filepath = get_cache_filepath(url);
    if is_cache_valid(&cache_filepath) {
        debug!("Using cached list for {}", url);
        let file = File::open(&cache_filepath)?;
        let ips: HashSet<String> = serde_json::from_reader(file)?;
        return Ok(ips);
    }

    let client = Client::new();
    let response = client.get(url).timeout(Duration::from_secs(20)).send()?;
    if !response.status().is_success() {
        return Err(anyhow!("HTTP error: {}", response.status()));
    }

    let text = response.text()?;
    let ips: HashSet<String> = text
        .lines()
        .filter(|line| !line.starts_with(&['#', ';', '/']))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if let Some(parent) = Path::new(&cache_filepath).parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(&cache_filepath)?;
    serde_json::to_writer(file, &ips)?;
    info!("Successfully downloaded new blocklist from {}", url);
    Ok(ips)
}

fn get_blocklists() -> HashMap<String, HashSet<String>> {
    let mut blocklisted_ips = HashMap::new();
    for url in BLOCKLIST_URLS.iter() {
        match download_list(url) {
            Ok(ips) => {
                blocklisted_ips.insert(url.to_string(), ips);
            }
            Err(e) => {
                error!("Failed to download blocklist {}: {}", url, e);
            }
        }
    }
    blocklisted_ips
}

fn check_ip_reputation(ip_address: &str, blocklists: &HashMap<String, HashSet<String>>) -> Vec<String> {
    blocklists
        .iter()
        .filter(|(_, ips)| ips.contains(ip_address))
        .map(|(url, _)| url.clone())
        .collect()
}

fn is_public_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified()
    } else {
        false
    }
}

fn enrich_ips_recursively(value: &mut Value, blocklists: &HashMap<String, HashSet<String>>) {
    match value {
        Value::Object(map) => {
            // First recursively process all values
            for val in map.values_mut() {
                enrich_ips_recursively(val, blocklists);
            }

            // Collect keys to avoid borrowing issues
            let keys: Vec<String> = map.keys().cloned().collect();
            let mut reputation_inserts = Vec::new();

            for key in keys {
                if let Some(Value::String(s)) = map.get(&key) {
                    let ips: Vec<_> = IP_REGEX
                        .find_iter(s)
                        .map(|m| m.as_str())
                        .filter(|ip| is_public_ip(ip))
                        .collect();

                    if ips.is_empty() {
                        continue;
                    }

                    let mut reputation_data = serde_json::Map::new();
                    for ip in ips {
                        let found_in_lists = check_ip_reputation(ip, blocklists);
                        if !found_in_lists.is_empty() {
                            info!("Found blocklisted IP {} in field '{}'", ip, key);
                            let mut ip_data = serde_json::Map::new();
                            ip_data.insert("status".to_string(), Value::String("blocklisted".to_string()));
                            ip_data.insert(
                                "source_lists".to_string(),
                                Value::Array(
                                    found_in_lists
                                        .into_iter()
                                        .map(Value::String)
                                        .collect(),
                                ),
                            );
                            reputation_data.insert(ip.to_string(), Value::Object(ip_data));
                        }
                    }

                    if !reputation_data.is_empty() {
                        reputation_inserts.push((key.clone(), reputation_data));
                    }
                }
            }

            // Insert new reputation fields
            for (key, reputation_data) in reputation_inserts {
                let new_field_name = format!("{}_reputation", key);
                map.insert(new_field_name, Value::Object(reputation_data));
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                enrich_ips_recursively(val, blocklists);
            }
        }
        _ => {}
    }
}

// ==============================================================================
// --- File Reader Thread ---
// ==============================================================================
fn file_reader_thread(
    alert_file: &str,
    state_manager: &mut StateManager,
    sender: Sender<String>,
    blocklists: Arc<Mutex<HashMap<String, HashSet<String>>>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("File reader thread started.");
    let mut line_buffer = String::new();

    // Handle first run logic
    if state_manager.state.inode.is_none() && Path::new(alert_file).exists() {
        warn!("First run with existing log file. Starting from the END to process new entries only.");
        send_telegram_message("ℹ️ First run: Starting from end of log file, ignoring historical data.");
        let metadata = fs::metadata(alert_file)?;
        state_manager.state.inode = Some(metadata.ino());
        state_manager.state.offset = metadata.size();
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

        // Handle file rotation
        if current_inode.is_none() || metadata.ino() != current_inode.unwrap() {
            info!("New log file or rotation detected. Resetting to start of new file.");
            state_manager.state.inode = Some(metadata.ino());
            state_manager.state.offset = 0;
            offset = 0;
            line_buffer.clear();
        }

        // Handle file truncation
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
                if bytes_read == 0 {
                    break;
                }

                let line = String::from_utf8_lossy(&chunk);
                line_buffer.push_str(&line);

                if line.ends_with('\n') {
                    let line = line_buffer.trim().to_string();
                    line_buffer.clear();

                    if line.is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<Value>(&line) {
                        Ok(mut alert_json) => {
                            if ENABLE_IP_REPUTATION {
                                let blocklists = blocklists.lock().unwrap();
                                enrich_ips_recursively(&mut alert_json, &blocklists);
                            }
                            let enriched_line = serde_json::to_string(&alert_json)?;
                            if sender.send(enriched_line).is_err() {
                                break;
                            }
                            lines_queued += 1;
                        }
                        Err(e) => {
                            warn!("Skipping malformed JSON line: {}... Error: {}", &line[..200.min(line.len())], e);
                        }
                    }
                }
            }

            state_manager.state.offset = reader.seek(SeekFrom::Current(0))?;
            if lines_queued > 0 {
                info!("Queued {} new alert(s).", lines_queued);
            }
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
fn elk_sender_thread(
    receiver: Receiver<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("ELK sender thread started.");
    let addr: SocketAddr = format!("{}:{}", ELK_HOST, ELK_PORT).parse()?;
    let mut retry_delay = 5;
    let mut last_heartbeat = Instant::now();
    let mut lines_processed = 0;
    let mut stream = None;

    // Initial connection
    match TcpStream::connect_timeout(&addr, Duration::from_secs(SOCKET_TIMEOUT)) {
        Ok(s) => {
            info!("Successfully connected to ELK at {}:{}", ELK_HOST, ELK_PORT);
            send_telegram_message(&format!("✅ *Connection Established:* Successfully connected to ELK server at {}:{}.", ELK_HOST, ELK_PORT));
            stream = Some(s);
        }
        Err(e) => {
            error!("Initial connection failed: {}", e);
        }
    };

    while !shutdown.load(Ordering::Relaxed) || !receiver.is_empty() {
        // Check for heartbeat
        if last_heartbeat.elapsed().as_secs() >= HEARTBEAT_INTERVAL {
            let message = format!(
                "❤️ *Heartbeat:* Service is alive. {} alerts forwarded. Queue size: {}.",
                lines_processed,
                receiver.len()
            );
            send_telegram_message(&message);
            info!("{}", message);
            lines_processed = 0;
            last_heartbeat = Instant::now();
        }

        // Process messages
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(message) => {
                let data = message + "\n";
                let mut success = false;

                while !success && !shutdown.load(Ordering::Relaxed) {
                    if let Some(ref mut s) = stream {
                        match s.write_all(data.as_bytes()) {
                            Ok(_) => {
                                debug!("Successfully sent alert to ELK");
                                lines_processed += 1;
                                success = true;
                            }
                            Err(e) => {
                                error!("Send error: {}", e);
                                stream = None;
                            }
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
// --- Blocklist Updater Thread ---
// ==============================================================================
fn blocklist_updater_thread(
    blocklists: Arc<Mutex<HashMap<String, HashSet<String>>>>,
    shutdown: Arc<AtomicBool>,
) {
    info!("Blocklist updater thread started.");
    while !shutdown.load(Ordering::Relaxed) {
        info!("Starting IP reputation database update...");
        send_telegram_message("⏳ Starting IP reputation database update...");

        let new_blocklists = get_blocklists();
        {
            let mut global = blocklists.lock().unwrap();
            *global = new_blocklists;
        }

        info!(
            "IP reputation databases updated. {} lists loaded.",
            blocklists.lock().unwrap().len()
        );
        send_telegram_message(&format!(
            "✅ IP reputation databases updated. {} lists loaded.",
            blocklists.lock().unwrap().len()
        ));

        // Wait for refresh interval or shutdown
        for _ in 0..REFRESH_INTERVAL {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
    info!("Blocklist updater thread shutting down.");
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
            let msg = format!(
                "🚨 Initial connection test FAILED: {}\nCheck firewall/connectivity to {}:{}",
                e, ELK_HOST, ELK_PORT
            );
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
    // Setup logging
    let _log_file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
    {
        Ok(file) => {
            fern::Dispatch::new()
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
                .chain(io::stdout())
                .chain(file)
                .apply()?
        }
        Err(e) => {
            eprintln!("Failed to open log file: {}. Logging to stdout only.", e);
            fern::Dispatch::new()
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
                .chain(io::stdout())
                .apply()?
        }
    };

    info!("==============================================");
    info!("      Wazuh Alert Forwarder Service (Rust)    ");
    info!("==============================================");
    info!("Forwarding to ELK server at: {}:{}", ELK_HOST, ELK_PORT);

    // Test initial connection
    if let Err(e) = test_initial_connection() {
        warn!("Proceeding despite connection failure: {}", e);
    }

    // Setup shutdown flag
    let shutdown = Arc::new(AtomicBool::new(false));
    let _shutdown_clone = shutdown.clone();

    // Setup signal handling
    let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
    let signal_shutdown = shutdown.clone();
    thread::spawn(move || {
        for sig in signals.forever() {
            info!("Received signal {:?}", sig);
            signal_shutdown.store(true, Ordering::Relaxed);
        }
    });

    // Create message channel
    let (tx, rx) = bounded(MAX_QUEUE_SIZE);

    // Initialize state manager
    let mut state_manager = StateManager::new(STATE_FILE);
    if let Err(e) = state_manager.load() {
        error!("Failed to load state: {}", e);
    }

    // Initialize blocklists
    let blocklists = Arc::new(Mutex::new(HashMap::new()));
    if ENABLE_IP_REPUTATION {
        let blocklists_clone = blocklists.clone();
        let shutdown_clone = shutdown.clone();
        thread::spawn(move || {
            blocklist_updater_thread(blocklists_clone, shutdown_clone);
        });
    }

    // Start file reader thread
    let file_reader_shutdown = shutdown.clone();
    let file_reader_tx = tx.clone();
    let file_reader_blocklists = blocklists.clone();
    let file_reader_handle = thread::spawn(move || {
        if let Err(e) = file_reader_thread(
            WAZUH_ALERTS_FILE,
            &mut state_manager,
            file_reader_tx,
            file_reader_blocklists,
            file_reader_shutdown,
        ) {
            error!("File reader thread error: {}", e);
        }
    });

    // Start ELK sender thread
    let elk_sender_shutdown = shutdown.clone();
    let elk_sender_handle = thread::spawn(move || {
        if let Err(e) = elk_sender_thread(rx, elk_sender_shutdown) {
            error!("ELK sender thread error: {}", e);
        }
    });

    // Wait for threads to finish
    file_reader_handle.join().unwrap();
    elk_sender_handle.join().unwrap();

    // Final shutdown message
    info!("Service stopped gracefully.");
    send_telegram_message("✅ *Shutdown Complete:* Service stopped gracefully.");

    Ok(())
}