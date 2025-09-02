#!/usr/bin/env python3
import json
import os
import socket
import time
import logging
import struct
import requests
import threading
import queue
import signal
import hashlib
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

# ==============================================================================
# --- Configuration ---
# (Configuration remains the same as the previous version)
# ==============================================================================
# -- Wazuh Settings --
WAZUH_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

# -- ELK Server Settings --
ELK_HOST = "68.168.216.248"
ELK_PORT = 5140
SOCKET_TIMEOUT = 10

# -- Script Internal Settings --
LOG_FILE = "/var/log/wazuh_forwarder.log"
STATE_FILE = "/var/lib/wazuh-forwarder/forwarder_state.json"
MAX_QUEUE_SIZE = 10000

# -- Telegram Bot Monitoring --
ENABLE_TELEGRAM = True
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
HEARTBEAT_INTERVAL = 3600

# -- IP Blocklist / Reputation Settings --
ENABLE_IP_REPUTATION = True
CACHE_DIR = "/var/lib/wazuh-forwarder/blocklist_cache"
REFRESH_INTERVAL = 86400
BLOCKLIST_URLS = [
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
    "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1"
]
# ==============================================================================

# --- Regex for finding IPv4 addresses ---
# This regex is designed to match IP addresses, using word boundaries (\b)
# to avoid matching IPs inside longer strings of digits.
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# --- Set up logging, globals, and Telegram (No changes from previous version) ---
logger = logging.getLogger("wazuh_forwarder")
logger.setLevel(logging.DEBUG)
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
except (PermissionError, IOError) as e:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.error(f"Permission denied for log file {LOG_FILE}, logging to console. Error: {e}")

shutdown_event = threading.Event()
g_blocklists = {}
g_blocklist_lock = threading.Lock()

def send_telegram_message(message):
    if not ENABLE_TELEGRAM or TELEGRAM_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        return
    api_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': f"[Wazuh-Forwarder]\n{message}", 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=10)
    except requests.RequestException as e:
        logger.error(f"Failed to send Telegram message: {e}")

# --- IP Blocklist Management (No changes from previous version) ---
def get_cache_filepath(url):
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()
    return os.path.join(CACHE_DIR, f"{url_hash}.json")
def is_cache_valid(filepath):
    if not os.path.exists(filepath): return False
    return (time.time() - os.path.getmtime(filepath)) < REFRESH_INTERVAL
def download_list(url, session):
    cache_filepath = get_cache_filepath(url)
    if is_cache_valid(cache_filepath):
        logger.debug(f"Using cached list for {url}")
        with open(cache_filepath, 'r') as f: return json.load(f), url
    try:
        response = session.get(url, timeout=20)
        response.raise_for_status()
        logger.info(f"Successfully downloaded new blocklist from {url}")
        ips = {ip.strip() for ip in response.text.splitlines() if ip.strip() and not ip.startswith(('#', ';', '/'))}
        with open(cache_filepath, 'w') as f: json.dump(list(ips), f)
        return ips, url
    except requests.RequestException as e:
        logger.error(f"Failed to download blocklist {url}: {e}")
        return [], url
def get_blocklists():
    os.makedirs(CACHE_DIR, exist_ok=True)
    blocklisted_ips = {}
    with requests.Session() as session, ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(download_list, url, session) for url in BLOCKLIST_URLS]
        for future in futures:
            ips, url = future.result()
            if ips: blocklisted_ips[url] = set(ips)
    return blocklisted_ips
def check_ip_reputation(ip_address, blocklists):
    found_in = []
    for url, ips in blocklists.items():
        if ip_address in ips: found_in.append(url)
    return found_in
class BlocklistUpdater(threading.Thread):
    def __init__(self):
        super().__init__()
        self.name = "BlocklistUpdaterThread"
    def run(self):
        logger.info("Blocklist updater thread started.")
        while not shutdown_event.is_set():
            logger.info("Starting IP reputation database update...")
            send_telegram_message("⏳ Starting IP reputation database update...")
            new_blocklists = get_blocklists()
            with g_blocklist_lock:
                global g_blocklists
                g_blocklists = new_blocklists
            logger.info(f"IP reputation databases updated. {len(g_blocklists)} lists loaded.")
            send_telegram_message(f"✅ IP reputation databases updated. {len(g_blocklists)} lists loaded.")
            shutdown_event.wait(REFRESH_INTERVAL)
        logger.info("Blocklist updater thread shutting down.")

# --- StateManager (No changes from previous version) ---
class StateManager:
    def __init__(self, state_file):
        self._state_file = state_file
        self._state = {'inode': None, 'offset': 0}
        os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
    def load(self):
        if not os.path.exists(self._state_file):
            logger.info("State file not found, will start reading from the beginning.")
            return self._state
        try:
            with open(self._state_file, 'r') as f: self._state = json.load(f)
            logger.info(f"Loaded state: Inode {self._state.get('inode')}, Offset {self._state.get('offset')}")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Could not load state file {self._state_file}, starting fresh: {e}")
        return self._state
    def save(self, inode, offset):
        if self._state.get('inode') == inode and self._state.get('offset') == offset: return
        self._state = {'inode': inode, 'offset': offset}
        try:
            with open(self._state_file, 'w') as f: json.dump(self._state, f)
            logger.debug(f"Saved state: Inode={inode}, Offset={offset}")
        except IOError as e:
            logger.error(f"Failed to save state to {self._state_file}: {e}")

# ==============================================================================
# --- FileReader with DYNAMIC IP detection ---
# ==============================================================================
class FileReader(threading.Thread):
    def __init__(self, alert_file, message_queue, state_manager):
        super().__init__()
        self.name = "FileReaderThread"
        self._alert_file = alert_file
        self._queue = message_queue
        self._state_manager = state_manager
        self._line_buffer = ""

    def _is_public_ip(self, ip_str):
        """Check if an IP is public using the ipaddress module."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_private and not ip.is_reserved and not ip.is_loopback
        except ValueError:
            return False # Not a valid IP address string

    def _find_and_enrich_ips_recursively(self, obj, blocklists):
        """
        Recursively traverse a dictionary or list, find all public IP addresses,
        check their reputation, and enrich the object in-place.
        """
        if isinstance(obj, dict):
            # Iterate over a copy of items to allow modification during iteration
            for key, value in list(obj.items()):
                if isinstance(value, str):
                    # Find all potential IPs in the string value
                    found_ips = set(IP_REGEX.findall(value))
                    if not found_ips:
                        continue

                    reputation_data = {}
                    for ip in found_ips:
                        if self._is_public_ip(ip):
                            found_in_lists = check_ip_reputation(ip, blocklists)
                            if found_in_lists:
                                logger.info(f"Found blocklisted IP {ip} in field '{key}'")
                                reputation_data[ip] = {
                                    "status": "blocklisted",
                                    "source_lists": found_in_lists
                                }
                    
                    if reputation_data:
                        # Add a new field for reputation, adjacent to the original
                        obj[f"{key}_reputation"] = reputation_data

                # If value is a dict or list, recurse into it
                elif isinstance(value, (dict, list)):
                    self._find_and_enrich_ips_recursively(value, blocklists)
        
        elif isinstance(obj, list):
            # If the object is a list, iterate and recurse into its items
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._find_and_enrich_ips_recursively(item, blocklists)

    def run(self):
        logger.info("File reader thread started.")
        state = self._state_manager.load()
        current_inode, offset = state.get('inode'), state.get('offset')

        while not shutdown_event.is_set():
            try:
                if not os.path.exists(self._alert_file):
                    shutdown_event.wait(15)
                    continue

                stat_info = os.stat(self._alert_file)
                if current_inode is None or stat_info.st_ino != current_inode:
                    logger.info(f"New log file or rotation detected. Resetting.")
                    current_inode, offset = stat_info.st_ino, 0
                    self._line_buffer = ""

                if stat_info.st_size < offset:
                    logger.warning(f"Log file truncated. Resetting offset.")
                    offset = 0
                    self._line_buffer = ""

                if offset < stat_info.st_size:
                    with open(self._alert_file, 'r', encoding='utf-8') as f:
                        f.seek(offset)
                        new_data = self._line_buffer + f.read()
                        if not new_data: continue

                        lines = new_data.split('\n')
                        self._line_buffer = lines.pop()

                        lines_queued = 0
                        for line in lines:
                            stripped_line = line.strip()
                            if not stripped_line: continue
                            
                            try:
                                alert_json = json.loads(stripped_line)
                                if ENABLE_IP_REPUTATION:
                                    # Get a thread-safe copy of the blocklists
                                    with g_blocklist_lock:
                                        blocklists_copy = g_blocklists
                                    
                                    # Enrich the alert_json object in-place
                                    self._find_and_enrich_ips_recursively(alert_json, blocklists_copy)
                                
                                self._queue.put(json.dumps(alert_json))
                                lines_queued += 1
                            except json.JSONDecodeError:
                                logger.warning(f"Skipping malformed JSON line: {stripped_line[:200]}")

                        if lines_queued > 0:
                            logger.info(f"Queued {lines_queued} new alert(s). Queue size: {self._queue.qsize()}")
                        
                        offset = f.tell() - len(self._line_buffer.encode('utf-8'))

                self._state_manager.save(current_inode, offset)
                shutdown_event.wait(0.5)

            except Exception as e:
                logger.exception(f"Critical error in file reader thread: {e}")
                shutdown_event.wait(10)

        logger.info(f"File reader thread shutting down. Final state saved.")
        self._state_manager.save(current_inode, offset)


# --- ELKSender (No changes from previous version) ---
class ELKSender(threading.Thread):
    def __init__(self, host, port, message_queue):
        super().__init__()
        self.name = "ELKSenderThread"
        self._host, self._port = host, port
        self._queue = message_queue
        self._sock = None
        self._lines_processed_period = 0
        self._last_heartbeat_time = time.time()

    def _connect_with_backoff(self):
        retry_delay = 5
        while not shutdown_event.is_set():
            try:
                if self._sock: self._sock.close()
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(SOCKET_TIMEOUT)
                self._sock.connect((self._host, self._port))
                logger.info(f"Successfully connected to ELK at {self._host}:{self._port}")
                send_telegram_message("✅ *Connection Established:* Successfully connected to ELK server.")
                return True
            except (socket.error, OSError) as e:
                logger.warning(f"Connection to ELK failed: {e}. Retrying in {retry_delay}s.")
                shutdown_event.wait(retry_delay)
                retry_delay = min(retry_delay * 2, 60)
        return False

    def _send(self, data_str):
        encoded_data = data_str.encode('utf-8') + b'\n'
        self._sock.sendall(encoded_data)

    def run(self):
        logger.info("ELK sender thread started.")
        while not shutdown_event.is_set() or not self._queue.empty():
            try:
                message = self._queue.get(timeout=1)
            except queue.Empty:
                self._check_heartbeat()
                continue

            sent = False
            while not sent and not shutdown_event.is_set():
                try:
                    if self._sock is None:
                        if not self._connect_with_backoff(): break
                    self._send(message)
                    logger.debug(f"Successfully sent alert to ELK: {message[:100]}...")
                    self._lines_processed_period += 1
                    self._queue.task_done()
                    sent = True
                except (socket.error, OSError) as e:
                    logger.error(f"Send error to {self._host}:{self._port}: {e}. Marking as disconnected.")
                    send_telegram_message(f"❌ *Connection Lost:* Failed to send data. Will retry automatically.")
                    if self._sock: self._sock.close()
                    self._sock = None

            if not sent:
                logger.warning(f"Could not send message due to shutdown. Re-queueing.")
                self._queue.put(message)
                break
            self._check_heartbeat()

        if self._sock: self._sock.close()
        logger.info("ELK sender thread shutting down.")

    def _check_heartbeat(self):
        if time.time() - self._last_heartbeat_time > HEARTBEAT_INTERVAL:
            q_size = self._queue.qsize()
            message = f"❤️ *Heartbeat:* Service is alive. {self._lines_processed_period} alerts forwarded. Queue size: {q_size}."
            send_telegram_message(message)
            logger.info(message)
            self._lines_processed_period = 0
            self._last_heartbeat_time = time.time()

# --- Main Execution & Signal Handling (No changes from previous version) ---
def main():
    logger.info("==============================================")
    logger.info("      Wazuh Alert Forwarder Service")
    logger.info("==============================================")
    logger.info(f"Monitoring Wazuh alerts file: {WAZUH_ALERTS_FILE}")
    logger.info(f"Forwarding to ELK server at: {ELK_HOST}:{ELK_PORT}")
    logger.info(f"IP Reputation checking enabled: {ENABLE_IP_REPUTATION} (Dynamic Scan)")
    logger.info("----------------------------------------------")
    send_telegram_message("🚀 Wazuh Forwarder is starting up...")
    message_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
    state_manager = StateManager(STATE_FILE)
    threads = [
        FileReader(WAZUH_ALERTS_FILE, message_queue, state_manager),
        ELKSender(ELK_HOST, ELK_PORT, message_queue)
    ]
    if ENABLE_IP_REPUTATION:
        threads.append(BlocklistUpdater())
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        try:
            [t.join(timeout=0.5) for t in threads]
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)
    logger.info("All threads have completed.")
    remaining_items = message_queue.qsize()
    if remaining_items > 0:
        logger.warning(f"{remaining_items} items remained in queue and were not sent.")
        send_telegram_message(f"⚠️ *Shutdown Complete:* Service stopped with {remaining_items} items unsent.")
    else:
        logger.info("Service stopped gracefully with an empty queue.")
        send_telegram_message("✅ *Shutdown Complete:* Service stopped gracefully.")
def signal_handler(signum, frame):
    if shutdown_event.is_set():
        logger.warning("Shutdown already in progress.")
        return
    logger.warning(f"Shutdown signal {signum} received. Draining queue before exiting...")
    send_telegram_message("🛑 Shutdown Signal Received... Draining queue and saving state.")
    shutdown_event.set()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        main()
    except Exception as e:
        logger.exception(f"A critical unhandled exception occurred in main: {e}")
        send_telegram_message(f"💥 *CRITICAL FAILURE:* The service has crashed: {e}")