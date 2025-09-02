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
from logging.handlers import RotatingFileHandler

# ==============================================================================
# --- Configuration ---
# ==============================================================================
# -- Wazuh Settings --
WAZUH_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

# -- ELK Server Settings --
ELK_HOST = "68.168.216.248"
ELK_PORT = 5140
SOCKET_TIMEOUT = 10  # Seconds to wait for a connection or send operation

# -- Script Internal Settings --
LOG_FILE = "/var/log/wazuh_forwarder.log"
# This file stores the last read position to resume after restarts.
STATE_FILE = "/var/lib/wazuh-forwarder/forwarder_state.json"
MAX_QUEUE_SIZE = 10000 # Max number of alerts to hold in memory if ELK is down.

# -- Telegram Bot Monitoring --
ENABLE_TELEGRAM = True
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"  # <-- SET YOUR BOT TOKEN
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"    # <-- SET YOUR CHAT ID
HEARTBEAT_INTERVAL = 3600  # Send a "still alive" message every hour (in seconds)
# ==============================================================================

# --- Set up logging ---
# Added DEBUG level for more granular control
logger = logging.getLogger("wazuh_forwarder")
logger.setLevel(logging.DEBUG) # Set to INFO for production, DEBUG for troubleshooting
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

# --- Global Events for Thread Coordination ---
shutdown_event = threading.Event()

# --- Telegram Notifier ---
def send_telegram_message(message):
    if not ENABLE_TELEGRAM or TELEGRAM_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        return
    api_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': f"[Wazuh-Forwarder]\n{message}", 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=10)
    except requests.RequestException as e:
        logger.error(f"Failed to send Telegram message: {e}")

# --- State Manager: Handles saving and loading the file read position ---
class StateManager:
    def __init__(self, state_file):
        self._state_file = state_file
        self._state = {'inode': None, 'offset': 0}
        os.makedirs(os.path.dirname(self._state_file), exist_ok=True)

    def load(self):
        if not os.path.exists(self._state_file):
            logger.info("State file not found, will start reading from the beginning of the log file.")
            return self._state
        try:
            with open(self._state_file, 'r') as f:
                self._state = json.load(f)
                logger.info(f"Loaded previous state: Inode {self._state.get('inode')}, Offset {self._state.get('offset')}")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Could not load state file {self._state_file}, starting fresh: {e}")
        return self._state

    def save(self, inode, offset):
        # Only write to disk if state has actually changed
        if self._state.get('inode') == inode and self._state.get('offset') == offset:
            return

        self._state = {'inode': inode, 'offset': offset}
        try:
            with open(self._state_file, 'w') as f:
                json.dump(self._state, f)
            logger.debug(f"Saved state: Inode={inode}, Offset={offset}")
        except IOError as e:
            logger.error(f"Failed to save state to {self._state_file}: {e}")

# --- File Reader Thread ---
class FileReader(threading.Thread):
    """
    Reads new lines from the alert file. It is designed to be robust against
    file rotations and incomplete lines being written. It works by buffering
    the last line of any read and prepending it to the next, ensuring only
    complete lines (terminated by a newline) are processed.
    """
    def __init__(self, alert_file, message_queue, state_manager):
        super().__init__()
        self.name = "FileReaderThread"
        self._alert_file = alert_file
        self._queue = message_queue
        self._state_manager = state_manager
        self._line_buffer = ""  # Buffer for any incomplete line from the last read

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
                    logger.info(f"New log file or rotation detected. Old inode: {current_inode}, New inode: {stat_info.st_ino}. Resetting to start of file.")
                    current_inode, offset = stat_info.st_ino, 0
                    self._line_buffer = "" # Reset buffer on rotation

                if stat_info.st_size < offset:
                    logger.warning(f"Log file appears to have been truncated. Resetting offset from {offset} to 0.")
                    offset = 0
                    self._line_buffer = "" # Reset buffer on truncation

                if offset < stat_info.st_size:
                    with open(self._alert_file, 'r', encoding='utf-8') as f:
                        f.seek(offset)
                        new_data = self._line_buffer + f.read()

                        if not new_data:
                            continue

                        lines = new_data.split('\n')
                        # The last element is either an empty string (if file ends with \n)
                        # or an incomplete line. In either case, we hold it back.
                        self._line_buffer = lines.pop()

                        lines_queued = 0
                        for line in lines:
                            stripped_line = line.strip()
                            if stripped_line:
                                try:
                                    # Final validation that it's a valid JSON object
                                    json.loads(stripped_line)
                                    self._queue.put(stripped_line)
                                    lines_queued += 1
                                except json.JSONDecodeError:
                                    logger.warning(f"Skipping malformed/corrupted JSON line: {stripped_line[:200]}")

                        if lines_queued > 0:
                            logger.info(f"Queued {lines_queued} new alert(s). Current queue size: {self._queue.qsize()}")

                        if self._line_buffer:
                            logger.debug(f"Holding back incomplete line fragment: '{self._line_buffer}'")

                        # The new offset for the next read is where the incomplete line begins.
                        offset = f.tell() - len(self._line_buffer.encode('utf-8'))

                self._state_manager.save(current_inode, offset)
                shutdown_event.wait(0.5)  # Wait for new log entries

            except Exception as e:
                logger.exception(f"Critical error in file reader thread: {e}")
                shutdown_event.wait(10)

        logger.info(f"File reader thread shutting down. Final position: Inode {current_inode}, Offset {offset}")
        self._state_manager.save(current_inode, offset) # Final save on shutdown

# --- ELK Sender Thread ---
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
                retry_delay = min(retry_delay * 2, 60) # Exponential backoff up to 1 minute
        return False

    def _send(self, data_str):
        # PREVIOUSLY: It sent a 4-byte length prefix.
        # encoded_data = data_str.encode('utf-8')
        # self._sock.sendall(struct.pack('!I', len(encoded_data)) + encoded_data)

        # NEW and CORRECTED: Send the data with a newline terminator.
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
                        if not self._connect_with_backoff():
                            break # Shutdown signaled
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

            if not sent: # Happens if shutdown was signaled mid-send attempt
                logger.warning(f"Could not send message due to shutdown. Re-queueing.")
                self._queue.put(message)
                break

            self._check_heartbeat()

        if self._sock: self._sock.close()
        logger.info("ELK sender thread shutting down.")

    def _check_heartbeat(self):
        if time.time() - self._last_heartbeat_time > HEARTBEAT_INTERVAL:
            q_size = self._queue.qsize()
            message = f"❤️ *Heartbeat:* Service is alive. {self._lines_processed_period} alerts forwarded in the last period. Queue size: {q_size}."
            send_telegram_message(message)
            logger.info(message)
            self._lines_processed_period = 0
            self._last_heartbeat_time = time.time()

# --- Main Execution & Signal Handling ---
def main():
    logger.info("==============================================")
    logger.info("      Wazuh Alert Forwarder Service")
    logger.info("==============================================")
    logger.info(f"Monitoring Wazuh alerts file: {WAZUH_ALERTS_FILE}")
    logger.info(f"Forwarding to ELK server at: {ELK_HOST}:{ELK_PORT}")
    logger.info(f"Logging to: {LOG_FILE}")
    logger.info(f"State persistence file: {STATE_FILE}")
    logger.info(f"Telegram monitoring enabled: {ENABLE_TELEGRAM}")
    logger.info("----------------------------------------------")

    send_telegram_message("🚀 Wazuh Forwarder is starting up...")

    message_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
    state_manager = StateManager(STATE_FILE)

    reader = FileReader(WAZUH_ALERTS_FILE, message_queue, state_manager)
    sender = ELKSender(ELK_HOST, ELK_PORT, message_queue)

    reader.start()
    sender.start()

    while reader.is_alive() and sender.is_alive():
        reader.join(timeout=0.5)
        sender.join(timeout=0.5)

    logger.info("All threads have completed.")
    remaining_items = message_queue.qsize()
    if remaining_items > 0:
        logger.warning(f"{remaining_items} items remained in queue and were not sent.")
        send_telegram_message(f"⚠️ *Shutdown Complete:* Service stopped with {remaining_items} items left unsent in the queue.")
    else:
        logger.info("Service stopped gracefully with an empty queue.")
        send_telegram_message("✅ *Shutdown Complete:* Service stopped gracefully.")

def signal_handler(signum, frame):
    """Gracefully handles shutdown signals from systemd or Ctrl+C."""
    if shutdown_event.is_set():
        logger.warning("Shutdown already in progress.")
        return
    logger.warning(f"Shutdown signal {signum} received. Draining queue before exiting...")
    send_telegram_message("🛑 Shutdown Signal Received... Draining queue before exiting.")
    shutdown_event.set()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        main()
    except Exception as e:
        logger.exception(f"A critical unhandled exception occurred in main: {e}")
        send_telegram_message(f"💥 *CRITICAL FAILURE:* The service has crashed: {e}")
