# Wazuh Alert Forwarder (Rust Edition)

This directory contains a high-performance, self-contained Wazuh alert forwarder written in Rust. It replaces the previous Python version, offering greater robustness, speed, and new features. The application is designed to run as a service on a Wazuh server, reliably forwarding security alerts from Wazuh's `alerts.json` file to a remote Logstash instance.

---

## **Key Features**

This Rust version inherits the best features of the original and adds significant improvements:

*   **High Performance & Low Overhead**: As a compiled Rust application, it runs with significantly better performance and lower memory usage compared to an interpreted script.
*   **IP Reputation Enrichment**: A major new feature that automatically checks source and destination IP addresses within alerts against a configurable list of blocklist providers. Findings are appended to the alert data.
*   **Concurrent Architecture**: A multi-threaded design separates file reading from network sending. An in-memory queue acts as a buffer, ensuring that network latency or downtime does not interrupt the reading of alerts from the disk.
*   **Persistent State**: Remembers the last read position in the log file. If the service is restarted, it resumes from where it left off, preventing duplicate or lost alerts.
*   **Robust Log Rotation Handling**: Automatically detects when the `alerts.json` file is rotated and correctly starts reading from the beginning of the new file.
*   **Automatic Reconnection**: If the connection to the Logstash server fails, the script will automatically attempt to reconnect with an exponential backoff strategy.
*   **Self-Contained Binary**: The compiled application has no external dependencies like a Python interpreter.
*   **Optional Real-time Monitoring**: Can send status updates, connection/disconnection alerts, and hourly heartbeats to a specified Telegram chat for easy monitoring.
*   **Systemd Service**: Includes a `wazuh-forwarder.service` file for easy management as a background service on modern Linux systems.

---

## **Prerequisites**

*   The service must be run on a machine with read access to the Wazuh `alerts.json` file.
*   **Rust toolchain** (including `cargo`) is required for compiling the application from the source.

---

## **Compilation**

Before you can run the forwarder, you must compile it.

1.  **Clone the Repository**:
    If you haven't already, clone the project to your Wazuh server.

2.  **Navigate to the Source Directory**:
    ```bash
    cd wazuh-forwarder
    ```

3.  **Build the Release Binary**:
    This command compiles the code in release mode, which is optimized for performance.
    ```bash
    cargo build --release
    ```

4.  **Locate the Binary**:
    The compiled binary will be located at `target/release/wazuh_forwarder`.

---

## **Configuration**

All configuration is managed via constants in the `wazuh-forwarder/src/main.rs` file. After modifying any of these values, **you must recompile the application** using the `cargo build --release` command.

| Constant                             | Description                                                                                             | Default Value                                |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **`ELK_HOST`**                       | The IP address or hostname of your Logstash server.                                                     | `"68.168.216.248"`                           |
| **`ELK_PORT`**                       | The port on which your Logstash service is listening.                                                   | `5140`                                       |
| **`WAZUH_ALERTS_FILE`**              | The full path to the Wazuh alerts file.                                                                 | `"/var/ossec/logs/alerts/alerts.json"`       |
| **`LOG_FILE`**                       | Path where the forwarder will write its own operational logs.                                           | `"/var/log/wazuh_forwarder.log"`             |
| **`STATE_FILE`**                     | Path to store the file's read position (inode and offset).                                              | `"/var/lib/wazuh-forwarder/forwarder_state.json"` |
| **`PROCESS_FROM_BEGINNING_ON_FIRST_RUN`** | If `true`, the forwarder will process all existing alerts in the file on its very first run. If `false`, it will start from the end of the file. | `true`                                       |
| **`ENABLE_TELEGRAM`**                | Set to `true` to enable Telegram status notifications.                                                  | `true`                                       |
| **`TELEGRAM_TOKEN`**                 | Your Telegram Bot Token from BotFather.                                                                 | `"YOUR_TELEGRAM_BOT_TOKEN"`                  |
| **`TELEGRAM_CHAT_ID`**               | The chat ID to which the bot should send messages.                                                      | `"YOUR_TELEGRAM_CHAT_ID"`                    |
| **`HEARTBEAT_INTERVAL`**             | How often (in seconds) to send a heartbeat message to Telegram.                                         | `3600` (1 hour)                              |
| **`ENABLE_IP_REPUTATION`**           | Set to `true` to enable the IP blocklist enrichment feature.                                            | `true`                                       |
| **`BLOCKLIST_URLS`**                 | An array of URLs pointing to IP blocklists (in plaintext format).                                       | (Array of 12 URLs)                           |
| **`CACHE_DIR`**                      | Directory to store cached copies of the downloaded blocklists.                                          | `"/var/lib/wazuh-forwarder/blocklist_cache"` |
| **`REFRESH_INTERVAL`**               | How often (in seconds) the IP blocklists are re-downloaded.                                             | `86400` (24 hours)                           |

---

## **Installation as a Systemd Service**

Using the provided service file is the recommended way to run the forwarder robustly in the background.

1.  **Copy the Compiled Binary**:
    After compiling, copy the binary to a standard location.
    ```bash
    sudo cp wazuh-forwarder/target/release/wazuh_forwarder /usr/local/bin/
    ```

2.  **Create the Service File**:
    Create a new service file in the systemd directory.
    ```bash
    sudo nano /etc/systemd/system/wazuh-forwarder.service
    ```
    Paste the following content into the file. This configuration is tailored for the Rust application.

    ```ini
    [Unit]
    Description=Wazuh Alert Forwarder (Rust) to ELK
    After=network-online.target
    Wants=network-online.target

    [Service]
    # Use 'root' or a user with correct permissions for wazuh logs and its own state/log files.
    User=root
    Group=root

    # Path to the compiled binary.
    ExecStart=/usr/local/bin/wazuh_forwarder

    # The Rust application handles its own graceful shutdown on SIGINT/SIGTERM.
    KillSignal=SIGINT

    # Restart the service on any non-successful exit code.
    Restart=on-failure
    RestartSec=10

    # Output application logs to the systemd journal.
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
    ```

3.  **Reload Systemd and Start the Service**:
    These commands will reload the systemd manager, enable the service to start automatically on boot, and start it immediately.
    ```bash
    # Reload the systemd manager configuration
    sudo systemctl daemon-reload

    # Enable the service to start on boot
    sudo systemctl enable wazuh-forwarder.service

    # Start the service now
    sudo systemctl start wazuh-forwarder.service
    ```

---

## **Managing the Service**

You can now manage the forwarder using standard `systemctl` commands:

*   **Check Status**: `sudo systemctl status wazuh-forwarder.service`
*   **Stop Service**: `sudo systemctl stop wazuh-forwarder.service`
*   **Restart Service**: `sudo systemctl restart wazuh-forwarder.service`

## **Viewing Logs**

You can monitor the operation of the application in two ways:

1.  **Application Log File**:
    Tail the log file defined in the configuration to see detailed operational messages, including connections, disconnections, and queued alerts.
    ```bash
    tail -f /var/log/wazuh_forwarder.log
    ```

2.  **Systemd Journal**:
    View logs captured by `systemd`, which is especially useful for debugging startup issues or crashes.
    ```bash
    sudo journalctl -u wazuh-forwarder.service -f
    ```