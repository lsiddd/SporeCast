# Wazuh Alert Forwarder Client

This directory contains a Python script and a `systemd` service file designed to run on a Wazuh server. The script's purpose is to reliably forward security alerts from Wazuh's `alerts.json` file to a remote Logstash instance.

---

## **Features**

*   **Persistent State**: Remembers the last read position in the log file. If the script is restarted, it resumes from where it left off, preventing duplicate or lost alerts.
*   **Log Rotation Handling**: Automatically detects when the `alerts.json` file is rotated and correctly starts reading from the beginning of the new file.
*   **In-Memory Queue**: Holds alerts in a memory queue if the connection to the ELK server is lost. This buffer prevents data loss during network interruptions.
*   **Automatic Reconnection**: If the connection fails, the script will automatically try to reconnect with an exponential backoff strategy.
*   **Real-time Monitoring (Optional)**: Can send status updates, connection/disconnection alerts, and hourly heartbeats to a specified Telegram chat for easy monitoring.
*   **Systemd Service**: Includes a `wazuh-forwarder.service` file for easy management as a background service on modern Linux systems.

---

## **Prerequisites**

*   Python 3.
*   The script must be run on a machine with read access to the Wazuh `alerts.json` file.
*   The `requests` Python library is required for Telegram notifications. Install it with:
    ```bash
    sudo pip3 install requests
    ```

---

## **Configuration**

All configuration is done by editing the constants at the top of the **`forwarder.py`** script.

*   `ELK_HOST`: The IP address or hostname of your server running the ELK stack.
*   `ELK_PORT`: The port on which your Logstash service is listening. The default is `5140`.
*   `WAZUH_ALERTS_FILE`: The full path to the Wazuh alerts file. The default `/var/ossec/logs/alerts/alerts.json` is standard.
*   `LOG_FILE`: Path where the forwarder will write its own operational logs. The user running the script needs write permission here.
*   `STATE_FILE`: Path to store the file's read position. The script needs write access to this location.

### Telegram Monitoring (Future)

To enable Telegram alerts:

1.  Set `ENABLE_TELEGRAM = True` in the script.
2.  Obtain a **Bot Token** from the BotFather on Telegram.
3.  Obtain your **Chat ID**. You can get this by sending a message to your new bot and then visiting `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`.
4.  Update the `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` variables in the script with your values.

---

## **Installation as a Systemd Service**

Using the provided `wazuh-forwarder.service` file is the recommended way to run the script robustly in the background.

1.  **Copy the Script**:
    Place the `forwarder.py` script in a suitable location. A common choice is `/opt/wazuh-forwarder/`.
    ```bash
    sudo mkdir -p /opt/wazuh-forwarder
    sudo cp forwarder.py /opt/wazuh-forwarder/
    ```

2.  **Copy the Service File**:
    Copy the `wazuh-forwarder.service` file to the systemd directory.
    ```bash
    sudo cp wazuh-forwarder.service /etc/systemd/system/
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

You can monitor the operation of the script in two ways:

1.  **Application Log File**:
    Tail the log file defined in the script's configuration to see detailed operational messages.
    ```bash
    tail -f /var/log/wazuh_forwarder.log
    ```

2.  **Systemd Journal**:
    View logs captured by `systemd`, which is especially useful for debugging startup issues.
    ```bash
    sudo journalctl -u wazuh-forwarder.service -f
    ```