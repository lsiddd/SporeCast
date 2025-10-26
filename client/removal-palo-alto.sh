#!/bin/bash

# Palo Alto Forwarder Removal Script
# This script removes all components installed by the deployment script

# set -e

# --- Configuration ---
APP_NAME="palo_alto_forwarder"
SERVICE_NAME="palo-alto-forwarder"
SOURCE_SERVICE_FILE_NAME="palo-alto-forwarder.service"
CONFIG_FILE="forwarder-config.toml"

# System paths (same as deployment script)
TARGET_BIN_PATH="/usr/local/bin/${APP_NAME}"
TARGET_SERVICE_PATH="/etc/systemd/system/${SOURCE_SERVICE_FILE_NAME}"
TARGET_CONFIG_PATH="/etc/forwarder/${CONFIG_FILE}"

# Application paths
DEFAULT_LOG_FILE="/var/log/palo_alto_forwarder.log"
DEFAULT_STATE_DIR="/var/lib/palo-alto-forwarder"
DEFAULT_CACHE_DIR="${DEFAULT_STATE_DIR}/threat_intel_cache"

# --- Pre-flight Checks ---
echo "--- Palo Alto Forwarder Removal Script ---"
echo "This script will remove all components installed by the deployment script."
echo

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

# Confirmation prompt
echo "WARNING: This will permanently remove:"
echo "  - Service: ${SERVICE_NAME}"
echo "  - Binary: ${TARGET_BIN_PATH}"
echo "  - Service file: ${TARGET_SERVICE_PATH}"
echo "  - Configuration: ${TARGET_CONFIG_PATH}"
echo "  - Log file: ${DEFAULT_LOG_FILE}"
echo "  - State directory: ${DEFAULT_STATE_DIR}"
echo

read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Removal cancelled."
    exit 0
fi

echo "--- Starting Removal Process ---"
echo

# --- Service Shutdown and Removal ---
echo "--- Stopping and Disabling Service ---"

# Check if service exists and is active
if systemctl list-units --full -all | grep -Fq "${SERVICE_NAME}.service"; then
    echo "Service found. Stopping ${SERVICE_NAME}..."
    
    # Stop the service
    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        systemctl stop "${SERVICE_NAME}.service"
        echo "Service stopped."
    else
        echo "Service was not running."
    fi
    
    # Disable the service
    if systemctl is-enabled --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}.service"
        echo "Service disabled."
    else
        echo "Service was not enabled."
    fi
else
    echo "Service ${SERVICE_NAME} not found."
fi
echo

# --- File and Directory Removal ---
echo "--- Removing Files and Directories ---"

# Remove the systemd service file
if [ -f "${TARGET_SERVICE_PATH}" ]; then
    echo "Removing service file: ${TARGET_SERVICE_PATH}"
    rm -f "${TARGET_SERVICE_PATH}"
    echo "Service file removed."
else
    echo "Service file not found: ${TARGET_SERVICE_PATH}"
fi

# Remove the binary
if [ -f "${TARGET_BIN_PATH}" ]; then
    echo "Removing binary: ${TARGET_BIN_PATH}"
    rm -f "${TARGET_BIN_PATH}"
    echo "Binary removed."
else
    echo "Binary not found: ${TARGET_BIN_PATH}"
fi

# Remove the configuration file
if [ -f "${TARGET_CONFIG_PATH}" ]; then
    echo "Removing configuration file: ${TARGET_CONFIG_PATH}"
    rm -f "${TARGET_CONFIG_PATH}"
    echo "Configuration file removed."
else
    echo "Configuration file not found: ${TARGET_CONFIG_PATH}"
fi

# Remove the log file
if [ -f "${DEFAULT_LOG_FILE}" ]; then
    echo "Removing log file: ${DEFAULT_LOG_FILE}"
    rm -f "${DEFAULT_LOG_FILE}"
    echo "Log file removed."
else
    echo "Log file not found: ${DEFAULT_LOG_FILE}"
fi

# Remove the state directory and cache
if [ -d "${DEFAULT_STATE_DIR}" ]; then
    echo "Removing state directory: ${DEFAULT_STATE_DIR}"
    rm -rf "${DEFAULT_STATE_DIR}"
    echo "State directory removed."
else
    echo "State directory not found: ${DEFAULT_STATE_DIR}"
fi

# Remove /etc/forwarder directory if it's empty
if [ -d "/etc/forwarder" ]; then
    if [ -z "$(ls -A /etc/forwarder)" ]; then
        echo "Removing empty directory: /etc/forwarder"
        rmdir "/etc/forwarder"
        echo "Empty forwarder config directory removed."
    else
        echo "Directory /etc/forwarder contains other files, leaving it intact."
    fi
fi

echo

# --- Systemd Reload ---
echo "--- Reloading systemd ---"
systemctl daemon-reload
echo "Systemd daemon reloaded."
echo

# --- Cleanup Verification ---
echo "--- Verifying Removal ---"

REMOVAL_COMPLETE=true

# Check if service still exists
if systemctl list-unit-files | grep -q "${SERVICE_NAME}"; then
    echo "WARNING: Service ${SERVICE_NAME} still appears in systemctl list-unit-files"
    REMOVAL_COMPLETE=false
fi

# Check for remaining files
for path in "${TARGET_BIN_PATH}" "${TARGET_SERVICE_PATH}" "${TARGET_CONFIG_PATH}" "${DEFAULT_LOG_FILE}" "${DEFAULT_STATE_DIR}"; do
    if [ -e "${path}" ]; then
        echo "WARNING: ${path} still exists"
        REMOVAL_COMPLETE=false
    fi
done

if [ "$REMOVAL_COMPLETE" = true ]; then
    echo "✓ All components successfully removed."
else
    echo "⚠ Some components may still exist. Please check the warnings above."
fi

echo

# --- Final Status ---
echo "--- Removal Complete ---"
echo "The Palo Alto Forwarder has been uninstalled from the system."
echo
echo "If you need to reinstall, run the deployment script again."
echo "If you encounter any issues, you may need to manually remove remaining files."
echo

# --- Optional: Show remaining processes (if any) ---
echo "Checking for any remaining processes..."
if pgrep -f "${APP_NAME}" > /dev/null; then
    echo "WARNING: Found running processes related to ${APP_NAME}:"
    pgrep -af "${APP_NAME}"
    echo "You may need to manually kill these processes."
else
    echo "✓ No remaining processes found."
fi

echo
echo "Removal script completed."
