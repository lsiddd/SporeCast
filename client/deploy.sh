#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# The binary name is derived from the 'name' field in Cargo.toml.
APP_NAME="wazuh_forwarder"
# The service name is taken from the .service file in the project root.
SERVICE_NAME="fortigate-forwarder"
# The full name of the service file to be copied.
SOURCE_SERVICE_FILE_NAME="${SERVICE_NAME}.service"

# Get the absolute path of the script's directory.
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RUST_SRC_DIR="${PROJECT_ROOT}/wazuh-forwarder"

# System paths
TARGET_BIN_PATH="/usr/local/bin/${APP_NAME}"
TARGET_SERVICE_PATH="/etc/systemd/system/${SOURCE_SERVICE_FILE_NAME}"

# Application-specific paths (from src/main.rs)
LOG_FILE_PATH="/var/log/fortigate_forwarder.log"
STATE_DIR="/var/lib/fortigate-forwarder"
CACHE_DIR="${STATE_DIR}/threat_intel_cache"

# --- Pre-flight Checks ---
echo "--- Running Pre-flight Checks ---"
# Check for root privileges.
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

# Check for the Rust compiler (cargo).
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust toolchain (cargo) could not be found."
    echo "Please install Rust by following the instructions at https://rustup.rs/"
    exit 1
fi

# Check if the service file exists.
if [ ! -f "${PROJECT_ROOT}/${SOURCE_SERVICE_FILE_NAME}" ]; then
    echo "Error: Service file not found at ${PROJECT_ROOT}/${SOURCE_SERVICE_FILE_NAME}"
    exit 1
fi
echo "Checks passed successfully."
echo

# --- Compilation ---
echo "--- Compiling the Rust application ---"
echo "Navigating to ${RUST_SRC_DIR}"
cd "${RUST_SRC_DIR}"
echo "Running 'cargo build --release' (this may take a few minutes)..."
cargo build --release
echo "Compilation successful."
echo

# Return to project root.
cd "${PROJECT_ROOT}"

# --- Service Shutdown (for upgrades) ---
if systemctl list-units --full -all | grep -Fq "${SERVICE_NAME}.service"; then
    echo "--- Service already exists. Stopping for update. ---"
    systemctl stop "${SERVICE_NAME}.service" || true # Continue if it was not running.
    echo "Service stopped."
else
    echo "--- First-time setup. Service does not exist yet. ---"
fi
echo

# --- Installation & Configuration ---
echo "--- Installing Files and Configuring System ---"
# Create necessary directories as defined in the Rust application.
echo "Creating required directories..."
mkdir -p "${CACHE_DIR}"
echo "Created ${CACHE_DIR}"

# Create the log file to ensure it exists with correct permissions.
echo "Ensuring log file exists..."
touch "${LOG_FILE_PATH}"
echo "Created ${LOG_FILE_PATH}"

# Set correct ownership for all application-managed files/directories.
echo "Setting ownership for app directories and files..."
chown -R root:root "${STATE_DIR}" "${LOG_FILE_PATH}"
echo "Ownership set to root:root."

# Copy the compiled binary to the system path.
echo "Copying compiled binary to ${TARGET_BIN_PATH}..."
cp "${RUST_SRC_DIR}/target/release/${APP_NAME}" "${TARGET_BIN_PATH}"
echo "Binary copied."

# Copy the systemd service file.
echo "Copying service file to ${TARGET_SERVICE_PATH}..."
cp "${PROJECT_ROOT}/${SOURCE_SERVICE_FILE_NAME}" "${TARGET_SERVICE_PATH}"
echo "Service file copied."
echo

# --- Service Activation ---
echo "--- Reloading systemd and Starting the Service ---"
# Reload systemd to recognize the new/changed service file.
systemctl daemon-reload
echo "Systemd daemon reloaded."

# Enable the service to ensure it starts on boot.
systemctl enable "${SERVICE_NAME}.service"
echo "Service '${SERVICE_NAME}' has been enabled."

# Start the service immediately.
systemctl start "${SERVICE_NAME}.service"
echo "Service '${SERVICE_NAME}' has been started."
echo

# --- Final Status ---
echo "--- Deployment Complete ---"
echo "The ${SERVICE_NAME} service is now active."
echo "To check its status, run: systemctl status ${SERVICE_NAME}.service"
echo "To view live logs, run: journalctl -u ${SERVICE_NAME}.service -f"