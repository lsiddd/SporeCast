#!/bin/bash

# Palo Alto Forwarder Deployment Script
# This script deploys the Palo Alto log forwarder with configurable settings

set -e

# --- Configuration ---
APP_NAME="palo_alto_forwarder"
SERVICE_NAME="palo-alto-forwarder"
SOURCE_SERVICE_FILE_NAME="palo-alto-forwarder.service"
CONFIG_FILE="forwarder-config.toml"

# Get the absolute path of the script's directory
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RUST_SRC_DIR="${PROJECT_ROOT}/wazuh-forwarder"

# System paths
TARGET_BIN_PATH="/usr/local/bin/${APP_NAME}"
TARGET_SERVICE_PATH="/etc/systemd/system/${SOURCE_SERVICE_FILE_NAME}"
TARGET_CONFIG_PATH="/etc/forwarder/${CONFIG_FILE}"

# Default application paths (can be overridden by config)
DEFAULT_LOG_FILE="/var/log/palo_alto_forwarder.log"
DEFAULT_STATE_DIR="/var/lib/palo-alto-forwarder"
DEFAULT_CACHE_DIR="${DEFAULT_STATE_DIR}/threat_intel_cache"

# --- Pre-flight Checks ---
echo "--- Running Pre-flight Checks for Palo Alto Forwarder ---"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

# Check for Rust compiler (cargo)
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust toolchain (cargo) could not be found."
    echo "Please install Rust by following the instructions at https://rustup.rs/"
    exit 1
fi

# Check if the configuration file exists
if [ ! -f "${PROJECT_ROOT}/${CONFIG_FILE}" ]; then
    echo "Error: Configuration file not found at ${PROJECT_ROOT}/${CONFIG_FILE}"
    echo "Please create the configuration file before running the deployment."
    exit 1
fi

# Validate that the config file specifies Palo Alto forwarder
if ! grep -q 'type = "palo_alto"' "${PROJECT_ROOT}/${CONFIG_FILE}"; then
    echo "Warning: Configuration file doesn't specify 'palo_alto' forwarder type."
    echo "Make sure forwarder.type = \"palo_alto\" in your configuration file."
fi

echo "Checks passed successfully."
echo

# --- Service File Creation ---
echo "--- Creating Palo Alto Forwarder Service File ---"

# Create the service file content
cat > "${PROJECT_ROOT}/${SOURCE_SERVICE_FILE_NAME}" << EOF
[Unit]
Description=Palo Alto Log Forwarder
Documentation=https://github.com/your-org/palo-alto-forwarder
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${TARGET_BIN_PATH} --config ${TARGET_CONFIG_PATH}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=palo-alto-forwarder

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log /var/lib/palo-alto-forwarder /tmp

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

echo "Service file created at ${PROJECT_ROOT}/${SOURCE_SERVICE_FILE_NAME}"
echo

# --- Compilation ---
echo "--- Compiling the Palo Alto Forwarder ---"
echo "Navigating to ${RUST_SRC_DIR}"
cd "${RUST_SRC_DIR}"
echo "Running 'cargo build --release --bin ${APP_NAME}' (this may take a few minutes)..."
cargo build --release --bin "${APP_NAME}"
echo "Compilation successful."
echo

# Return to project root
cd "${PROJECT_ROOT}"

# --- Service Shutdown (for upgrades) ---
if systemctl list-units --full -all | grep -Fq "${SERVICE_NAME}.service"; then
    echo "--- Service already exists. Stopping for update. ---"
    systemctl stop "${SERVICE_NAME}.service" || true
    echo "Service stopped."
else
    echo "--- First-time setup. Service does not exist yet. ---"
fi
echo

# --- Installation & Configuration ---
echo "--- Installing Files and Configuring System ---"

# Create necessary directories
echo "Creating required directories..."
mkdir -p "${DEFAULT_STATE_DIR}"
mkdir -p "${DEFAULT_CACHE_DIR}"
mkdir -p "/etc/forwarder"
echo "Created application directories"

# Create the log file
echo "Ensuring log file exists..."
touch "${DEFAULT_LOG_FILE}"
echo "Created ${DEFAULT_LOG_FILE}"

# Set correct ownership
echo "Setting ownership for app directories and files..."
chown -R root:root "${DEFAULT_STATE_DIR}" "${DEFAULT_LOG_FILE}"
chmod -R 755 "${DEFAULT_STATE_DIR}"
chmod 644 "${DEFAULT_LOG_FILE}"
echo "Ownership and permissions set."

# Copy the configuration file
echo "Copying configuration file to ${TARGET_CONFIG_PATH}..."
cp "${PROJECT_ROOT}/${CONFIG_FILE}" "${TARGET_CONFIG_PATH}"
chown root:root "${TARGET_CONFIG_PATH}"
chmod 644 "${TARGET_CONFIG_PATH}"
echo "Configuration file copied."

# Copy the compiled binary
echo "Copying compiled binary to ${TARGET_BIN_PATH}..."
cp "${RUST_SRC_DIR}/target/release/${APP_NAME}" "${TARGET_BIN_PATH}"
chown root:root "${TARGET_BIN_PATH}"
chmod 755 "${TARGET_BIN_PATH}"
echo "Binary copied."

# Copy the systemd service file
echo "Copying service file to ${TARGET_SERVICE_PATH}..."
cp "${PROJECT_ROOT}/${SOURCE_SERVICE_FILE_NAME}" "${TARGET_SERVICE_PATH}"
chown root:root "${TARGET_SERVICE_PATH}"
chmod 644 "${TARGET_SERVICE_PATH}"
echo "Service file copied."
echo

# --- Service Activation ---
echo "--- Reloading systemd and Starting the Service ---"

# Reload systemd
systemctl daemon-reload
echo "Systemd daemon reloaded."

# Enable the service
systemctl enable "${SERVICE_NAME}.service"
echo "Service '${SERVICE_NAME}' has been enabled."

# Start the service
systemctl start "${SERVICE_NAME}.service"
echo "Service '${SERVICE_NAME}' has been started."
echo

# --- Final Status and Information ---
echo "--- Deployment Complete ---"
echo "The ${SERVICE_NAME} service is now active."
echo
echo "Configuration file: ${TARGET_CONFIG_PATH}"
echo "Binary location: ${TARGET_BIN_PATH}"
echo "Service file: ${TARGET_SERVICE_PATH}"
echo "Log file: ${DEFAULT_LOG_FILE}"
echo "State directory: ${DEFAULT_STATE_DIR}"
echo
echo "Useful commands:"
echo "  Status: systemctl status ${SERVICE_NAME}.service"
echo "  Logs:   journalctl -u ${SERVICE_NAME}.service -f"
echo "  Stop:   systemctl stop ${SERVICE_NAME}.service"
echo "  Start:  systemctl start ${SERVICE_NAME}.service"
echo "  Config: ${TARGET_CONFIG_PATH}"
echo
echo "Note: Make sure to update your configuration file at ${TARGET_CONFIG_PATH}"
echo "with the correct ELK stack and Wazuh connection details."