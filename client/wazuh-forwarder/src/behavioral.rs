use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use crate::unified_config::*;

// ==============================================================================
// --- Behavioral Analysis Engine Structure ---
// This struct tracks historical log data for anomaly detection.
// ==============================================================================
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AlertHistory {
    pub src_ips: HashMap<String, u32>, // Counts of source IPs within the behavior window.
    pub users: HashMap<String, u32>,   // Counts of users within the behavior window.
    pub rules: HashMap<u32, u32>,      // Counts of log rule IDs within the behavior window.
    pub last_alert_time: DateTime<Utc>, // Timestamp of the last processed log. Used to reset the window.
}

impl Default for AlertHistory {
    // Provides a default, empty state for AlertHistory.
    fn default() -> Self {
        Self {
            src_ips: HashMap::new(),
            users: HashMap::new(),
            rules: HashMap::new(),
            last_alert_time: Utc::now(),
        }
    }
}

impl AlertHistory {
    // Updates the behavioral history with data from the current log.
    pub fn update(&mut self, log_data: &Value) {
        let now = Utc::now();

        // If the last log was processed outside the defined behavior window, reset all counts.
        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            info!(
                "Behavioral analysis window expired ({} minutes). Resetting history counts.",
                BEHAVIOR_WINDOW_MINUTES
            );
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now; // Update last processed time to current time.

        // Increment count for source IP. Checks both 'srcip' and 'src' fields.
        if let Some(src_ip) = log_data
            .get("srcip")
            .or_else(|| log_data.get("src"))
            .and_then(Value::as_str)
        {
            *self.src_ips.entry(src_ip.to_string()).or_insert(0) += 1;
            debug!(
                "Updated src_ip history for {}: count = {}",
                src_ip, self.src_ips[src_ip]
            );
        }
        // Increment count for user. Logs might not consistently have a 'user' field in all log types.
        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
            *self.users.entry(user.to_string()).or_insert(0) += 1;
            debug!(
                "Updated user history for {}: count = {}",
                user, self.users[user]
            );
        }
        // Increment count for log rule ID. This acts as a unique identifier for log types.
        if let Some(logid) = log_data.get("logid").and_then(Value::as_u64) {
            *self.rules.entry(logid as u32).or_insert(0) += 1;
            debug!(
                "Updated logid history for {}: count = {}",
                logid,
                self.rules[&(logid as u32)]
            );
        }
    }

    // Checks if the current log, in context of history, indicates suspicious activity.
    pub fn is_suspicious_activity(&self, log_data: &Value) -> Option<Value> {
        let mut anomalies = json!({});
        let mut found_anomaly = false;

        // Check for high frequency from the same source IP.
        if let Some(src_ip) = log_data
            .get("srcip")
            .or_else(|| log_data.get("src"))
            .and_then(Value::as_str)
        {
            if let Some(&count) = self.src_ips.get(src_ip) {
                if count > HIGH_SEVERITY_THRESHOLD {
                    warn!(
                        "High frequency IP detected: {} has {} events in last {} minutes.",
                        src_ip, count, BEHAVIOR_WINDOW_MINUTES
                    );
                    anomalies["high_frequency_ip"] =
                        json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }
        // Check for suspicious user activity frequency.
        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
            if let Some(&count) = self.users.get(user) {
                if count > HIGH_SEVERITY_THRESHOLD {
                    warn!(
                        "High frequency user detected: {} has {} events in last {} minutes.",
                        user, count, BEHAVIOR_WINDOW_MINUTES
                    );
                    anomalies["high_frequency_user"] =
                        json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }
        // Check for specific log ID flooding.
        if let Some(logid) = log_data.get("logid").and_then(Value::as_u64) {
            if let Some(&count) = self.rules.get(&(logid as u32)) {
                if count > HIGH_SEVERITY_THRESHOLD {
                    warn!(
                        "High frequency Log ID detected: {} has {} events in last {} minutes.",
                        logid, count, BEHAVIOR_WINDOW_MINUTES
                    );
                    anomalies["high_frequency_logid"] =
                        json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                    found_anomaly = true;
                }
            }
        }

        // Return anomalies if any were found, otherwise None.
        if found_anomaly {
            Some(anomalies)
        } else {
            None
        }
    }

    // Merges another AlertHistory into this one.
    // This is useful for consolidating history from multiple worker threads.
    pub fn merge(&mut self, other: AlertHistory) {
        let now = Utc::now();
        // Reset if own window has expired
        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now.max(other.last_alert_time); // Keep the latest timestamp

        for (ip, count) in other.src_ips {
            *self.src_ips.entry(ip).or_insert(0) += count;
        }
        for (user, count) in other.users {
            *self.users.entry(user).or_insert(0) += count;
        }
        for (rule, count) in other.rules {
            *self.rules.entry(rule).or_insert(0) += count;
        }
    }
}

// ==============================================================================
// --- State Management ---
// Handles loading and saving the forwarder's persistent state (behavioral history).
// ==============================================================================
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct State {
    pub inode: Option<u64>, // Not used for syslog, kept for potential future file-based features
    pub offset: u64,         // Not used for syslog, kept for potential future file-based features
    pub alert_history: AlertHistory, // The behavioral analysis history.
}

pub struct StateManager {
    state_file: String, // Path to the state file.
    pub state: State,   // The current state object.
}

impl StateManager {
    // Creates a new StateManager instance with a default empty state.
    pub fn new(state_file: &str) -> Self {
        debug!("Creating new StateManager for file: {}", state_file);
        let state = State::default();
        Self {
            state_file: state_file.to_string(),
            state,
        }
    }

    // Attempts to load the state from the configured state file.
    pub fn load(&mut self) -> Result<()> {
        info!("Attempting to load state from: {}", self.state_file);
        if !Path::new(&self.state_file).exists() {
            info!(
                "State file not found at {}. Using default state for first run.",
                self.state_file
            );
            return Ok(()); // No error, just a new start.
        }
        let contents = fs::read_to_string(&self.state_file)
            .with_context(|| format!("Failed to read state file {}", self.state_file))?;
        self.state = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file {}", self.state_file))?;
        info!(
            "Successfully loaded state from {}. Behavioral analysis history: {:?}",
            self.state_file, self.state.alert_history
        );
        Ok(())
    }

    // Saves the current state to the configured state file.
    pub fn save(&self) -> Result<()> {
        debug!("Attempting to save state to: {}", self.state_file);
        let serialized =
            serde_json::to_string(&self.state).context("Failed to serialize state to JSON")?;
        if let Some(parent) = Path::new(&self.state_file).parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent directory for state file: {:?}",
                    parent
                )
            })?;
            debug!(
                "Ensured parent directory for state file exists: {:?}",
                parent
            );
        }
        fs::write(&self.state_file, serialized)
            .with_context(|| format!("Failed to write state to file {}", self.state_file))?;
        debug!("Successfully saved state.");
        Ok(())
    }

    // Merges worker state into the main state manager
    pub fn _merge_worker_state(&mut self, worker_state: &AlertHistory) {
        debug!("Merging worker state into main state manager");
        self.state.alert_history.merge(worker_state.clone());
    }
}