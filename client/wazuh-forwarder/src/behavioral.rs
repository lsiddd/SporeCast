use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, num::NonZeroUsize, path::Path};

use crate::unified_config::*;
use lru::LruCache; // ADDED: Import LruCache

// ==============================================================================
// --- Behavioral Analysis Engine Structure ---
// This struct tracks historical log data for anomaly detection.
// ==============================================================================

const MAX_UNIQUE_IPS_TO_TRACK: usize = 250_000;
const MAX_UNIQUE_USERS_TO_TRACK: usize = 100_000;
const MAX_RULES_TO_TRACK: usize = 10_000;

fn cache_capacity(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

// MODIFIED: Replaced unbounded HashMaps with size-limited LruCache.
// This is the primary fix for the OOM killer issue.
// Note: LruCache does not derive Serialize/Deserialize by default.
// State saving/loading for this struct is disabled for now to fix the memory leak.
#[derive(Clone, Debug)]
pub struct AlertHistory {
    pub src_ips: LruCache<String, u32>,
    pub users: LruCache<String, u32>,
    pub rules: LruCache<u32, u32>,
    pub last_alert_time: DateTime<Utc>,
}

impl Default for AlertHistory {
    fn default() -> Self {
        Self {
            src_ips: LruCache::new(cache_capacity(MAX_UNIQUE_IPS_TO_TRACK)),
            users: LruCache::new(cache_capacity(MAX_UNIQUE_USERS_TO_TRACK)),
            rules: LruCache::new(cache_capacity(MAX_RULES_TO_TRACK)),
            last_alert_time: Utc::now(),
        }
    }
}

impl AlertHistory {
    // MODIFIED: Updates the behavioral history using LruCache API.
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

        // Increment count for source IP.
        if let Some(src_ip) = log_data
            .get("srcip")
            .or_else(|| log_data.get("src"))
            .and_then(Value::as_str)
        {
            let count = self.src_ips.get_or_insert_mut(src_ip.to_string(), || 0);
            *count = count.saturating_add(1);
            debug!("Updated src_ip history for {}: count = {}", src_ip, *count);
        }
        // Increment count for user.
        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
            let count = self.users.get_or_insert_mut(user.to_string(), || 0);
            *count = count.saturating_add(1);
            debug!("Updated user history for {}: count = {}", user, *count);
        }
        // Increment count for log rule ID.
        if let Some(logid) = log_data.get("logid").and_then(Value::as_u64) {
            match u32::try_from(logid) {
                Ok(rule_id) => {
                    let count = self.rules.get_or_insert_mut(rule_id, || 0);
                    *count = count.saturating_add(1);
                    debug!("Updated logid history for {}: count = {}", logid, *count);
                }
                Err(_) => warn!("Skipping logid {} because it exceeds u32::MAX", logid),
            }
        }
    }

    // MODIFIED: Checks for suspicious activity using LruCache API's .peek() method.
    // This method inspects the value without mutating the cache order, so it works
    // with an immutable `&self` reference, fixing the compilation error.
    pub fn is_suspicious_activity(&self, log_data: &Value) -> Option<Value> {
        let mut anomalies = json!({});
        let mut found_anomaly = false;

        // Check for high frequency from the same source IP.
        if let Some(src_ip) = log_data
            .get("srcip")
            .or_else(|| log_data.get("src"))
            .and_then(Value::as_str)
        {
            // MODIFIED: Used .peek() instead of .get() to avoid mutable borrow.
            if let Some(&count) = self.src_ips.peek(src_ip) {
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
            // MODIFIED: Used .peek() instead of .get() to avoid mutable borrow.
            if let Some(&count) = self.users.peek(user) {
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
            if let Ok(rule_id) = u32::try_from(logid) {
                if let Some(&count) = self.rules.peek(&rule_id) {
                    if count > HIGH_SEVERITY_THRESHOLD {
                        warn!(
                            "High frequency Log ID detected: {} has {} events in last {} minutes.",
                            logid, count, BEHAVIOR_WINDOW_MINUTES
                        );
                        anomalies["high_frequency_logid"] = json!({ "count": count, "time_window_minutes": BEHAVIOR_WINDOW_MINUTES });
                        found_anomaly = true;
                    }
                }
            }
        }

        if found_anomaly {
            Some(anomalies)
        } else {
            None
        }
    }

    // Merges another AlertHistory into this one.
    pub fn merge(&mut self, other: AlertHistory) {
        let now = Utc::now();
        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now.max(other.last_alert_time);

        // Merge by iterating and putting, respecting the LRU limit
        for (ip, count) in other.src_ips {
            let entry = self.src_ips.get_or_insert_mut(ip, || 0);
            *entry = entry.saturating_add(count);
        }
        for (user, count) in other.users {
            let entry = self.users.get_or_insert_mut(user, || 0);
            *entry = entry.saturating_add(count);
        }
        for (rule, count) in other.rules {
            let entry = self.rules.get_or_insert_mut(rule, || 0);
            *entry = entry.saturating_add(count);
        }
    }
}

// ==============================================================================
// --- State Management ---
// Handles loading and saving the forwarder's persistent state.
// ==============================================================================
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct State {
    pub inode: Option<u64>,
    pub offset: u64,
    // MODIFIED: The alert_history is skipped during serialization to avoid compile errors
    // with LruCache and to prioritize fixing the memory leak. The history will be
    // ephemeral and reset on each application start.
    #[serde(skip)]
    pub alert_history: AlertHistory,
}

pub struct StateManager {
    state_file: String,
    pub state: State,
}

impl StateManager {
    pub fn new(state_file: &str) -> Self {
        debug!("Creating new StateManager for file: {}", state_file);
        let state = State::default();
        Self {
            state_file: state_file.to_string(),
            state,
        }
    }

    // MODIFIED: Loading will now ignore the behavioral history, which will start fresh.
    pub fn load(&mut self) -> Result<()> {
        info!("Attempting to load state from: {}", self.state_file);
        if !Path::new(&self.state_file).exists() {
            info!(
                "State file not found at {}. Using default state for first run.",
                self.state_file
            );
            return Ok(());
        }
        let contents = fs::read_to_string(&self.state_file)
            .with_context(|| format!("Failed to read state file {}", self.state_file))?;
        self.state = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file {}", self.state_file))?;
        info!(
            "Successfully loaded state from {}. Behavioral analysis history will start fresh.",
            self.state_file
        );
        Ok(())
    }

    // MODIFIED: Saving will now skip the behavioral history.
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
        debug!("Successfully saved state (excluding behavioral history).");
        Ok(())
    }

    pub fn _merge_worker_state(&mut self, worker_state: &AlertHistory) {
        debug!("Merging worker state into main state manager");
        self.state.alert_history.merge(worker_state.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_logid_is_ignored_in_behavioral_counters() {
        let mut history = AlertHistory::default();
        let log = json!({ "logid": u64::from(u32::MAX) + 1 });

        for _ in 0..=HIGH_SEVERITY_THRESHOLD {
            history.update(&log);
        }

        assert!(history.is_suspicious_activity(&log).is_none());
    }
}
