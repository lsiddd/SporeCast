//! Behavioral anomaly detection domain logic.

use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use lru::LruCache;
use serde_json::{json, Value};
use std::num::NonZeroUsize;

use crate::domain::rules::{BEHAVIOR_WINDOW_MINUTES, HIGH_SEVERITY_THRESHOLD};

const MAX_UNIQUE_IPS_TO_TRACK: usize = 250_000;
const MAX_UNIQUE_USERS_TO_TRACK: usize = 100_000;
const MAX_RULES_TO_TRACK: usize = 10_000;

fn cache_capacity(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

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
    pub fn update(&mut self, log_data: &Value) {
        let now = Utc::now();

        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            info!(
                "Behavioral analysis window expired ({} minutes). Resetting history counts.",
                BEHAVIOR_WINDOW_MINUTES
            );
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now;

        if let Some(src_ip) = log_data
            .get("source_address")
            .or_else(|| log_data.get("srcip"))
            .or_else(|| log_data.get("src"))
            .and_then(Value::as_str)
        {
            let count = self.src_ips.get_or_insert_mut(src_ip.to_string(), || 0);
            *count = count.saturating_add(1);
            debug!("Updated src_ip history for {}: count = {}", src_ip, *count);
        }

        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
            let count = self.users.get_or_insert_mut(user.to_string(), || 0);
            *count = count.saturating_add(1);
            debug!("Updated user history for {}: count = {}", user, *count);
        }

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

    pub fn is_suspicious_activity(&self, log_data: &Value) -> Option<Value> {
        let mut anomalies = json!({});
        let mut found_anomaly = false;

        if let Some(src_ip) = log_data
            .get("source_address")
            .or_else(|| log_data.get("srcip"))
            .or_else(|| log_data.get("src"))
            .and_then(Value::as_str)
        {
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

        if let Some(user) = log_data.get("user").and_then(Value::as_str) {
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

    pub fn merge(&mut self, other: AlertHistory) {
        let now = Utc::now();
        if (now - self.last_alert_time).num_minutes() > BEHAVIOR_WINDOW_MINUTES {
            self.src_ips.clear();
            self.users.clear();
            self.rules.clear();
        }
        self.last_alert_time = now.max(other.last_alert_time);

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

    #[test]
    fn detects_high_frequency_ip_via_source_address_field() {
        // Both palo_alto and tshark parsers produce "source_address"
        let mut history = AlertHistory::default();
        let log = json!({ "source_address": "203.0.113.77" });

        for _ in 0..=HIGH_SEVERITY_THRESHOLD {
            history.update(&log);
        }

        let anomaly = history.is_suspicious_activity(&log);
        assert!(anomaly.is_some(), "should detect high-frequency IP via source_address");
        assert!(anomaly.unwrap().get("high_frequency_ip").is_some());
    }

    #[test]
    fn source_address_preferred_over_srcip_fallback() {
        let mut history = AlertHistory::default();
        // Feed via source_address
        let log = json!({ "source_address": "1.2.3.4" });
        for _ in 0..=HIGH_SEVERITY_THRESHOLD {
            history.update(&log);
        }
        assert!(history.is_suspicious_activity(&log).is_some());

        // Separate history with srcip fallback
        let mut history2 = AlertHistory::default();
        let log2 = json!({ "srcip": "5.6.7.8" });
        for _ in 0..=HIGH_SEVERITY_THRESHOLD {
            history2.update(&log2);
        }
        assert!(history2.is_suspicious_activity(&log2).is_some());
    }

    #[test]
    fn no_anomaly_below_threshold() {
        let mut history = AlertHistory::default();
        let log = json!({ "source_address": "10.0.0.1" });

        for _ in 0..HIGH_SEVERITY_THRESHOLD {
            history.update(&log);
        }

        assert!(history.is_suspicious_activity(&log).is_none());
    }
}
