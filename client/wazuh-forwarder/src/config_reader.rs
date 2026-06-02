use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

use crate::palo_alto_config::{ELK_HOST, ELK_PORT, LOG_FILE, PALO_ALTO_SYSLOG_PORT, STATE_FILE};
use crate::unified_config::{
    BEHAVIOR_WINDOW_MINUTES, ELK_BATCH_FLUSH_INTERVAL_SECS, ELK_BATCH_SIZE,
    ENABLE_BEHAVIORAL_ANALYSIS, ENABLE_THREAT_INTEL_FEEDS, ENRICHMENT_WORKER_COUNT,
    HIGH_SEVERITY_THRESHOLD, MAX_ENRICHMENT_QUEUE_SIZE, MAX_RECEIVER_QUEUE_SIZE,
    MAX_WAZUH_QUEUE_SIZE, SOCKET_TIMEOUT_SECS, THREAT_INTEL_CACHE_DIR,
    THREAT_INTEL_REFRESH_INTERVAL_SECS, WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Complete runtime configuration loaded from TOML.
pub struct ForwarderConfig {
    pub forwarder: ForwarderType,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
    pub performance: PerformanceConfig,
    pub threat_intelligence: ThreatIntelConfig,
    pub behavioral_analysis: BehavioralConfig,
    #[serde(default)]
    pub palo_alto: PaloAltoConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Identifies which forwarder implementation should run.
pub struct ForwarderType {
    #[serde(rename = "type")]
    pub forwarder_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Network endpoints and socket settings.
pub struct NetworkConfig {
    pub syslog_port: u16,
    pub wazuh_host: String,
    pub wazuh_port: u16,
    pub elk_host: String,
    pub elk_port: u16,
    pub elk_index_name: String,
    pub socket_timeout_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Log and state file locations.
pub struct LoggingConfig {
    pub log_file: String,
    pub state_file: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Queue, worker, and batching settings.
pub struct PerformanceConfig {
    pub max_receiver_queue_size: usize,
    pub max_enrichment_queue_size: usize,
    pub max_wazuh_queue_size: usize,
    pub enrichment_worker_count: usize,
    pub elk_batch_size: usize,
    pub elk_batch_flush_interval_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Threat-intelligence feed settings.
pub struct ThreatIntelConfig {
    pub enable_threat_intel_feeds: bool,
    pub threat_intel_refresh_interval_secs: u64,
    pub threat_intel_cache_dir: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Behavioral anomaly detection settings.
pub struct BehavioralConfig {
    pub enable_behavioral_analysis: bool,
    pub behavior_window_minutes: i64,
    pub high_severity_threshold: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
/// Palo Alto-specific extension point for future settings.
pub struct PaloAltoConfig {
    // Add Palo Alto-specific settings here if needed
}

#[derive(Debug, Error)]
/// Errors produced while loading or validating configuration.
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

impl ConfigError {
    fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }
}

impl Default for ForwarderConfig {
    fn default() -> Self {
        Self {
            forwarder: ForwarderType {
                forwarder_type: "palo_alto".to_string(),
            },
            network: NetworkConfig {
                syslog_port: PALO_ALTO_SYSLOG_PORT,
                wazuh_host: WAZUH_LOCAL_SYSLOG_HOST.to_string(),
                wazuh_port: WAZUH_LOCAL_SYSLOG_PORT,
                elk_host: ELK_HOST.to_string(),
                elk_port: ELK_PORT,
                elk_index_name: "prodepa-logs".to_string(),
                socket_timeout_secs: SOCKET_TIMEOUT_SECS,
            },
            logging: LoggingConfig {
                log_file: LOG_FILE.to_string(),
                state_file: STATE_FILE.to_string(),
            },
            performance: PerformanceConfig {
                max_receiver_queue_size: MAX_RECEIVER_QUEUE_SIZE,
                max_enrichment_queue_size: MAX_ENRICHMENT_QUEUE_SIZE,
                max_wazuh_queue_size: MAX_WAZUH_QUEUE_SIZE,
                enrichment_worker_count: ENRICHMENT_WORKER_COUNT,
                elk_batch_size: ELK_BATCH_SIZE,
                elk_batch_flush_interval_secs: ELK_BATCH_FLUSH_INTERVAL_SECS,
            },
            threat_intelligence: ThreatIntelConfig {
                enable_threat_intel_feeds: ENABLE_THREAT_INTEL_FEEDS,
                threat_intel_refresh_interval_secs: THREAT_INTEL_REFRESH_INTERVAL_SECS,
                threat_intel_cache_dir: THREAT_INTEL_CACHE_DIR.to_string(),
            },
            behavioral_analysis: BehavioralConfig {
                enable_behavioral_analysis: ENABLE_BEHAVIORAL_ANALYSIS,
                behavior_window_minutes: BEHAVIOR_WINDOW_MINUTES,
                high_severity_threshold: HIGH_SEVERITY_THRESHOLD,
            },
            palo_alto: PaloAltoConfig::default(),
        }
    }
}

impl ForwarderConfig {
    /// Loads configuration from a TOML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let display_path = path.display().to_string();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: display_path.clone(),
            source,
        })?;
        let config: ForwarderConfig =
            toml::de::from_str(&contents).map_err(|source| ConfigError::Parse {
                path: display_path,
                source,
            })?;
        Ok(config)
    }

    /// Validates required runtime invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate forwarder type
        match self.forwarder.forwarder_type.as_str() {
            "palo_alto" => {}
            _ => {
                return Err(ConfigError::validation(format!(
                    "invalid forwarder type: {}",
                    self.forwarder.forwarder_type
                )))
            }
        }

        // Validate network configuration
        if self.network.syslog_port == 0 {
            return Err(ConfigError::validation("syslog port cannot be 0"));
        }

        if self.network.elk_port == 0 {
            return Err(ConfigError::validation("ELK port cannot be 0"));
        }

        if self.network.wazuh_port == 0 {
            return Err(ConfigError::validation("Wazuh port cannot be 0"));
        }

        // Validate performance settings
        if self.performance.enrichment_worker_count == 0 {
            return Err(ConfigError::validation("worker count cannot be 0"));
        }

        if self.performance.max_receiver_queue_size == 0 {
            return Err(ConfigError::validation("receiver queue size cannot be 0"));
        }

        if self.performance.max_enrichment_queue_size == 0 {
            return Err(ConfigError::validation("enrichment queue size cannot be 0"));
        }

        if self.performance.max_wazuh_queue_size == 0 {
            return Err(ConfigError::validation("Wazuh queue size cannot be 0"));
        }

        if self.performance.elk_batch_size == 0 {
            return Err(ConfigError::validation("ELK batch size cannot be 0"));
        }

        if self.performance.elk_batch_flush_interval_secs == 0 {
            return Err(ConfigError::validation(
                "ELK batch flush interval cannot be 0",
            ));
        }

        Ok(())
    }

    /// Returns true when the configured forwarder type is Palo Alto.
    pub fn is_palo_alto(&self) -> bool {
        self.forwarder.forwarder_type == "palo_alto"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_zero_queue_and_batch_sizes() {
        let mut config = ForwarderConfig::default();
        config.performance.max_receiver_queue_size = 0;
        assert!(config.validate().is_err());

        let mut config = ForwarderConfig::default();
        config.performance.max_enrichment_queue_size = 0;
        assert!(config.validate().is_err());

        let mut config = ForwarderConfig::default();
        config.performance.max_wazuh_queue_size = 0;
        assert!(config.validate().is_err());

        let mut config = ForwarderConfig::default();
        config.performance.elk_batch_size = 0;
        assert!(config.validate().is_err());
    }
}
