use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

use crate::infrastructure::defaults::{
    BEHAVIOR_WINDOW_MINUTES_DEFAULT, ELK_BATCH_FLUSH_INTERVAL_SECS, ELK_BATCH_SIZE,
    ENABLE_BEHAVIORAL_ANALYSIS_DEFAULT, ENABLE_THREAT_INTEL_FEEDS, ENRICHMENT_WORKER_COUNT,
    HIGH_SEVERITY_THRESHOLD_DEFAULT, MAX_ENRICHMENT_QUEUE_SIZE, MAX_RECEIVER_QUEUE_SIZE,
    MAX_WAZUH_QUEUE_SIZE, SOCKET_TIMEOUT_SECS, THREAT_INTEL_CACHE_DIR,
    THREAT_INTEL_REFRESH_INTERVAL_SECS, WAZUH_LOCAL_SYSLOG_HOST, WAZUH_LOCAL_SYSLOG_PORT,
};

const PALO_ALTO_SYSLOG_PORT: u16 = 514;
const ELK_HOST: &str = "127.0.0.1";
const ELK_PORT: u16 = 5142;
const LOG_FILE: &str = "run/forwarder.log";
const STATE_FILE: &str = "run/state.json";

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
    #[serde(default)]
    pub geoip: GeoIpConfig,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
/// GeoIP database settings for IP geolocation enrichment.
pub struct GeoIpConfig {
    pub enabled: bool,
    pub database_path: String,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database_path: "run/geoip/dbip-city-lite.mmdb".to_string(),
        }
    }
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
                enable_behavioral_analysis: ENABLE_BEHAVIORAL_ANALYSIS_DEFAULT,
                behavior_window_minutes: BEHAVIOR_WINDOW_MINUTES_DEFAULT,
                high_severity_threshold: HIGH_SEVERITY_THRESHOLD_DEFAULT,
            },
            palo_alto: PaloAltoConfig::default(),
            geoip: GeoIpConfig::default(),
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
            "palo_alto" | "tshark" => {}
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

    /// Remaps paths that start with `/var/` to a project-local `run/` directory.
    /// Call this in binaries that run without root (dev/test mode).
    pub fn resolve_user_paths(&mut self) {
        let run_dir = "run";
        std::fs::create_dir_all(format!("{}/geoip", run_dir)).ok();
        std::fs::create_dir_all(format!("{}/threat_intel_cache", run_dir)).ok();

        if self.logging.log_file.starts_with("/var/") {
            self.logging.log_file = format!("{}/forwarder.log", run_dir);
        }
        if self.logging.state_file.starts_with("/var/") {
            self.logging.state_file = format!("{}/state.json", run_dir);
        }
        if self
            .threat_intelligence
            .threat_intel_cache_dir
            .starts_with("/var/")
        {
            self.threat_intelligence.threat_intel_cache_dir =
                format!("{}/threat_intel_cache", run_dir);
        }
        if self.geoip.database_path.starts_with("/var/") {
            self.geoip.database_path = format!("{}/geoip/dbip-city-lite.mmdb", run_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_config_file(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "wazuh_forwarder_{name}_{}_{}.toml",
                std::process::id(),
                nanos
            ))
            .display()
            .to_string()
    }

    fn valid_config_toml() -> String {
        r#"
[forwarder]
type = "tshark"

[network]
syslog_port = 1515
wazuh_host = "127.0.0.2"
wazuh_port = 1516
elk_host = "127.0.0.3"
elk_port = 1517
elk_index_name = "loaded-index"
socket_timeout_secs = 9

[logging]
log_file = "run/test-forwarder.log"
state_file = "run/test-state.json"

[performance]
max_receiver_queue_size = 11
max_enrichment_queue_size = 12
max_wazuh_queue_size = 13
enrichment_worker_count = 2
elk_batch_size = 3
elk_batch_flush_interval_secs = 4

[threat_intelligence]
enable_threat_intel_feeds = false
threat_intel_refresh_interval_secs = 99
threat_intel_cache_dir = "run/test-cache"

[behavioral_analysis]
enable_behavioral_analysis = true
behavior_window_minutes = 7
high_severity_threshold = 8

[geoip]
enabled = false
database_path = "run/test.mmdb"
"#
        .to_string()
    }

    #[test]
    fn valid_toml_config_loads_all_sections() {
        let config_file = unique_config_file("valid_config");
        fs::write(&config_file, valid_config_toml()).expect("config fixture should be written");

        let config = ForwarderConfig::load_from_file(&config_file)
            .expect("valid config fixture should load");

        assert_eq!(config.forwarder.forwarder_type, "tshark");
        assert_eq!(config.network.syslog_port, 1515);
        assert_eq!(config.network.elk_host, "127.0.0.3");
        assert_eq!(config.performance.enrichment_worker_count, 2);
        assert_eq!(config.performance.elk_batch_flush_interval_secs, 4);
        assert_eq!(
            config.threat_intelligence.threat_intel_cache_dir,
            "run/test-cache"
        );
        assert_eq!(config.geoip.enabled, false);
        assert!(config.validate().is_ok());

        let _ = fs::remove_file(config_file);
    }

    #[test]
    fn missing_config_file_returns_read_error_with_path() {
        let config_file = unique_config_file("missing_config");

        let error = ForwarderConfig::load_from_file(&config_file)
            .expect_err("missing config should return a read error");

        match error {
            ConfigError::Read { path, .. } => assert_eq!(path, config_file),
            other => panic!("expected ConfigError::Read, got {other:?}"),
        }
    }

    #[test]
    fn var_paths_are_remapped_to_run_directory() {
        let mut config = ForwarderConfig::default();
        config.logging.log_file = "/var/log/wazuh-forwarder/forwarder.log".to_string();
        config.logging.state_file = "/var/lib/wazuh-forwarder/state.json".to_string();
        config.threat_intelligence.threat_intel_cache_dir =
            "/var/cache/wazuh-forwarder/threat_intel".to_string();
        config.geoip.database_path = "/var/lib/wazuh-forwarder/geoip.mmdb".to_string();

        config.resolve_user_paths();

        assert_eq!(config.logging.log_file, "run/forwarder.log");
        assert_eq!(config.logging.state_file, "run/state.json");
        assert_eq!(
            config.threat_intelligence.threat_intel_cache_dir,
            "run/threat_intel_cache"
        );
        assert_eq!(config.geoip.database_path, "run/geoip/dbip-city-lite.mmdb");
    }

    #[test]
    fn invalid_zero_runtime_limits_return_specific_validation_errors() {
        let cases: Vec<(fn(&mut ForwarderConfig), &str)> = vec![
            (
                |config| config.network.syslog_port = 0,
                "syslog port cannot be 0",
            ),
            (|config| config.network.elk_port = 0, "ELK port cannot be 0"),
            (
                |config| config.network.wazuh_port = 0,
                "Wazuh port cannot be 0",
            ),
            (
                |config| config.performance.enrichment_worker_count = 0,
                "worker count cannot be 0",
            ),
            (
                |config| config.performance.max_receiver_queue_size = 0,
                "receiver queue size cannot be 0",
            ),
            (
                |config| config.performance.max_enrichment_queue_size = 0,
                "enrichment queue size cannot be 0",
            ),
            (
                |config| config.performance.max_wazuh_queue_size = 0,
                "Wazuh queue size cannot be 0",
            ),
            (
                |config| config.performance.elk_batch_size = 0,
                "ELK batch size cannot be 0",
            ),
            (
                |config| config.performance.elk_batch_flush_interval_secs = 0,
                "ELK batch flush interval cannot be 0",
            ),
        ];

        for (mutate, expected_message) in cases {
            let mut config = ForwarderConfig::default();
            mutate(&mut config);

            let error = config.validate().expect_err("config should be rejected");

            assert_eq!(
                error.to_string(),
                format!("invalid configuration: {expected_message}")
            );
        }
    }

    #[test]
    fn unknown_forwarder_type_is_rejected_with_type_name() {
        let mut config = ForwarderConfig::default();
        config.forwarder.forwarder_type = "fortigate".to_string();

        let error = config
            .validate()
            .expect_err("unknown forwarder type should be rejected");

        assert_eq!(
            error.to_string(),
            "invalid configuration: invalid forwarder type: fortigate"
        );
    }
}
