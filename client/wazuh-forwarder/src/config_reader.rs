use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForwarderConfig {
    pub forwarder: ForwarderType,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
    pub performance: PerformanceConfig,
    pub threat_intelligence: ThreatIntelConfig,
    pub behavioral_analysis: BehavioralConfig,
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub palo_alto: PaloAltoConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForwarderType {
    #[serde(rename = "type")]
    pub forwarder_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
pub struct LoggingConfig {
    pub log_file: String,
    pub state_file: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PerformanceConfig {
    pub max_receiver_queue_size: usize,
    pub max_enrichment_queue_size: usize,
    pub max_wazuh_queue_size: usize,
    pub enrichment_worker_count: usize,
    pub elk_batch_size: usize,
    pub elk_batch_flush_interval_secs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatIntelConfig {
    pub enable_threat_intel_feeds: bool,
    pub threat_intel_refresh_interval_secs: u64,
    pub threat_intel_cache_dir: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BehavioralConfig {
    pub enable_behavioral_analysis: bool,
    pub behavior_window_minutes: i64,
    pub high_severity_threshold: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TelegramConfig {
    pub enable_telegram: bool,
    pub bot_token: String,
    pub chat_id: String,
    pub heartbeat_interval_secs: u64,
}


#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PaloAltoConfig {
    // Add Palo Alto-specific settings here if needed
}

impl ForwarderConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: ForwarderConfig = toml::de::from_str(&contents)?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate forwarder type
        match self.forwarder.forwarder_type.as_str() {
            "palo_alto" => {},
            _ => return Err(format!("Invalid forwarder type: {}", self.forwarder.forwarder_type)),
        }

        // Validate network configuration
        if self.network.syslog_port == 0 {
            return Err("Syslog port cannot be 0".to_string());
        }

        if self.network.elk_port == 0 {
            return Err("ELK port cannot be 0".to_string());
        }

        if self.network.wazuh_port == 0 {
            return Err("Wazuh port cannot be 0".to_string());
        }

        // Validate performance settings
        if self.performance.enrichment_worker_count == 0 {
            return Err("Worker count cannot be 0".to_string());
        }

        // Validate Telegram configuration if enabled
        if self.telegram.enable_telegram {
            if self.telegram.bot_token.is_empty() || self.telegram.bot_token == "YOUR_TELEGRAM_BOT_TOKEN" {
                return Err("Telegram bot token must be configured".to_string());
            }
            if self.telegram.chat_id.is_empty() || self.telegram.chat_id == "YOUR_TELEGRAM_CHAT_ID" {
                return Err("Telegram chat ID must be configured".to_string());
            }
        }

        Ok(())
    }


    pub fn is_palo_alto(&self) -> bool {
        self.forwarder.forwarder_type == "palo_alto"
    }
}