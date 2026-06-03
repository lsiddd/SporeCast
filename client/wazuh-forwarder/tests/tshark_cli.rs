use std::{
    fs,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn unique_config_path(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wazuh_forwarder_{name}_{}_{}.toml",
        std::process::id(),
        nanos
    ))
}

fn invalid_tshark_config_with_zero_worker_count() -> String {
    r#"
[forwarder]
type = "tshark"

[network]
syslog_port = 514
wazuh_host = "127.0.0.1"
wazuh_port = 1514
elk_host = "127.0.0.1"
elk_port = 5142
elk_index_name = "test-index"
socket_timeout_secs = 10

[logging]
log_file = "run/forwarder.log"
state_file = "run/state.json"

[performance]
max_receiver_queue_size = 10
max_enrichment_queue_size = 10
max_wazuh_queue_size = 10
enrichment_worker_count = 0
elk_batch_size = 1
elk_batch_flush_interval_secs = 1

[threat_intelligence]
enable_threat_intel_feeds = false
threat_intel_refresh_interval_secs = 86400
threat_intel_cache_dir = "run/threat_intel_cache"

[behavioral_analysis]
enable_behavioral_analysis = true
behavior_window_minutes = 5
high_severity_threshold = 10

[geoip]
enabled = false
database_path = "run/geoip/dbip-city-lite.mmdb"
"#
    .to_string()
}

#[test]
fn invalid_zero_worker_count_is_rejected_before_tshark_runtime_starts() {
    let config_path = unique_config_path("invalid_tshark_zero_workers");
    fs::write(&config_path, invalid_tshark_config_with_zero_worker_count())
        .expect("config fixture should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_tshark_forwarder"))
        .arg("--config")
        .arg(&config_path)
        .arg("--stdout")
        .stdin(Stdio::null())
        .output()
        .expect("tshark_forwarder should execute");

    let _ = fs::remove_file(&config_path);

    assert!(
        !output.status.success(),
        "invalid config unexpectedly succeeded; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("worker count cannot be 0"),
        "stderr should explain the validation failure, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
