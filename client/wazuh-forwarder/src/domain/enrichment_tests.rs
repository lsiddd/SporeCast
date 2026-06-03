use super::*;
use crate::domain::behavioral::AlertHistory;
use crate::domain::palo_alto::parse_palo_alto_log_to_json;
use crate::domain::tshark::normalize_packet;

#[test]
fn extracts_iocs_from_nested_json_strings() {
    let log = json!({
        "message": "connect to http://malicious.example/path from 8.8.8.8",
        "nested": { "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
    });

    let iocs = extract_iocs(&log);

    assert!(iocs["ip"].contains(&"8.8.8.8".to_string()));
    assert!(iocs["url"].contains(&"http://malicious.example/path".to_string()));
    assert!(iocs["hash"].contains(&"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()));
}

#[test]
fn adds_enrichment_when_ioc_matches_threat_intel() {
    let mut intel = ThreatIntel::new();
    intel.malicious_domains = Arc::new(["malicious.example".to_string()].into_iter().collect());
    let intel = Arc::new(intel);
    let mut state = AlertHistory::default();
    let log = json!({ "url": "http://malicious.example/path" });

    let enriched = enrich_and_analyze_log(log, &intel, &mut state, None);

    assert!(enriched.get("forwarder_enrichment").is_some());
}

#[test]
fn palo_alto_log_enriched_with_malicious_ip() {
    let raw = "<14>Jun 02 13:10:07 PA-VM-01 1,2026/06/02 13:10:07,007951000123,TRAFFIC,deny,2561,2026/06/02 13:10:07,10.10.20.44,203.0.113.10,0.0.0.0,0.0.0.0,deny-any,,,telnet,vsys1,trust,untrust,ethernet1/3,ethernet1/1,LFP-SIEM,2026/06/02 13:10:07,4839202,1,51514,23,0,0,0x0,tcp,deny,66,66,0,1";

    let parsed = parse_palo_alto_log_to_json(raw).expect("should parse");
    assert_eq!(parsed["destination_address"], "203.0.113.10");

    let mut intel = ThreatIntel::new();
    let mut malicious_ips = std::collections::HashMap::new();
    malicious_ips.insert("203.0.113.10".to_string(), vec!["test-feed".to_string()]);
    intel.malicious_ips = Arc::new(malicious_ips);
    let intel = Arc::new(intel);
    let mut state = AlertHistory::default();

    let enriched = enrich_and_analyze_log(parsed, &intel, &mut state, None);

    let enrichment = enriched.get("forwarder_enrichment").expect("should have enrichment");
    let ioc_matches = enrichment.get("ioc_matches").expect("should have ioc_matches");
    assert!(ioc_matches.get("malicious_ips").is_some());
}

#[test]
fn tshark_packet_normalized_then_enriched_end_to_end() {
    let raw_packet = json!({
        "timestamp": "1780410711074",
        "layers": {
            "ip": {
                "ip_ip_src": "198.51.100.99",
                "ip_ip_dst": "10.0.0.1"
            },
            "tcp": {
                "tcp_tcp_srcport": "4444",
                "tcp_tcp_dstport": "80"
            },
            "frame": {
                "frame_frame_len": "512",
                "frame_frame_protocols": "sll:ethertype:ip:tcp",
                "frame_frame_time_utc": "2026-06-02T14:00:00Z"
            }
        }
    });

    let normalized = normalize_packet(&raw_packet).expect("should normalize");
    assert_eq!(normalized["source_address"], "198.51.100.99");
    assert_eq!(normalized["log_type"], "tshark");

    let mut intel = ThreatIntel::new();
    let mut malicious_ips = std::collections::HashMap::new();
    malicious_ips.insert("198.51.100.99".to_string(), vec!["test-blocklist".to_string()]);
    intel.malicious_ips = Arc::new(malicious_ips);
    let intel = Arc::new(intel);
    let mut state = AlertHistory::default();

    let enriched = enrich_and_analyze_log(normalized, &intel, &mut state, None);

    let enrichment = enriched.get("forwarder_enrichment").expect("tshark packet should be enriched");
    let ioc = enrichment.get("ioc_matches").expect("should have ioc_matches");
    assert!(ioc.get("malicious_ips").is_some());
}

#[test]
fn threat_hunt_detects_sql_injection_in_plaintext_payload() {
    // Use a log with a plaintext (non-URL-encoded) SQL injection payload
    let log = json!({
        "type": "THREAT",
        "source_address": "10.0.0.5",
        "destination_address": "1.2.3.4",
        "threat_content_type": "url",
        "url_filename": "/search.php?id=1' OR 1=1",
        "log_source": "palo_alto"
    });

    let intel = Arc::new(ThreatIntel::new());
    let mut state = crate::domain::behavioral::AlertHistory::default();

    let enriched = enrich_and_analyze_log(log, &intel, &mut state, None);

    let enrichment = enriched.get("forwarder_enrichment").expect("should have enrichment");
    let hunt = enrichment.get("threat_hunting").expect("should have threat_hunting");
    let patterns = hunt.get("suspicious_patterns").expect("should have suspicious_patterns");
    let patterns_arr = patterns.as_array().expect("should be array");
    assert!(
        patterns_arr.iter().any(|p| p["pattern"] == "sql_injection"),
        "sql_injection pattern should be detected in plaintext payload"
    );
}

#[test]
fn palo_alto_threat_log_is_parsed_and_enrichable() {
    let raw = "<14>Jun 02 13:10:13 PA-VM-01 1,2026/06/02 13:10:13,007951000123,THREAT,vulnerability,2561,2026/06/02 13:10:13,10.10.30.15,203.0.113.77,0.0.0.0,0.0.0.0,allow-dmz-web,,,web-browsing,vsys1,dmz,untrust,ethernet1/4,ethernet1/1,LFP-SIEM,2026/06/02 13:10:13,4839203,1,49822,80,0,0,0x400019,tcp,reset-both,/search.php?id=1%27%20OR%201=1,HTTP SQL Injection Attempt(40001),any,high,client-to-server,7408146363088945004";

    let parsed = parse_palo_alto_log_to_json(raw).expect("should parse");
    assert_eq!(parsed["type"], "THREAT");
    assert_eq!(parsed["source_address"], "10.10.30.15");

    // Verify it flows through enrichment without error
    let intel = Arc::new(ThreatIntel::new());
    let mut state = crate::domain::behavioral::AlertHistory::default();
    let enriched = enrich_and_analyze_log(parsed, &intel, &mut state, None);

    // Should at minimum preserve parsed fields
    assert_eq!(enriched["type"], "THREAT");
    assert_eq!(enriched["log_source"], "palo_alto");
}
