use super::*;
use crate::behavioral::AlertHistory;

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

    let enriched = enrich_and_analyze_log(log, &intel, &mut state);

    assert!(enriched.get("forwarder_enrichment").is_some());
}
