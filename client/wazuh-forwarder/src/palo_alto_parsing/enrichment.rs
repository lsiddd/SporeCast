use log::{debug, info, warn};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

use crate::behavioral::AlertHistory;
use crate::threat_intel::ThreatIntel;
use crate::unified_config::*;

#[cfg(test)]
#[path = "enrichment_tests.rs"]
mod tests;

/// Extracts IPs, domains, hashes, and URLs from all string fields in a JSON log.
pub fn extract_iocs(log_data: &Value) -> HashMap<&'static str, Vec<String>> {
    debug!("Extracting IOCs from log data.");
    let mut iocs = HashMap::new();

    let mut collect_matches = |s: &str| {
        iocs.entry("ip")
            .or_insert_with(Vec::new)
            .extend(IP_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
        iocs.entry("domain")
            .or_insert_with(Vec::new)
            .extend(DOMAIN_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
        iocs.entry("hash")
            .or_insert_with(Vec::new)
            .extend(HASH_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
        iocs.entry("url")
            .or_insert_with(Vec::new)
            .extend(URL_REGEX.find_iter(s).map(|m| m.as_str().to_string()));
    };

    let find_in_value_recursive_and_collect = |value: &Value, f: &mut dyn FnMut(&str)| {
        fn inner(value: &Value, f: &mut dyn FnMut(&str)) {
            match value {
                Value::Object(map) => {
                    for (_, val) in map {
                        inner(val, f);
                    }
                }
                Value::Array(arr) => {
                    for val in arr {
                        inner(val, f);
                    }
                }
                Value::String(s) => {
                    f(s);
                }
                _ => {}
            }
        }
        inner(value, f);
    };

    find_in_value_recursive_and_collect(log_data, &mut collect_matches);
    debug!("Extracted IOCs: {:?}", iocs);
    iocs
}

// Main function for enriching and analyzing a single log.
/// Adds threat-intelligence, hunting, and behavioral enrichment to a parsed log.
pub fn enrich_and_analyze_log(
    mut log_data: Value,
    intel: &Arc<ThreatIntel>,
    state: &mut AlertHistory,
) -> Value {
    debug!("Starting enrichment and analysis for log.");
    let iocs = extract_iocs(&log_data);
    let mut enrichment_data = json!({});
    let mut found_enrichment = false;

    let mut ioc_matches = json!({});
    let mut found_ioc_match = false;

    if let Some(ips) = iocs.get("ip") {
        let mut malicious_ip_hits = Vec::new();
        for ip in ips {
            if let Some(sources) = intel.malicious_ips.get(ip) {
                info!(
                    "Threat Intel Match: Malicious IP '{}' detected from feeds: {:?}",
                    ip, sources
                );
                malicious_ip_hits.push(json!({
                    "ip": ip, "status": "blocklisted", "sources": sources, "source_count": sources.len()
                }));
            } else {
                debug!("IP '{}' not found in malicious IP feeds.", ip);
            }
        }
        if !malicious_ip_hits.is_empty() {
            ioc_matches["malicious_ips"] = Value::Array(malicious_ip_hits);
            found_ioc_match = true;
        }
    }

    if let Some(domains) = iocs.get("domain") {
        let hits: Vec<_> = domains
            .iter()
            .filter(|d| intel.malicious_domains.contains(*d))
            .collect();
        if !hits.is_empty() {
            info!(
                "Threat Intel Match: Malicious domain(s) detected: {:?}",
                hits
            );
            ioc_matches["malicious_domains"] = json!(hits);
            found_ioc_match = true;
        }
    }
    if let Some(hashes) = iocs.get("hash") {
        let hits: Vec<_> = hashes
            .iter()
            .filter(|h| intel.malicious_hashes.contains(*h))
            .collect();
        if !hits.is_empty() {
            info!(
                "Threat Intel Match: Malicious hash(es) detected: {:?}",
                hits
            );
            ioc_matches["malicious_hashes"] = json!(hits);
            found_ioc_match = true;
        }
    }
    if let Some(urls) = iocs.get("url") {
        let hits: Vec<_> = urls
            .iter()
            .filter(|u| intel.malicious_urls.contains(*u))
            .collect();
        if !hits.is_empty() {
            info!("Threat Intel Match: Malicious URL(s) detected: {:?}", hits);
            ioc_matches["malicious_urls"] = json!(hits);
            found_ioc_match = true;
        }
    }

    if found_ioc_match {
        enrichment_data["ioc_matches"] = ioc_matches;
        found_enrichment = true;
    }

    let mut hunt_detections = json!({});
    let mut found_hunt_detection = false;

    let mut suspicious_patterns_found = Vec::new();
    let check_suspicious_patterns =
        |value: &Value, path: String, f: &mut dyn FnMut(&str, &str, &str)| {
            fn inner(
                value: &Value,
                path: String,
                compiled_patterns: &HashMap<String, regex::Regex>,
                f: &mut dyn FnMut(&str, &str, &str),
            ) {
                match value {
                    Value::Object(map) => {
                        for (key, val) in map {
                            let new_path = if path.is_empty() {
                                key.clone()
                            } else {
                                format!("{}.{}", path, key)
                            };
                            inner(val, new_path, compiled_patterns, f);
                        }
                    }
                    Value::Array(arr) => {
                        for (index, val) in arr.iter().enumerate() {
                            let new_path = format!("{}[{}]", path, index);
                            inner(val, new_path, compiled_patterns, f);
                        }
                    }
                    Value::String(s) => {
                        for (name, re) in compiled_patterns {
                            if re.is_match(s) {
                                f(name, &path, s);
                            }
                        }
                    }
                    _ => {}
                }
            }
            inner(value, path, &SUSPICIOUS_PATTERNS_COMPILED, f);
        };
    let mut collect_suspicious = |name: &str, path: &str, s: &str| {
        warn!(
            "Threat Hunt: Suspicious pattern '{}' found in field '{}'.",
            name, path
        );
        suspicious_patterns_found.push(json!({"pattern": name, "field_path": path, "sample": s.chars().take(100).collect::<String>()}));
        found_hunt_detection = true;
    };
    check_suspicious_patterns(&log_data, String::new(), &mut collect_suspicious);

    if !suspicious_patterns_found.is_empty() {
        hunt_detections["suspicious_patterns"] = Value::Array(suspicious_patterns_found);
        found_hunt_detection = true;
    }

    if let Some(cmd) = log_data
        .get("msg")
        .or_else(|| log_data.get("eventdescription"))
        .and_then(Value::as_str)
    {
        let lower_cmd = cmd.to_lowercase();
        for process in SUSPICIOUS_PROCESSES.iter() {
            if lower_cmd.contains(process) {
                warn!(
                    "Threat Hunt: Suspicious process keyword '{}' detected.",
                    process
                );
                hunt_detections["suspicious_process"] = json!(process);
                found_hunt_detection = true;
                break;
            }
        }
    }

    if let Some(desc) = log_data
        .get("msg")
        .or_else(|| log_data.get("logdesc"))
        .and_then(Value::as_str)
    {
        let lower_desc = desc.to_lowercase();
        for asset in CRITICAL_ASSETS.iter() {
            if lower_desc.contains(asset) {
                warn!(
                    "Threat Hunt: Critical asset access keyword '{}' detected.",
                    asset
                );
                hunt_detections["critical_asset_access"] = json!(asset);
                found_hunt_detection = true;
                break;
            }
        }
    }

    if let Some(desc) = log_data
        .get("msg")
        .or_else(|| log_data.get("logdesc"))
        .and_then(Value::as_str)
    {
        let mut matches = Vec::new();
        for (name, re) in CORRELATION_RULES_COMPILED.iter() {
            if re.is_match(desc) {
                info!("Threat Hunt: Correlation rule '{}' matched.", name);
                matches.push(json!({ "rule": name, "pattern": re.as_str() }));
            }
        }
        if !matches.is_empty() {
            hunt_detections["correlation_rules"] = Value::Array(matches);
            found_hunt_detection = true;
        }
    }

    if found_hunt_detection {
        enrichment_data["threat_hunting"] = hunt_detections;
        found_enrichment = true;
    }

    if ENABLE_BEHAVIORAL_ANALYSIS {
        state.update(&log_data);
        if let Some(anomalies) = state.is_suspicious_activity(&log_data) {
            warn!("Behavioral anomalies detected: {:?}", anomalies);
            enrichment_data["behavioral_anomalies"] = anomalies;
            found_enrichment = true;
        }
    }

    if found_enrichment {
        if let Some(obj) = log_data.as_object_mut() {
            enrichment_data["intel_last_updated"] = json!(intel.last_updated.to_rfc3339());
            obj.insert("forwarder_enrichment".to_string(), enrichment_data);
            info!("Log successfully enriched.");
        }
    }
    log_data
}
