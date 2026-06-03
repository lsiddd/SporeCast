use log::{debug, info, warn};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

use crate::domain::behavioral::AlertHistory;
use crate::domain::indicators::{is_public_ip, ThreatIntel};
use crate::domain::ports::GeoIpLookup;
use crate::domain::rules::{
    CORRELATION_RULES_COMPILED, CRITICAL_ASSETS, DOMAIN_REGEX, ENABLE_BEHAVIORAL_ANALYSIS,
    HASH_REGEX, IP_REGEX, SUSPICIOUS_PATTERNS_COMPILED, SUSPICIOUS_PROCESSES, URL_REGEX,
};
use std::collections::HashSet;

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

    let find_recursive = |value: &Value, f: &mut dyn FnMut(&str)| {
        fn inner(value: &Value, f: &mut dyn FnMut(&str)) {
            match value {
                Value::Object(map) => map.values().for_each(|v| inner(v, f)),
                Value::Array(arr) => arr.iter().for_each(|v| inner(v, f)),
                Value::String(s) => f(s),
                _ => {}
            }
        }
        inner(value, f);
    };

    find_recursive(log_data, &mut collect_matches);
    for values in iocs.values_mut() {
        let mut seen = HashSet::new();
        values.retain(|value| seen.insert(value.clone()));
    }
    debug!("Extracted IOCs: {:?}", iocs);
    iocs
}

/// Adds threat-intelligence, hunting, behavioral, and GeoIP enrichment to a parsed log.
pub fn enrich_and_analyze_log(
    mut log_data: Value,
    intel: &Arc<ThreatIntel>,
    state: &mut AlertHistory,
    geoip: Option<&dyn GeoIpLookup>,
) -> Value {
    debug!("Starting enrichment and analysis for log.");
    let mut enrichment_data = json!({});
    let mut found_enrichment = false;

    if let Some(ioc_matches) = enrich_ioc_matches(&log_data, intel) {
        enrichment_data["ioc_matches"] = ioc_matches;
        found_enrichment = true;
    }

    if let Some(hunt) = enrich_threat_hunt(&log_data) {
        enrichment_data["threat_hunting"] = hunt;
        found_enrichment = true;
    }

    if ENABLE_BEHAVIORAL_ANALYSIS {
        if let Some(anomalies) = enrich_behavioral(&log_data, state) {
            enrichment_data["behavioral_anomalies"] = anomalies;
            found_enrichment = true;
        }
    }

    if let Some(geoip_data) = enrich_geoip(&log_data, geoip) {
        enrichment_data["geoip"] = geoip_data;
        found_enrichment = true;
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

fn enrich_ioc_matches(log_data: &Value, intel: &Arc<ThreatIntel>) -> Option<Value> {
    let iocs = extract_iocs(log_data);
    let mut result = json!({});
    let mut found = false;

    if let Some(ips) = iocs.get("ip") {
        let hits: Vec<_> = ips
            .iter()
            .filter_map(|ip| {
                intel.malicious_ips.get(ip).map(|sources| {
                    info!(
                        "Threat Intel Match: Malicious IP '{}' from feeds: {:?}",
                        ip, sources
                    );
                    json!({
                        "ip": ip, "status": "blocklisted",
                        "sources": sources, "source_count": sources.len()
                    })
                })
            })
            .collect();
        if !hits.is_empty() {
            result["malicious_ips"] = Value::Array(hits);
            found = true;
        }
    }

    if let Some(domains) = iocs.get("domain") {
        let hits: Vec<_> = domains
            .iter()
            .filter(|d| intel.malicious_domains.contains(*d))
            .collect();
        if !hits.is_empty() {
            info!("Threat Intel Match: Malicious domain(s): {:?}", hits);
            result["malicious_domains"] = json!(hits);
            found = true;
        }
    }

    if let Some(hashes) = iocs.get("hash") {
        let hits: Vec<_> = hashes
            .iter()
            .filter(|h| intel.malicious_hashes.contains(*h))
            .collect();
        if !hits.is_empty() {
            info!("Threat Intel Match: Malicious hash(es): {:?}", hits);
            result["malicious_hashes"] = json!(hits);
            found = true;
        }
    }

    if let Some(urls) = iocs.get("url") {
        let hits: Vec<_> = urls
            .iter()
            .filter(|u| intel.malicious_urls.contains(*u))
            .collect();
        if !hits.is_empty() {
            info!("Threat Intel Match: Malicious URL(s): {:?}", hits);
            result["malicious_urls"] = json!(hits);
            found = true;
        }
    }

    found.then_some(result)
}

fn collect_all_strings(value: &Value) -> Vec<String> {
    fn inner(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => map.values().for_each(|v| inner(v, out)),
            Value::Array(arr) => arr.iter().for_each(|v| inner(v, out)),
            Value::String(s) => out.push(s.clone()),
            _ => {}
        }
    }
    let mut out = Vec::new();
    inner(value, &mut out);
    out
}

fn enrich_threat_hunt(log_data: &Value) -> Option<Value> {
    let mut hunt = json!({});
    let mut found = false;

    // Suspicious pattern scan across all string fields
    let mut pattern_hits: Vec<Value> = Vec::new();
    fn scan_patterns(value: &Value, path: String, hits: &mut Vec<Value>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    scan_patterns(val, new_path, hits);
                }
            }
            Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    scan_patterns(val, format!("{}[{}]", path, i), hits);
                }
            }
            Value::String(s) => {
                for (name, re) in SUSPICIOUS_PATTERNS_COMPILED.iter() {
                    if re.is_match(s) {
                        warn!(
                            "Threat Hunt: Suspicious pattern '{}' in field '{}'.",
                            name, path
                        );
                        hits.push(json!({
                            "pattern": name,
                            "field_path": path,
                            "sample": s.chars().take(100).collect::<String>()
                        }));
                    }
                }
            }
            _ => {}
        }
    }
    scan_patterns(log_data, String::new(), &mut pattern_hits);
    if !pattern_hits.is_empty() {
        hunt["suspicious_patterns"] = Value::Array(pattern_hits);
        found = true;
    }

    // Scan all string fields for suspicious processes and correlation rules.
    // This covers palo_alto (application, rule_name, etc.) and tshark (protocols)
    // in addition to traditional syslog fields (msg, logdesc, eventdescription).
    let all_strings = collect_all_strings(log_data);
    let combined = all_strings.join(" ");
    let combined_lower = combined.to_lowercase();

    for process in SUSPICIOUS_PROCESSES.iter() {
        if combined_lower.contains(process) {
            warn!(
                "Threat Hunt: Suspicious process/keyword '{}' detected.",
                process
            );
            hunt["suspicious_process"] = json!(process);
            found = true;
            break;
        }
    }

    for asset in CRITICAL_ASSETS.iter() {
        if combined_lower.contains(asset) {
            warn!("Threat Hunt: Critical asset access '{}' detected.", asset);
            hunt["critical_asset_access"] = json!(asset);
            found = true;
            break;
        }
    }

    let rule_matches: Vec<_> = CORRELATION_RULES_COMPILED
        .iter()
        .filter(|(_, re)| re.is_match(&combined))
        .map(|(name, re)| {
            info!("Threat Hunt: Correlation rule '{}' matched.", name);
            json!({ "rule": name, "pattern": re.as_str() })
        })
        .collect();
    if !rule_matches.is_empty() {
        hunt["correlation_rules"] = Value::Array(rule_matches);
        found = true;
    }

    found.then_some(hunt)
}

fn enrich_behavioral(log_data: &Value, state: &mut AlertHistory) -> Option<Value> {
    state.update(log_data);
    if let Some(anomalies) = state.is_suspicious_activity(log_data) {
        warn!("Behavioral anomalies detected: {:?}", anomalies);
        Some(anomalies)
    } else {
        None
    }
}

fn enrich_geoip(log_data: &Value, geoip: Option<&dyn GeoIpLookup>) -> Option<Value> {
    let geo = geoip?;
    let mut geoip_data = json!({});
    let mut found = false;

    if let Some(src) = log_data
        .get("source_address")
        .and_then(Value::as_str)
        .filter(|ip| is_public_ip(ip))
        .and_then(|ip| geo.lookup(ip))
    {
        geoip_data["src"] = src;
        found = true;
    }

    if let Some(dst) = log_data
        .get("destination_address")
        .and_then(Value::as_str)
        .filter(|ip| is_public_ip(ip))
        .and_then(|ip| geo.lookup(ip))
    {
        geoip_data["dst"] = dst;
        found = true;
    }

    found.then_some(geoip_data)
}
