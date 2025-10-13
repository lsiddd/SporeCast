use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info, warn};
use serde_json::{json, Value};
use std::{
    borrow::Cow,
    collections::HashMap,
    sync::Arc,
};

use crate::behavioral::AlertHistory;
use crate::config::*;
use crate::threat_intel::ThreatIntel;

// ==============================================================================
// --- Threat Hunting & Enrichment ---
// Functions to extract Indicators of Compromise (IOCs) and enrich logs.
// ==============================================================================

// Extracts common IOCs (IPs, domains, hashes, URLs) from all string fields in a JSON log.
pub fn extract_iocs(log_data: &Value) -> HashMap<&'static str, Vec<String>> {
    debug!("Extracting IOCs from log data.");
    let mut iocs = HashMap::new();

    // Helper closure to collect matches from a string
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

    // Recursively traverse the JSON value to find all string fields.
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
                _ => {} // Do nothing for other types (Number, Bool, Null).
            }
        }
        inner(value, f);
    };

    find_in_value_recursive_and_collect(log_data, &mut collect_matches);
    debug!("Extracted IOCs: {:?}", iocs);
    iocs
}

// Main function for enriching and analyzing a single Fortigate log.
pub fn enrich_and_analyze_log(
    mut log_data: Value,
    intel: &Arc<ThreatIntel>, // Changed to Arc<ThreatIntel>
    state: &mut AlertHistory,
) -> Value {
    debug!("Starting enrichment and analysis for log.");
    let iocs = extract_iocs(&log_data); // Extract IOCs from the current log.
    let mut enrichment_data = json!({}); // Accumulates all enrichment findings.
    let mut found_enrichment = false; // Flag to track if any enrichment occurred.

    // --- 1. Threat Intelligence IOC Matching ---
    let mut ioc_matches = json!({}); // Stores specific IOC matches.
    let mut found_ioc_match = false; // Flag for IOC matches.

    // IP Reputation Check: Checks extracted IPs against the malicious IP database.
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
        } else {
            debug!("No IP addresses extracted for IOC check.");
        }
    }

    // Domain, Hash, and URL checks: Checks extracted domains, hashes, and URLs against their respective databases.
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
        } else {
            debug!(
                "No malicious domains found among extracted domains: {:?}",
                domains
            );
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
        } else {
            debug!(
                "No malicious hashes found among extracted hashes: {:?}",
                hashes
            );
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
        } else {
            debug!("No malicious URLs found among extracted URLs: {:?}", urls);
        }
    }

    if found_ioc_match {
        enrichment_data["ioc_matches"] = ioc_matches;
        found_enrichment = true;
        debug!("IOC matches added to enrichment data.");
    } else {
        debug!("No IOC matches found for this log.");
    }

    // --- 2. Other Threat Hunting Detections ---
    let mut hunt_detections = json!({}); // Stores custom threat hunting findings.
    let mut found_hunt_detection = false; // Flag for custom hunt detections.

    // Suspicious Patterns: Looks for specific regex patterns within any string field.
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
            inner(value, path, &SUSPICIOUS_PATTERNS_COMPILED, f); // Use pre-compiled patterns
        };

    let mut collect_suspicious = |name: &str, path: &str, s: &str| {
        warn!(
            "Threat Hunt: Suspicious pattern '{}' found in field '{}'. Sample: '{}'.",
            name,
            path,
            s.chars().take(100).collect::<String>()
        );
        suspicious_patterns_found.push(json!({"pattern": name, "field_path": path, "sample": s.chars().take(100).collect::<String>()}));
        found_hunt_detection = true;
    };
    check_suspicious_patterns(&log_data, String::new(), &mut collect_suspicious);

    if !suspicious_patterns_found.is_empty() {
        hunt_detections["suspicious_patterns"] = Value::Array(suspicious_patterns_found);
        found_hunt_detection = true;
        debug!("Suspicious patterns added to threat hunting data.");
    } else {
        debug!("No suspicious patterns found in log.");
    }

    // Suspicious Processes: Checks for known suspicious process names in relevant Fortigate log fields.
    if let Some(cmd) = log_data
        .get("msg")
        .or_else(|| log_data.get("eventdescription"))
        .and_then(Value::as_str)
    {
        debug!(
            "Checking for suspicious processes in command/message: {}",
            cmd
        );
        let lower_cmd = cmd.to_lowercase(); // Convert once
        for process in SUSPICIOUS_PROCESSES.iter() {
            if lower_cmd.contains(process) {
                warn!(
                    "Threat Hunt: Suspicious process keyword '{}' detected in log.",
                    process
                );
                hunt_detections["suspicious_process"] = json!(process);
                found_hunt_detection = true;
                break; // Only need to find one match.
            }
        }
    } else {
        debug!("No command line or event description field found for suspicious process check.");
    }

    // Critical Asset Access: Checks for keywords indicating access to predefined critical assets.
    if let Some(desc) = log_data
        .get("msg")
        .or_else(|| log_data.get("logdesc"))
        .and_then(Value::as_str)
    {
        debug!(
            "Checking for critical asset access in message/log description: {}",
            desc
        );
        let lower_desc = desc.to_lowercase(); // Convert once
        for asset in CRITICAL_ASSETS.iter() {
            if lower_desc.contains(asset) {
                warn!(
                    "Threat Hunt: Critical asset access keyword '{}' detected in log.",
                    asset
                );
                hunt_detections["critical_asset_access"] = json!(asset);
                found_hunt_detection = true;
                break;
            }
        }
    } else {
        debug!("No message or log description field found for critical asset access check.");
    }

    // Correlation Rules: Applies custom correlation rules (simple regex matches) to log descriptions.
    if let Some(desc) = log_data
        .get("msg")
        .or_else(|| log_data.get("logdesc"))
        .and_then(Value::as_str)
    {
        debug!(
            "Checking correlation rules against message/log description: {}",
            desc
        );
        let mut matches = Vec::new();
        for (name, re) in CORRELATION_RULES_COMPILED.iter() {
            // Use pre-compiled regexes
            if re.is_match(desc) {
                info!(
                    "Threat Hunt: Correlation rule '{}' matched with pattern '{}'.",
                    name,
                    re.as_str()
                );
                matches.push(json!({ "rule": name, "pattern": re.as_str() }));
            }
        }
        if !matches.is_empty() {
            hunt_detections["correlation_rules"] = Value::Array(matches);
            found_hunt_detection = true;
            debug!("Correlation rule matches added to threat hunting data.");
        }
    } else {
        debug!("No message or log description field found for correlation rules check.");
    }

    if found_hunt_detection {
        enrichment_data["threat_hunting"] = hunt_detections;
        found_enrichment = true;
        debug!("Threat hunting detections added to enrichment data.");
    } else {
        debug!("No custom threat hunting detections found for this log.");
    }

    // --- 3. Behavioral Analysis ---
    if ENABLE_BEHAVIORAL_ANALYSIS {
        debug!("Performing behavioral analysis.");
        // Update the state with the current log's details *before* checking for anomalies
        // for this log, so that this log contributes to the history for *future* anomaly checks.
        state.update(&log_data);
        if let Some(anomalies) = state.is_suspicious_activity(&log_data) {
            warn!("Behavioral anomalies detected: {:?}", anomalies);
            enrichment_data["behavioral_anomalies"] = anomalies;
            found_enrichment = true;
            debug!("Behavioral anomalies added to enrichment data.");
        } else {
            debug!("No behavioral anomalies detected for this log.");
        }
    } else {
        info!("Behavioral analysis is disabled by configuration.");
    }

    // Add all aggregated enrichment data to the original log data under a specific key.
    if found_enrichment {
        if let Some(obj) = log_data.as_object_mut() {
            // Add the last update time of the intel feeds for context.
            enrichment_data["intel_last_updated"] = json!(intel.last_updated.to_rfc3339());
            obj.insert("forwarder_enrichment".to_string(), enrichment_data);
            info!("Log successfully enriched with forwarder_enrichment data.");
        } else {
            warn!("Could not add enrichment data: Log data is not a JSON object.");
        }
    } else {
        debug!("Log not enriched, no matches or anomalies found.");
    }
    log_data // Return the modified Value
}

// ==============================================================================
// --- Fortigate Syslog Parser ---
// This function parses a raw Fortigate Syslog string into a structured JSON object.
// It's designed to be robust but may need further refinement for edge cases
// or highly complex Fortigate log variations.
// ==============================================================================
pub fn parse_fortigate_log_to_json(raw_log: &str) -> Result<Value> {
    debug!("Attempting to parse raw Fortigate log: '{}'", raw_log);
    let mut json_map = HashMap::new();

    // 1. Basic Syslog header parsing (e.g., "<PRI>MESSAGE").
    let log_content_start_idx;
    if let Some(angle_bracket_end) = raw_log.find('>') {
        debug!(
            "Syslog priority header found at index {}.",
            angle_bracket_end
        );
        if let Some(priority_str) = raw_log.get(1..angle_bracket_end) {
            if let Ok(priority) = priority_str.parse::<u8>() {
                json_map.insert(
                    "syslog_priority".to_string(),
                    Value::Number(priority.into()),
                );
                let facility = priority / 8;
                let severity = priority % 8;
                json_map.insert(
                    "syslog_facility".to_string(),
                    Value::Number(facility.into()),
                );
                json_map.insert(
                    "syslog_severity".to_string(),
                    Value::Number(severity.into()),
                );
                debug!(
                    "Parsed Syslog priority: {}, facility: {}, severity: {}",
                    priority, facility, severity
                );
            } else {
                warn!("Failed to parse syslog priority string '{}'.", priority_str);
            }
        } else {
            warn!("Could not extract priority string from syslog header.");
        }
        log_content_start_idx = angle_bracket_end + 1; // Content starts after '>'
    } else {
        info!("No Syslog priority header found. Assuming full log is content.");
        log_content_start_idx = 0; // Content starts from the beginning.
    }
    let log_content = &raw_log[log_content_start_idx..];
    debug!("Log content for KV parsing: '{}'", log_content);

    // 2. Parse key=value pairs from the extracted log content.
    for cap in FORTIGATE_KV_REGEX.captures_iter(log_content) {
        let key = cap.get(1).map_or("", |m| m.as_str());

        let value_cow: Cow<'_, str> = if let Some(quoted_match) = cap.get(3) {
            // Quoted value, unescape it
            let unescaped = quoted_match.as_str().replace("\\\"", "\""); // Basic unescaping
            Cow::Owned(unescaped)
        } else if let Some(unquoted_match) = cap.get(4) {
            // Unquoted value, use directly
            Cow::Borrowed(unquoted_match.as_str())
        } else {
            // Should not happen given regex structure, but handle defensively
            Cow::Borrowed("")
        };

        let value_str = value_cow.as_ref();
        debug!(
            "Extracted key-value pair: key='{}', value_str='{}'",
            key, value_str
        );

        // Attempt to parse known numeric fields to actual numbers in JSON.
        // If parsing fails, store as a string.
        let parsed_value = match key {
            // Fields typically expected to be strings.
            "date" | "time" | "devname" | "devid" | "tz" | "type" | "subtype" | "eventtype"
            | "level" | "vd" | "srccountry" | "dstcountry" | "srcintf" | "srcintfrole"
            | "dstintf" | "dstintfrole" | "proto" | "service" | "direction" | "policytype"
            | "applist" | "action" | "appcat" | "app" | "msg" | "apprisk" | "policyname"
            | "trandisp" | "vwlquality" | "vwlname" | "utmaction" | "srchwvendor" | "devtype"
            | "osname" | "mastersrcmac" | "srcmac" | "srcserver" | "dstdevtype"
            | "masterdstmac" | "dstmac" | "dstserver" | "hostname" | "profile" | "reqtype"
            | "url" | "method" | "catdesc" => {
                debug!("Key '{}' identified as string type.", key);
                Value::String(value_str.to_string())
            }
            // Fields typically expected to be numbers (integers or floats).
            "eventtime" | "logid" | "appid" | "srcport" | "dstport" | "policyid" | "sessionid"
            | "incidentserialno" | "sentbyte" | "rcvdbyte" | "duration" | "sentpkt" | "rcvdpkt"
            | "countapp" | "cat" => {
                if let Ok(num) = value_str.parse::<i64>() {
                    debug!("Key '{}' parsed as integer: {}", key, num);
                    Value::Number(num.into())
                } else if let Ok(num) = value_str.parse::<f64>() {
                    debug!("Key '{}' parsed as float: {}", key, num);
                    Value::Number(serde_json::Number::from_f64(num).unwrap_or_else(|| 0.into()))
                } else {
                    warn!("Key '{}' expected to be numeric, but parsing failed. Storing as string: '{}'", key, value_str);
                    Value::String(value_str.to_string()) // Fallback to string if numeric parsing fails.
                }
            }
            // Fields for IP addresses, typically stored as strings.
            "srcip" | "dstip" | "transip" => {
                debug!("Key '{}' identified as IP address string.", key);
                Value::String(value_str.to_string())
            }
            // Default case: if key is not specifically matched, store as string.
            _ => {
                debug!(
                    "Key '{}' not explicitly handled. Storing as string: '{}'",
                    key, value_str
                );
                Value::String(value_str.to_string())
            }
        };
        json_map.insert(key.to_string(), parsed_value); // Insert the parsed key-value pair into the map.
    }

    // Add original raw log for debugging/completeness in the final JSON.
    json_map.insert(
        "fortigate_raw_log".to_string(),
        Value::String(raw_log.to_string()),
    );

    // Add current timestamp for ingestion into ELK.
    json_map.insert(
        "@timestamp".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );

    debug!("Finished parsing log. Resulting JSON: {:?}", json_map);
    Ok(Value::Object(json_map.into_iter().collect())) // Return the constructed JSON object as a Result.
}

// ==============================================================================
// --- Fortigate Syslog Formatter ---
// This function takes a JSON log and converts it back to a Fortigate-like syslog string.
// It prioritizes certain fields for the syslog header and formats key-value pairs.
// ==============================================================================
pub fn format_json_to_fortigate_syslog(log_json: &Value) -> Result<String> {
    let mut parts = Vec::new();

    // Helper to format a value for syslog, handling quoting and internal escaping
    fn format_syslog_value(value: &Value) -> String {
        match value {
            Value::String(s) => format!("\"{}\"", s.replace("\"", "\\\"")),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Array(arr) => {
                // For arrays, join elements with comma, quoting strings
                let elements: Vec<String> = arr.iter().map(|elem| {
                    if let Value::String(s) = elem {
                        s.replace("\"", "\\\"") // Escape quotes, but no outer quotes for array elements
                    } else {
                        elem.to_string()
                    }
                }).collect();
                elements.join(",") // Example: item1,item2,"item with space"
            },
            Value::Null => "null".to_string(), // Or choose to skip nulls if preferred
            _ => "".to_string(), // Should not happen for Value::Object in this refactored logic, but fallback
        }
    }


    // Prioritize specific fields for the beginning of the syslog message
    if let Some(date) = log_json.get("date").and_then(Value::as_str) {
        parts.push(format!("date={}", date));
    }
    if let Some(time) = log_json.get("time").and_then(Value::as_str) {
        parts.push(format!("time={}", time));
    }
    if let Some(devname) = log_json.get("devname").and_then(Value::as_str) {
        parts.push(format!("devname=\"{}\"", devname));
    }
    if let Some(devid) = log_json.get("devid").and_then(Value::as_str) {
        parts.push(format!("devid=\"{}\"", devid));
    }
    if let Some(logid) = log_json.get("logid") {
        if logid.is_u64() {
            parts.push(format!("logid={}", logid.as_u64().unwrap()));
        } else if logid.is_string() {
            parts.push(format!("logid=\"{}\"", logid.as_str().unwrap()));
        }
    }

    // Iterate over all fields in the JSON object
    if let Some(obj) = log_json.as_object() {
        for (key, value) in obj {
            // Skip fields already handled or internal/raw fields that shouldn't be in the syslog output
            if key == "date" || key == "time" || key == "devname" || key == "devid" || key == "logid"
                || key == "fortigate_raw_log" || key == "@timestamp"
                || key == "syslog_priority" || key == "syslog_facility" || key == "syslog_severity"
            {
                continue;
            }

            // --- SPECIAL HANDLING for 'forwarder_enrichment' ---
            // Instead of nesting, flatten its sub-fields with a prefix
            if key == "forwarder_enrichment" {
                if let Some(enrichment_obj) = value.as_object() {
                    for (enrich_key, enrich_value) in enrichment_obj {
                        let prefixed_key = format!("enrich_{}", enrich_key); // e.g., enrich_ioc_matches
                        
                        // Handle specific enrichment types for better flattening
                        match enrich_key.as_str() {
                            "ioc_matches" => {
                                if let Some(ioc_matches_obj) = enrich_value.as_object() {
                                    for (ioc_type, ioc_array_val) in ioc_matches_obj {
                                        if let Some(ioc_array) = ioc_array_val.as_array() {
                                            let ioc_strings: Vec<String> = ioc_array.iter().flat_map(|item| {
                                                // Extract primary identifier from each IOC object (e.g., "ip", "domain", "hash", "url")
                                                if let Some(item_obj) = item.as_object() {
                                                    if let Some(ip) = item_obj.get("ip").and_then(Value::as_str) {
                                                        Some(ip.to_string())
                                                    } else if let Some(domain) = item_obj.get("domain").and_then(Value::as_str) {
                                                        Some(domain.to_string())
                                                    } else if let Some(hash) = item_obj.get("hash").and_then(Value::as_str) {
                                                        Some(hash.to_string())
                                                    } else if let Some(url) = item_obj.get("url").and_then(Value::as_str) {
                                                        Some(url.to_string())
                                                    } else if let Some(pattern) = item_obj.get("pattern").and_then(Value::as_str) { // For suspicious patterns
                                                        Some(pattern.to_string())
                                                    } else if let Some(rule) = item_obj.get("rule").and_then(Value::as_str) { // For correlation rules
                                                        Some(rule.to_string())
                                                    } else {
                                                        None
                                                    }
                                                } else if let Some(s) = item.as_str() { // Fallback for simple string arrays
                                                    Some(s.to_string())
                                                } else {
                                                    None
                                                }
                                            }).collect();
                                            if !ioc_strings.is_empty() {
                                                parts.push(format!("enrich_ioc_{}=\"{}\"", ioc_type, ioc_strings.join(",")));
                                            }
                                        }
                                    }
                                }
                            },
                            "threat_hunting" => {
                                if let Some(hunt_obj) = enrich_value.as_object() {
                                    for (hunt_type, hunt_data) in hunt_obj {
                                        match hunt_type.as_str() {
                                            "suspicious_patterns" => {
                                                if let Some(patterns_array) = hunt_data.as_array() {
                                                    let pattern_names: Vec<String> = patterns_array.iter()
                                                        .filter_map(|p| p.get("pattern").and_then(Value::as_str).map(String::from))
                                                        .collect();
                                                    if !pattern_names.is_empty() {
                                                        parts.push(format!("enrich_hunt_patterns=\"{}\"", pattern_names.join(",")));
                                                    }
                                                }
                                            },
                                            "correlation_rules" => {
                                                if let Some(rules_array) = hunt_data.as_array() {
                                                    let rule_names: Vec<String> = rules_array.iter()
                                                        .filter_map(|r| r.get("rule").and_then(Value::as_str).map(String::from))
                                                        .collect();
                                                    if !rule_names.is_empty() {
                                                        parts.push(format!("enrich_hunt_rules=\"{}\"", rule_names.join(",")));
                                                    }
                                                }
                                            },
                                            // Handle other simple threat_hunting fields directly
                                            _ => {
                                                let formatted = format_syslog_value(hunt_data);
                                                if !formatted.is_empty() && formatted != "\"\"" && formatted != "null" {
                                                    parts.push(format!("enrich_hunt_{}={}", hunt_type, formatted));
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "behavioral_anomalies" => {
                                if let Some(anomalies_obj) = enrich_value.as_object() {
                                    for (anomaly_type, anomaly_data) in anomalies_obj {
                                        // For simplicity, just indicate presence or extract key counts
                                        let formatted = format_syslog_value(anomaly_data); // This might still be nested, but simpler than full JSON
                                        if !formatted.is_empty() && formatted != "\"\"" && formatted != "null" {
                                             parts.push(format!("enrich_behavior_{}={}", anomaly_type, formatted));
                                        }
                                    }
                                }
                            },
                            // Add other top-level enrichment fields here (e.g., intel_last_updated)
                            _ => {
                                let formatted = format_syslog_value(enrich_value);
                                if !formatted.is_empty() && formatted != "\"\"" && formatted != "null" {
                                     parts.push(format!("{}=\"{}\"", prefixed_key, formatted.trim_matches('"'))); // Remove outer quotes if already string
                                }
                            }
                        }
                    }
                }
                continue; // Skip the main "forwarder_enrichment" field as we've processed its children
            }

            // Normal field handling for non-enrichment fields
            let formatted_value = format_syslog_value(value);
            if !formatted_value.is_empty() && formatted_value != "\"\"" && formatted_value != "null" {
                parts.push(format!("{}={}", key, formatted_value));
            }
        }
    } else {
        return Err(anyhow!("Log JSON is not an object, cannot format to Fortigate syslog."));
    }

    // Join all parts with a space.
    let body = parts.join(" ");

    // Prepend a syslog header. Fortigate usually sends with facility 1 (user-level) and severity 6 (informational).
    // The original Fortigate log has a priority. We'll use 134 for user.info (16*8 + 6) or extract from original if available.
    let syslog_priority = log_json.get("syslog_priority")
        .and_then(Value::as_u64)
        .unwrap_or(134); // Default to user.info if not found

    Ok(format!("<{}>{}", syslog_priority, body))
}