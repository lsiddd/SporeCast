use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info, warn};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use crate::performance::STRING_POOL;
use crate::behavioral::AlertHistory;
use crate::unified_config::*;
use crate::threat_intel::ThreatIntel;

// ==============================================================================
// --- Palo Alto Log Parser ---
// Parses Palo Alto PAN-OS CSV format logs into structured JSON objects.
// ==============================================================================

// Field headers for Palo Alto Traffic logs
const PALO_ALTO_HEADERS: &[&str] = &[
    "Log Number", "Receive Time", "Serial Number", "Type", "Threat/Content Type", "Config Version", "Generated Time",
    "Source address", "Destination address", "NAT source IP", "NAT destination IP", "Rule Name",
    "Source User", "Destination User", "Application", "Virtual System", "Source Zone", "Destination Zone",
    "Inbound Interface", "Outbound Interface", "Log Action", "Time Logged", "Session ID", "Repeat Count",
    "Source Port", "Destination Port", "NAT Source Port", "NAT Destination Port", "Flags", "IP Protocol",
    "Action", "Bytes", "Bytes Sent", "Bytes Received", "Packets", "Start Time", "Elapsed Time in seconds",
    "Category", "Padding", "Sequence Number", "Action Flags", "Source Location", "Destination Location",
    "Padding-2", "Packets Sent", "Packets Received", "Session End Reason", "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2", "Device Group Hierarchy Level 3", "Device Group Hierarchy Level 4",
    "Virtual System Name", "Device Name", "Action Source", "Source VM UUID", "Destination VM UUID",
    "Tunnel ID/IMSI", "Monitor Tag/IMEI", "Parent Session ID", "Parent Start Time", "Tunnel Type",
    "SCTP Association ID", "SCTP Chunks", "SCTP Chunks Sent", "SCTP Chunks Received", "UUID for rule",
    "HTTP/2 Connection", "Application-Level-Link-Changes", "Policy-ID", "Link-Switches", "SD-WAN-Cluster",
    "SD-WAN-Device-Type", "SD-WAN-Cluster-Type", "SD-WAN-Site", "Dynamic-User-Group-Name",
    "X-Forwarded-For-Address", "Source-Device-Category", "Source-Device-Profile", "Source-Device-Model",
    "Source-Device-Vendor", "Source-Device-OS-Family", "Source-Device-OS-Version", "Source-Hostname",
    "Source-MAC-Address", "Destination-Device-Category", "Destination-Device-Profile",
    "Destination-Device-Model", "Destination-Device-Vendor", "Destination-Device-OS-Family",
    "Destination-Device-OS-Version", "Destination-Hostname", "Destination-MAC-Address", "Container-ID",
    "POD-Namespace", "POD-Name", "Source-External-Dynamic-List", "Destination-External-Dynamic-List",
    "Host-ID", "User-Device-Serial-Number", "Source-Dynamic-Address-Group", "Destination-Dynamic-Address-Group",
    "Session-Owner", "High-Resolution-Timestamp", "A-Slice-Service-Type", "A-Slice-Differentiator",
    "Application-Subcategory", "Application-Category", "Application-Technology", "Application-Risk",
    "Application-Characteristics", "Application-Container-Name", "Tunneled-Application", "is-SAAS-App",
    "Application-Sanctioned-State", "Offloaded"
];

// Fields that should be parsed as integers
const INTEGER_FIELDS: &[&str] = &[
    "Config Version", "Session ID", "Repeat Count", "Source Port", "Destination Port", 
    "NAT Source Port", "NAT Destination Port", "Bytes", "Bytes Sent", "Bytes Received", 
    "Packets", "Elapsed Time in seconds", "Sequence Number", "Packets Sent", "Packets Received",
    "Policy-ID", "Link-Switches", "Application-Risk"
];

// Fields that should be parsed as floats  
const FLOAT_FIELDS: &[&str] = &["High-Resolution-Timestamp"];

pub fn parse_palo_alto_log_to_json(raw_log: &str) -> Result<Value> {
    debug!("Attempting to parse raw Palo Alto log: '{}'", raw_log);
    
    let mut working_string = STRING_POOL.get_string();
    
    // Extract the CSV part from the syslog message
    let csv_content = if let Some(device_start) = raw_log.find("PA-") {
        let device_section = &raw_log[device_start..];
        if let Some(space_pos) = device_section.find(' ') {
            &device_section[space_pos + 1..]
        } else {
            device_section
        }
    } else if let Some(csv_start) = raw_log.find(",2025/") {
        if csv_start > 0 {
            let preceding = &raw_log[..csv_start];
            if let Some(space_before_num) = preceding.rfind(' ') {
                &raw_log[space_before_num + 1..]
            } else {
                &raw_log[csv_start..]
            }
        } else {
            &raw_log[csv_start..]
        }
    } else if let Some(angle_bracket_end) = raw_log.find('>') {
        &raw_log[angle_bracket_end + 1..]
    } else {
        raw_log
    };
    
    working_string.push_str(csv_content);

    debug!("Extracted CSV content: '{}'", csv_content);

    // Parse CSV fields synchronously
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(working_string.as_bytes());

    let record = match reader.records().next() {
        Some(Ok(record)) => record,
        Some(Err(e)) => return Err(anyhow!("CSV parsing error: {}", e)),
        None => return Err(anyhow!("No CSV records found in log")),
    };

    let mut json_map = HashMap::new();
    
    // Map CSV fields to JSON using headers
    for (i, field) in record.iter().enumerate() {
        let field_name = if i < PALO_ALTO_HEADERS.len() {
            PALO_ALTO_HEADERS[i]
        } else {
            debug!("Unknown field at position {}: {}", i, field);
            continue;
        };

        let field_value = field.trim();
        if field_value.is_empty() {
            continue;
        }

        // Parse based on field type
        let parsed_value = if INTEGER_FIELDS.contains(&field_name) {
            match field_value.parse::<i64>() {
                Ok(num) => Value::Number(num.into()),
                Err(_) => Value::String(field_value.to_string()),
            }
        } else if FLOAT_FIELDS.contains(&field_name) {
            match field_value.parse::<f64>() {
                Ok(num) => Value::Number(serde_json::Number::from_f64(num).unwrap_or_else(|| 0.into())),
                Err(_) => Value::String(field_value.to_string()),
            }
        } else {
            Value::String(field_value.to_string())
        };

        let normalized_name = field_name.replace(" ", "_")
            .replace("/", "_")
            .replace("-", "_")
            .to_lowercase();
            
        json_map.insert(normalized_name, parsed_value);
    }

    // Add metadata
    json_map.insert("palo_alto_raw_log".to_string(), Value::String(raw_log.to_string()));
    json_map.insert("@timestamp".to_string(), Value::String(Utc::now().to_rfc3339()));
    json_map.insert("log_source".to_string(), Value::String("palo_alto".to_string()));

    debug!("Finished parsing Palo Alto log. Resulting JSON keys: {:?}", json_map.keys().collect::<Vec<_>>());
    
    STRING_POOL.return_string(working_string);
    
    Ok(Value::Object(json_map.into_iter().collect()))
}

// ==============================================================================
// --- Palo Alto Syslog Formatter ---
// Converts JSON log back to Palo Alto-compatible syslog format for Wazuh
// ==============================================================================
pub fn format_json_to_palo_alto_syslog(log_json: &Value) -> Result<String> {
    let mut parts = Vec::new();

    fn format_syslog_value(value: &Value) -> String {
        match value {
            Value::String(s) => {
                if s.contains(' ') || s.contains('"') {
                    format!("\"{}\"", s.replace("\"", "\\\""))
                } else {
                    s.clone()
                }
            }
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Array(arr) => {
                let elements: Vec<String> = arr.iter()
                    .map(|elem| format_syslog_value(elem).replace("\"", ""))
                    .collect();
                format!("\"{}\"", elements.join(","))
            }
            Value::Null => "".to_string(),
            _ => "".to_string(),
        }
    }

    if let Some(obj) = log_json.as_object() {
        if let Some(device) = obj.get("device_name") {
            parts.push(format!("device_name={}", format_syslog_value(device)));
        }
        if let Some(serial) = obj.get("serial_number") {
            parts.push(format!("serial_number={}", format_syslog_value(serial)));
        }
        if let Some(generated_time) = obj.get("generated_time") {
            parts.push(format!("generated_time={}", format_syslog_value(generated_time)));
        }
        if let Some(src_addr) = obj.get("source_address") {
            parts.push(format!("src_ip={}", format_syslog_value(src_addr)));
        }
        if let Some(dst_addr) = obj.get("destination_address") {
            parts.push(format!("dst_ip={}", format_syslog_value(dst_addr)));
        }
        if let Some(src_port) = obj.get("source_port") {
            parts.push(format!("src_port={}", format_syslog_value(src_port)));
        }
        if let Some(dst_port) = obj.get("destination_port") {
            parts.push(format!("dst_port={}", format_syslog_value(dst_port)));
        }
        if let Some(action) = obj.get("action") {
            parts.push(format!("action={}", format_syslog_value(action)));
        }
        if let Some(app) = obj.get("application") {
            parts.push(format!("application={}", format_syslog_value(app)));
        }

        for (key, value) in obj {
            if key.starts_with("@") || 
               key == "palo_alto_raw_log" || 
               key == "log_source" ||
               key == "forwarder_enrichment" ||
               key == "device_name" || key == "serial_number" || key == "generated_time" ||
               key == "source_address" || key == "destination_address" ||
               key == "source_port" || key == "destination_port" ||
               key == "action" || key == "application" {
                continue;
            }

            let formatted_value = format_syslog_value(value);
            if !formatted_value.is_empty() {
                parts.push(format!("{}={}", key, formatted_value));
            }
        }

        if let Some(enrichment) = obj.get("forwarder_enrichment") {
            if let Some(enrich_obj) = enrichment.as_object() {
                for (enrich_key, enrich_value) in enrich_obj {
                    let formatted = format_syslog_value(enrich_value);
                    if !formatted.is_empty() {
                        parts.push(format!("enrich_{}={}", enrich_key, formatted));
                    }
                }
            }
        }
    } else {
        return Err(anyhow!("Log JSON is not an object, cannot format to Palo Alto syslog."));
    }

    let body = parts.join(" ");
    
    let priority = 134;
    
    Ok(format!("<{}>PaloAlto: {}", priority, body))
}

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

// Main function for enriching and analyzing a single log.
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

    // Suspicious Processes: Checks for known suspicious process names in relevant log fields.
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