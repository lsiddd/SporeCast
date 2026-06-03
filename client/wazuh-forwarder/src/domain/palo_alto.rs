use crate::domain::rules::CSV_TIMESTAMP_PATTERN;
use anyhow::{anyhow, Result};
use chrono::Utc;
use log::debug;
use serde_json::Value;
use std::collections::HashMap;

mod schema;
use schema::{COMMON_HEADERS, FLOAT_FIELDS, INTEGER_FIELDS, THREAT_EXTRA_HEADERS, TRAFFIC_EXTRA_HEADERS};

// ==============================================================================
// --- Palo Alto Log Parser ---
// Parses Palo Alto PAN-OS CSV format logs into structured JSON objects.
// ==============================================================================

const PALO_ALTO_SYSLOG_PRIORITY: u16 = 134;

/// Parses a Palo Alto PAN-OS CSV/syslog line into normalized JSON fields.
pub fn parse_palo_alto_log_to_json(raw_log: &str) -> Result<Value> {
    debug!("Attempting to parse raw Palo Alto log: '{}'", raw_log);

    let mut working_string = String::new();

    // Extract the CSV part from the syslog message
    let csv_content = if let Some(device_start) = raw_log.find("PA-") {
        let device_section = &raw_log[device_start..];
        if let Some(space_pos) = device_section.find(' ') {
            &device_section[space_pos + 1..]
        } else {
            device_section
        }
    } else if let Some(m) = CSV_TIMESTAMP_PATTERN.find(raw_log) {
        let csv_start = m.start();
        if csv_start > 0 {
            let preceding = &raw_log[..csv_start];
            if let Some(space_before_num) = preceding.rfind(' ') {
                &raw_log[space_before_num + 1..]
            } else {
                raw_log
            }
        } else {
            raw_log
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

    // Detect log type from field 3 to pick the correct extra-field schema.
    let log_type = record.get(3).map(|s| s.trim()).unwrap_or("");
    let extra_headers: &[&str] = match log_type {
        "THREAT" => THREAT_EXTRA_HEADERS,
        _ => TRAFFIC_EXTRA_HEADERS, // TRAFFIC, SYSTEM, CONFIG, etc.
    };

    let mut json_map = HashMap::new();

    for (i, field) in record.iter().enumerate() {
        let field_name: &str = if i < COMMON_HEADERS.len() {
            COMMON_HEADERS[i]
        } else {
            let extra_i = i - COMMON_HEADERS.len();
            match extra_headers.get(extra_i) {
                Some(name) => name,
                None => {
                    debug!("Unknown field at position {}: {}", i, field);
                    continue;
                }
            }
        };

        let field_value = field.trim();
        if field_value.is_empty() {
            continue;
        }

        let parsed_value = if INTEGER_FIELDS.contains(&field_name) {
            match field_value.parse::<i64>() {
                Ok(num) => Value::Number(num.into()),
                Err(_) => Value::String(field_value.to_string()),
            }
        } else if FLOAT_FIELDS.contains(&field_name) {
            match field_value.parse::<f64>() {
                Ok(num) => {
                    Value::Number(serde_json::Number::from_f64(num).unwrap_or_else(|| 0.into()))
                }
                Err(_) => Value::String(field_value.to_string()),
            }
        } else {
            Value::String(field_value.to_string())
        };

        let normalized_name = field_name
            .replace(' ', "_")
            .replace('/', "_")
            .replace('-', "_")
            .to_lowercase();

        json_map.insert(normalized_name, parsed_value);
    }

    // Add metadata
    // REMOVED: The following line was removed to prevent duplicating the entire log message in memory.
    // json_map.insert("palo_alto_raw_log".to_string(), Value::String(raw_log.to_string()));
    json_map.insert(
        "@timestamp".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    json_map.insert(
        "log_source".to_string(),
        Value::String("palo_alto".to_string()),
    );

    debug!(
        "Finished parsing Palo Alto log. Resulting JSON keys: {:?}",
        json_map.keys().collect::<Vec<_>>()
    );

    Ok(Value::Object(json_map.into_iter().collect()))
}

// ==============================================================================
// --- Palo Alto Syslog Formatter ---
// Converts JSON log back to Palo Alto-compatible syslog format for Wazuh
// ==============================================================================
/// Formats a normalized Palo Alto JSON log into a Wazuh-friendly syslog line.
pub fn format_json_to_palo_alto_syslog(log_json: &Value) -> Result<String> {
    let mut parts = Vec::new();

    fn format_syslog_value(value: &Value) -> String {
        match value {
            Value::String(s) => {
                if s.contains(' ') || s.contains('"') {
                    format!("\"{}\"", s.replace('"', "\\\""))
                } else {
                    s.clone()
                }
            }
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Array(arr) => {
                let elements: Vec<String> = arr
                    .iter()
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
            parts.push(format!(
                "generated_time={}",
                format_syslog_value(generated_time)
            ));
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
            if key.starts_with("@")
                || key == "palo_alto_raw_log"
                || key == "log_source"
                || key == "forwarder_enrichment"
                || key == "device_name"
                || key == "serial_number"
                || key == "generated_time"
                || key == "source_address"
                || key == "destination_address"
                || key == "source_port"
                || key == "destination_port"
                || key == "action"
                || key == "application"
            {
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
        return Err(anyhow!(
            "Log JSON is not an object, cannot format to Palo Alto syslog."
        ));
    }

    let body = parts.join(" ");

    Ok(format!("<{}>PaloAlto: {}", PALO_ALTO_SYSLOG_PRIORITY, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Realistic TRAFFIC log line from palo_alto_pan_os_sample_firewall_realistic_v2.log
    const TRAFFIC_LOG: &str = "<14>Jun 02 13:10:01 PA-VM-01 1,2026/06/02 13:10:01,007951000123,TRAFFIC,end,2561,2026/06/02 13:10:01,10.10.10.25,198.51.100.14,192.0.2.25,198.51.100.14,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,LFP-SIEM,2026/06/02 13:10:01,4839201,1,54321,443,39321,443,0x400019,tcp,allow,48233,21132,27101,64,2026/06/02 13:09:57,3,any,,7408146363088945002,0x0,10.0.0.0-10.255.255.255,United States,,32,32,tcp-fin,0,0,0,0,,PA-VM-01,from-policy";

    // Realistic THREAT log line (SQL injection)
    const THREAT_LOG: &str = "<14>Jun 02 13:10:13 PA-VM-01 1,2026/06/02 13:10:13,007951000123,THREAT,vulnerability,2561,2026/06/02 13:10:13,10.10.30.15,203.0.113.77,0.0.0.0,0.0.0.0,allow-dmz-web,,,web-browsing,vsys1,dmz,untrust,ethernet1/4,ethernet1/1,LFP-SIEM,2026/06/02 13:10:13,4839203,1,49822,80,0,0,0x400019,tcp,reset-both,/search.php?id=1%27%20OR%201=1,HTTP SQL Injection Attempt(40001),any,high,client-to-server,7408146363088945004";

    #[test]
    fn parses_palo_alto_csv_fields_to_normalized_json() {
        let raw =
            "1,2026/06/02 12:00:00,SERIAL,TRAFFIC,threat,42,2026/06/02 12:00:01,10.0.0.1,8.8.8.8";
        let parsed = parse_palo_alto_log_to_json(raw).expect("sample CSV should parse");

        assert_eq!(parsed["log_number"], 1);
        assert_eq!(parsed["serial_number"], "SERIAL");
        assert_eq!(parsed["source_address"], "10.0.0.1");
        assert_eq!(parsed["destination_address"], "8.8.8.8");
        assert_eq!(parsed["log_source"], "palo_alto");
    }

    #[test]
    fn parses_realistic_traffic_log_with_syslog_prefix() {
        let parsed = parse_palo_alto_log_to_json(TRAFFIC_LOG).expect("TRAFFIC log should parse");

        assert_eq!(parsed["type"], "TRAFFIC");
        assert_eq!(parsed["source_address"], "10.10.10.25");
        assert_eq!(parsed["destination_address"], "198.51.100.14");
        assert_eq!(parsed["action"], "allow");
        assert_eq!(parsed["application"], "ssl");
        assert_eq!(parsed["serial_number"], "007951000123");
        assert_eq!(parsed["log_source"], "palo_alto");
        assert!(parsed.get("@timestamp").is_some());
    }

    #[test]
    fn parses_realistic_threat_log_fields() {
        let parsed = parse_palo_alto_log_to_json(THREAT_LOG).expect("THREAT log should parse");

        assert_eq!(parsed["type"], "THREAT");
        assert_eq!(parsed["source_address"], "10.10.30.15");
        assert_eq!(parsed["destination_address"], "203.0.113.77");
        assert_eq!(parsed["ip_protocol"], "tcp");
        assert_eq!(parsed["source_port"], 49822);
        assert_eq!(parsed["destination_port"], 80);
    }

    #[test]
    fn traffic_log_integer_fields_parsed_as_numbers() {
        let parsed = parse_palo_alto_log_to_json(TRAFFIC_LOG).expect("should parse");

        assert!(parsed["source_port"].is_number());
        assert!(parsed["destination_port"].is_number());
        assert_eq!(parsed["destination_port"], 443);
        assert_eq!(parsed["source_port"], 54321);
    }

    #[test]
    fn formats_selected_json_fields_as_syslog() {
        let log = json!({
            "device_name": "pa-01",
            "serial_number": "SERIAL",
            "source_address": "10.0.0.1",
            "destination_address": "8.8.8.8",
            "action": "allow"
        });

        let formatted = format_json_to_palo_alto_syslog(&log).expect("object should format");

        assert!(formatted.starts_with("<134>PaloAlto:"));
        assert!(formatted.contains("device_name=pa-01"));
        assert!(formatted.contains("src_ip=10.0.0.1"));
        assert!(formatted.contains("dst_ip=8.8.8.8"));
    }

    #[test]
    fn full_round_trip_parse_then_format() {
        let parsed = parse_palo_alto_log_to_json(TRAFFIC_LOG).expect("should parse");
        let formatted = format_json_to_palo_alto_syslog(&parsed).expect("should format");

        assert!(formatted.starts_with("<134>PaloAlto:"));
        assert!(formatted.contains("src_ip=10.10.10.25"));
        assert!(formatted.contains("dst_ip=198.51.100.14"));
        assert!(formatted.contains("action=allow"));
    }
}
