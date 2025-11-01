use anyhow::{anyhow, Result};
use chrono::Utc;
use log::debug;
use serde_json::Value;
use std::collections::HashMap;
use crate::performance::STRING_POOL;

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

// Re-use enrichment functions from original parsing module
pub use crate::parsing::{extract_iocs, enrich_and_analyze_log};