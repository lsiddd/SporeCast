use serde_json::Value;
use std::sync::Arc;
use wazuh_forwarder::{
    behavioral::AlertHistory,
    palo_alto_parsing::{enrich_and_analyze_log, parse_palo_alto_log_to_json},
    threat_intel::ThreatIntel,
};

fn main() {
    // Initialize test data with sample Palo Alto log
    let sample_log = r#"<14>Aug 19 10:49:56 PA-5220-1 1,2025/08/19 10:49:56,013201006880,TRAFFIC,end,2562,2025/08/19 10:49:56,177.74.1.41,10.1.13.87,0.0.0.0,0.0.0.0,DMZ1-HAPROXY-1-1-1-2,,,incomplete,vsys2,CHEGADA_INT,REDE13,ae1.3010,ae1.3005,PANORAMA,2025/08/19 10:49:56,2120706,1,34770,8180,0,0,0x1a,tcp,allow,226,148,78,3,2025/08/19 10:49:45,0,any,,7359924275596011931,0x8000000000000000,Brazil,10.0.0.0-10.255.255.255,,2,1,tcp-rst-from-client,0,0,0,0,DMZ_INTERNAS,PA-5220-1,from-policy,,,0,,0,,N/A,0,0,0,0,5eabeee6-a418-473a-9dd3-e6a870928b4c,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-08-19T10:49:56.644-03:00,,,unknown,unknown,unknown,1,,,incomplete,no,no,0"#;

    println!("Testing Palo Alto Log Parsing and Threat Intelligence");
    println!("=====================================================");
    println!();

    // Test 1: Parse Palo Alto log
    println!("1. Testing Palo Alto log parsing...");
    match parse_palo_alto_log_to_json(sample_log) {
        Ok(parsed_json) => {
            println!("✅ Successfully parsed Palo Alto log");
            
            // Extract key fields to verify parsing
            let extract_field = |json: &Value, field: &str| -> String {
                json.get(field)
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => "N/A".to_string()
                    })
                    .unwrap_or("N/A".to_string())
            };

            println!("   - Source IP: {}", extract_field(&parsed_json, "source_address"));
            println!("   - Destination IP: {}", extract_field(&parsed_json, "destination_address"));
            println!("   - Source Port: {} (raw: {})", extract_field(&parsed_json, "source_port"), extract_field(&parsed_json, "Source Port"));
            println!("   - Destination Port: {} (raw: {})", extract_field(&parsed_json, "destination_port"), extract_field(&parsed_json, "Destination Port"));
            println!("   - Application: {}", extract_field(&parsed_json, "application"));
            println!("   - Action: {}", extract_field(&parsed_json, "action"));

            // Test 2: Threat Intelligence Enrichment
            println!("\n2. Testing threat intelligence enrichment...");
            
            // Create threat intel database with sample malicious IPs
            let mut threat_intel = ThreatIntel::new();
            
            // Add a malicious IP to test detection (using an IP from the log)
            let mut malicious_ips = std::collections::HashMap::new();
            malicious_ips.insert("177.74.1.41".to_string(), vec!["test_feed".to_string()]);
            threat_intel.malicious_ips = Arc::new(malicious_ips);
            
            let intel_arc = Arc::new(threat_intel);
            let mut alert_history = AlertHistory::default();
            
            // Test enrichment
            let enriched_log = enrich_and_analyze_log(parsed_json.clone(), &intel_arc, &mut alert_history);
            
            // Check if enrichment was applied
            if let Some(enrichment) = enriched_log.get("forwarder_enrichment") {
                println!("✅ Log successfully enriched with threat intelligence");
                
                if let Some(ioc_matches) = enrichment.get("ioc_matches") {
                    println!("   - IOC matches found:");
                    if let Some(malicious_ips) = ioc_matches.get("malicious_ips") {
                        println!("     * Malicious IPs: {}", malicious_ips);
                    }
                } else {
                    println!("   - No IOC matches found (expected for clean IPs)");
                }
                
                if let Some(behavioral) = enrichment.get("behavioral_anomalies") {
                    println!("   - Behavioral anomalies: {}", behavioral);
                }
                
                if let Some(hunt) = enrichment.get("threat_hunting") {
                    println!("   - Threat hunting detections: {}", hunt);
                }
                
                println!("   - Intel last updated: {}", enrichment.get("intel_last_updated").unwrap_or(&Value::String("N/A".to_string())));
            } else {
                println!("❌ No enrichment data found");
            }

            // Test 3: Pattern Recognition
            println!("\n3. Testing pattern recognition capabilities...");
            
            // Count fields extracted
            if let Some(obj) = parsed_json.as_object() {
                println!("   - Total fields extracted: {}", obj.len());
                // Print first 20 field names for readability
                let field_names: Vec<&String> = obj.keys().collect();
                println!("   - First 20 fields: {:?}", &field_names[..20.min(field_names.len())]);
                
                // Check specific port values
                if let Some(sport) = obj.get("source_port") {
                    println!("   - Source port value: {:?}", sport);
                }
                if let Some(dport) = obj.get("destination_port") {
                    println!("   - Destination port value: {:?}", dport);
                }
            }

            // Test 4: IOC Extraction
            println!("\n4. Testing IOC extraction...");
            let iocs = wazuh_forwarder::parsing::extract_iocs(&parsed_json);
            for (ioc_type, values) in &iocs {
                if !values.is_empty() {
                    println!("   - {}: {:?}", ioc_type, values);
                }
            }

            println!("\n✅ All parsing tests completed successfully!");

        }
        Err(e) => {
            println!("❌ Failed to parse Palo Alto log: {}", e);
        }
    }
}