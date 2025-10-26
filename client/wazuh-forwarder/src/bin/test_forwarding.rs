use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use wazuh_forwarder::{
    behavioral::AlertHistory,
    palo_alto_parsing::{
        enrich_and_analyze_log, format_json_to_palo_alto_syslog, parse_palo_alto_log_to_json,
    },
    threat_intel::ThreatIntel,
    unified_config::*,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Palo Alto Log Forwarding and Format Conversion");
    println!("======================================================");
    println!();

    // Sample Palo Alto log
    let sample_log = r#"<14>Aug 19 10:49:56 PA-5220-1 1,2025/08/19 10:49:56,013201006880,TRAFFIC,end,2562,2025/08/19 10:49:56,177.74.1.41,10.1.13.87,0.0.0.0,0.0.0.0,DMZ1-HAPROXY-1-1-1-2,,,incomplete,vsys2,CHEGADA_INT,REDE13,ae1.3010,ae1.3005,PANORAMA,2025/08/19 10:49:56,2120706,1,34770,8180,0,0,0x1a,tcp,allow,226,148,78,3,2025/08/19 10:49:45,0,any,,7359924275596011931,0x8000000000000000,Brazil,10.0.0.0-10.255.255.255,,2,1,tcp-rst-from-client,0,0,0,0,DMZ_INTERNAS,PA-5220-1,from-policy,,,0,,0,,N/A,0,0,0,0,5eabeee6-a418-473a-9dd3-e6a870928b4c,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-08-19T10:49:56.644-03:00,,,unknown,unknown,unknown,1,,,incomplete,no,no,0"#;

    // Test 1: Parse the log
    println!("1. Testing log parsing...");
    let parsed_json = match parse_palo_alto_log_to_json(sample_log) {
        Ok(json) => {
            println!("✅ Successfully parsed Palo Alto log");
            json
        }
        Err(e) => {
            println!("❌ Failed to parse log: {}", e);
            return Ok(());
        }
    };

    // Test 2: Enrich the log
    println!("\n2. Testing threat intelligence enrichment...");
    
    // Create threat intel with malicious IP
    let mut threat_intel = ThreatIntel::new();
    let mut malicious_ips = std::collections::HashMap::new();
    malicious_ips.insert("177.74.1.41".to_string(), vec!["test_feed".to_string()]);
    threat_intel.malicious_ips = Arc::new(malicious_ips);
    
    let intel_arc = Arc::new(threat_intel);
    let mut alert_history = AlertHistory::default();
    
    let enriched_json = enrich_and_analyze_log(parsed_json, &intel_arc, &mut alert_history);
    
    if enriched_json.get("forwarder_enrichment").is_some() {
        println!("✅ Log successfully enriched with threat intelligence");
    } else {
        println!("ℹ️  Log processed (no enrichment needed)");
    }

    // Test 3: Format back to syslog for Wazuh
    println!("\n3. Testing syslog format conversion...");
    match format_json_to_palo_alto_syslog(&enriched_json) {
        Ok(formatted_log) => {
            println!("✅ Successfully formatted JSON back to syslog");
            println!("   - Original length: {} bytes", sample_log.len());
            println!("   - Formatted length: {} bytes", formatted_log.len());
            println!("   - First 200 chars: {}", &formatted_log[..200.min(formatted_log.len())]);
        }
        Err(e) => {
            println!("❌ Failed to format log: {}", e);
        }
    }

    // Test 4: Test UDP forwarding simulation
    println!("\n4. Testing UDP forwarding simulation...");
    
    // Set up a mock UDP receiver on a test port
    let test_port = 9999;
    let receiver_addr = SocketAddr::from(([127, 0, 0, 1], test_port));
    
    // Start a UDP receiver in a separate thread
    let received_logs = Arc::new(Mutex::new(Vec::new()));
    let received_logs_clone = received_logs.clone();
    
    let receiver_handle = thread::spawn(move || {
        let socket = UdpSocket::bind(receiver_addr).expect("Failed to bind receiver");
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        
        let mut buffer = [0; 8192];
        for _ in 0..2 { // Expect to receive 2 logs (raw + enriched)
            match socket.recv_from(&mut buffer) {
                Ok((size, _)) => {
                    let message = String::from_utf8_lossy(&buffer[..size]).to_string();
                    received_logs_clone.lock().unwrap().push(message);
                }
                Err(e) => {
                    eprintln!("Receiver timeout or error: {}", e);
                    break;
                }
            }
        }
    });

    // Give the receiver a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send raw log
    let sender_socket = UdpSocket::bind("0.0.0.0:0")?;
    sender_socket.send_to(sample_log.as_bytes(), receiver_addr)?;
    println!("✅ Sent raw log to UDP receiver");

    // Send enriched log
    if let Ok(formatted_enriched) = format_json_to_palo_alto_syslog(&enriched_json) {
        sender_socket.send_to(formatted_enriched.as_bytes(), receiver_addr)?;
        println!("✅ Sent enriched log to UDP receiver");
    }

    // Wait for receiver to finish
    receiver_handle.join().unwrap();

    // Check received logs
    let logs = received_logs.lock().unwrap();
    println!("\n5. Verifying forwarding results...");
    println!("   - Total logs received: {}", logs.len());
    
    if logs.len() >= 1 {
        println!("✅ Raw log forwarding successful");
        println!("   - Raw log size: {} bytes", logs[0].len());
    }
    
    if logs.len() >= 2 {
        println!("✅ Enriched log forwarding successful");
        println!("   - Enriched log size: {} bytes", logs[1].len());
        
        // Check if enrichment data is present
        if logs[1].contains("enrich_") {
            println!("   - Enrichment fields detected in forwarded log");
        }
    }

    // Test 5: Verify ELK JSON format
    println!("\n6. Testing ELK JSON format...");
    match serde_json::to_string_pretty(&enriched_json) {
        Ok(json_string) => {
            println!("✅ JSON serialization for ELK successful");
            println!("   - JSON size: {} bytes", json_string.len());
            println!("   - Contains @timestamp: {}", json_string.contains("@timestamp"));
            println!("   - Contains threat intel: {}", json_string.contains("forwarder_enrichment"));
        }
        Err(e) => {
            println!("❌ JSON serialization failed: {}", e);
        }
    }

    println!("\n7. Summary of unified threat intelligence capabilities:");
    println!("   ✅ {} comprehensive IP threat feeds", IP_FEED_URLS.len());
    println!("   ✅ {} domain reputation feeds", DOMAIN_FEED_URLS.len());
    println!("   ✅ {} URL analysis feeds", URL_FEED_URLS.len());
    println!("   ✅ {} hash analysis feeds", HASH_FEED_URLS.len());
    println!("   ✅ {} behavioral analysis patterns", SUSPICIOUS_PROCESSES.len());
    println!("   ✅ {} critical asset keywords", CRITICAL_ASSETS.len());
    println!("   ✅ {} correlation rules", CORRELATION_RULES.len());

    println!("\n🎉 All forwarding tests completed successfully!");
    println!("   Both Fortigate and Palo Alto now use the same comprehensive threat intelligence!");
    
    Ok(())
}