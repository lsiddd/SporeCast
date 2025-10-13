use wazuh_forwarder::palo_alto_parsing::parse_palo_alto_log_to_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Test with a sample Palo Alto log from the test file
    let sample_log = "PA-5220-1 1,2025/08/07 09:08:47,013201006880,TRAFFIC,end,2562,2025/08/07 09:08:47,10.95.1.5,172.217.150.136,177.74.63.4,172.217.150.136,ACESSO_INTERNET_SECRETARIAS,,,ssl,vsys1,CHEGADA,WAN,ae1.1000,ethernet1/20,PANORAMA-TRAFFIC_ONLY,2025/08/07 09:08:47,1674967,1,63747,443,11611,443,0x40041c,tcp,allow,3548,2925,623,15,2025/08/07 09:08:28,5,license-expired,,7359924265781034305,0x8000000000000000,10.0.0.0-10.255.255.255,United States,,8,7,tcp-fin,0,0,0,0,FW_ESTADO,PA-5220-1,from-policy,,,0,,0,,N/A,0,0,0,0,5d24f562-d05e-453c-a154-1b4a6c80d556,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-08-07T09:08:47.866-03:00,,,encrypted-tunnel,networking,browser-based,4,\"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use\",,ssl,no,no,0";

    println!("Testing Palo Alto log parser with sample log...");
    println!("Sample log: {}", sample_log);
    println!();

    match parse_palo_alto_log_to_json(sample_log) {
        Ok(parsed_json) => {
            println!("✅ Successfully parsed Palo Alto log!");
            println!("Parsed JSON (pretty-printed):");
            println!("{}", serde_json::to_string_pretty(&parsed_json)?);
            
            // Test specific fields
            if let Some(src_addr) = parsed_json.get("source_address") {
                println!("\n📊 Source Address: {}", src_addr);
            }
            if let Some(dst_addr) = parsed_json.get("destination_address") {
                println!("📊 Destination Address: {}", dst_addr);
            }
            if let Some(action) = parsed_json.get("action") {
                println!("📊 Action: {}", action);
            }
            if let Some(app) = parsed_json.get("application") {
                println!("📊 Application: {}", app);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to parse Palo Alto log: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}