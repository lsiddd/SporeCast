use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Let's examine the first clean log from the test file
    let sample_log = "PA-5220-1 1,2025/08/07 09:08:47,013201006880,TRAFFIC,end,2562,2025/08/07 09:08:47,10.95.1.5,172.217.150.136,177.74.63.4,172.217.150.136,ACESSO_INTERNET_SECRETARIAS,,,ssl,vsys1,CHEGADA,WAN,ae1.1000,ethernet1/20,PANORAMA-TRAFFIC_ONLY,2025/08/07 09:08:47,1674967,1,63747,443,11611,443,0x40041c,tcp,allow,3548,2925,623,15,2025/08/07 09:08:28,5,license-expired,,7359924265781034305,0x8000000000000000,10.0.0.0-10.255.255.255,United States,,8,7,tcp-fin,0,0,0,0,FW_ESTADO,PA-5220-1,from-policy,,,0,,0,,N/A,0,0,0,0,5d24f562-d05e-453c-a154-1b4a6c80d556,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-08-07T09:08:47.866-03:00,,,encrypted-tunnel,networking,browser-based,4,\"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use\",,ssl,no,no,0";

    println!("Original log:");
    println!("{}\n", sample_log);

    // Extract CSV part - skip "PA-5220-1 " prefix
    let csv_start = sample_log.find(' ').unwrap() + 1;
    let csv_content = &sample_log[csv_start..];
    
    println!("CSV content:");
    println!("{}\n", csv_content);
    
    // Parse CSV manually to debug
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(csv_content.as_bytes());
        
    if let Some(result) = reader.records().next() {
        match result {
            Ok(record) => {
                println!("CSV fields parsed ({} total):", record.len());
                for (i, field) in record.iter().enumerate() {
                    println!("  [{}]: '{}'", i, field);
                }
                
                println!("\nExpected field mapping based on Palo Alto standard:");
                let headers = [
                    "Receive Time", "Serial Number", "Type", "Threat/Content Type", "Config Version", "Generated Time",
                    "Source address", "Destination address", "NAT source IP", "NAT destination IP", "Rule Name",
                    "Source User", "Destination User", "Application", "Virtual System", "Source Zone", "Destination Zone"
                ];
                
                for (i, header) in headers.iter().enumerate() {
                    if i < record.len() {
                        println!("  {}: '{}'", header, record.get(i).unwrap_or(""));
                    }
                }
            }
            Err(e) => {
                println!("CSV parsing error: {}", e);
            }
        }
    }
    
    Ok(())
}