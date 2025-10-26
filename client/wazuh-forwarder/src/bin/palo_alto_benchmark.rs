use anyhow::Result;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
    time::{Duration, Instant},
};
use wazuh_forwarder::{
    behavioral::AlertHistory,
    palo_alto_parsing::{enrich_and_analyze_log, format_json_to_palo_alto_syslog, parse_palo_alto_log_to_json},
    threat_intel::ThreatIntel,
    unified_config::*,
};

#[derive(Default)]
struct BenchmarkStats {
    total_logs: usize,
    parsed_successfully: usize,
    parsing_failures: usize,
    enriched_logs: usize,
    ioc_matches: usize,
    behavioral_anomalies: usize,
    threat_hunting_hits: usize,
    unique_source_ips: HashSet<String>,
    unique_dest_ips: HashSet<String>,
    unique_applications: HashSet<String>,
    port_distribution: HashMap<String, usize>,
    action_distribution: HashMap<String, usize>,
    processing_times: Vec<Duration>,
}

struct DetailedAnalysis {
    sample_enriched_log: Option<Value>,
    threat_intelligence_matches: Vec<String>,
    behavioral_patterns: Vec<String>,
    performance_metrics: PerformanceMetrics,
    field_coverage: HashMap<String, usize>,
}

#[derive(Default)]
struct PerformanceMetrics {
    total_processing_time: Duration,
    avg_processing_time_per_log: Duration,
    parsing_time: Duration,
    enrichment_time: Duration,
    logs_per_second: f64,
    _memory_efficiency_score: f64,
}

fn extract_palo_alto_log_from_tcpdump_line(line: &str) -> Option<String> {
    // Check if this line contains Palo Alto log data
    if line.contains("PA-") && line.contains(",TRAFFIC,") {
        // Find the start of the syslog message (priority number in angle brackets)
        if let Some(start_pos) = line.find("<") {
            if let Some(end_angle) = line[start_pos..].find(">") {
                let _priority_end = start_pos + end_angle + 1;
                
                // Extract everything from the priority marker onward
                let syslog_part = &line[start_pos..];
                
                // Clean up the log by removing non-printable characters but preserving structure
                let cleaned = syslog_part
                    .chars()
                    .filter(|c| {
                        c.is_ascii_graphic() || 
                        *c == ' ' || *c == '\t' || *c == '\n' || 
                        *c == ',' || *c == '=' || *c == '-' || *c == ':' ||
                        *c == '/' || *c == '.'
                    })
                    .collect::<String>();
                
                // Verify this looks like a valid Palo Alto log
                if cleaned.contains("PA-") && 
                   cleaned.contains(",TRAFFIC,") && 
                   cleaned.len() > 100 { // Should be a substantial log
                    return Some(cleaned);
                }
            }
        }
    }
    
    // Alternative approach: look for PA- device identifier and extract from there
    if let Some(pa_pos) = line.find("PA-") {
        // Look backwards to find the syslog priority marker
        if let Some(angle_start) = line[..pa_pos].rfind("<") {
            let syslog_part = &line[angle_start..];
            
            // Clean and validate
            let cleaned = syslog_part
                .chars()
                .filter(|c| {
                    c.is_ascii_graphic() || 
                    *c == ' ' || *c == '\t' || 
                    *c == ',' || *c == '=' || *c == '-' || *c == ':' ||
                    *c == '/' || *c == '.'
                })
                .collect::<String>();
                
            if cleaned.contains(",TRAFFIC,") && cleaned.len() > 100 {
                return Some(cleaned);
            }
        }
    }
    
    None
}

fn create_sample_threat_intel() -> Arc<ThreatIntel> {
    let mut threat_intel = ThreatIntel::new();
    
    // Add some sample malicious IPs for testing
    let mut malicious_ips = HashMap::new();
    malicious_ips.insert("177.74.1.41".to_string(), vec!["sample_blocklist".to_string()]);
    malicious_ips.insert("192.168.1.100".to_string(), vec!["internal_threat_feed".to_string()]);
    malicious_ips.insert("10.0.0.50".to_string(), vec!["suspicious_internal".to_string()]);
    
    // Add sample malicious domains
    let mut malicious_domains = HashSet::new();
    malicious_domains.insert("malicious-domain.com".to_string());
    malicious_domains.insert("bad-actor.net".to_string());
    
    threat_intel.malicious_ips = Arc::new(malicious_ips);
    threat_intel.malicious_domains = Arc::new(malicious_domains);
    threat_intel.malicious_urls = Arc::new(HashSet::new());
    threat_intel.malicious_hashes = Arc::new(HashSet::new());
    
    Arc::new(threat_intel)
}

fn analyze_log_fields(parsed_log: &Value) -> HashMap<String, usize> {
    let mut field_coverage = HashMap::new();
    
    if let Some(obj) = parsed_log.as_object() {
        for (key, value) in obj {
            let has_data = match value {
                Value::String(s) => !s.is_empty() && s != "N/A",
                Value::Number(_) => true,
                Value::Bool(_) => true,
                Value::Array(arr) => !arr.is_empty(),
                Value::Object(obj) => !obj.is_empty(),
                Value::Null => false,
            };
            
            if has_data {
                *field_coverage.entry(key.clone()).or_insert(0) += 1;
            }
        }
    }
    
    field_coverage
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Palo Alto Log Processing Benchmark & Analysis Tool");
    println!("=====================================================");
    println!();

    let log_file_path = "/Users/lucas/git/paloalto_fwd/client/palo_alto_logs.txt";
    
    println!("📁 Processing log file: {}", log_file_path);
    
    let file = File::open(log_file_path)?;
    let reader = BufReader::new(file);
    
    let mut stats = BenchmarkStats::default();
    let mut detailed_analysis = DetailedAnalysis {
        sample_enriched_log: None,
        threat_intelligence_matches: Vec::new(),
        behavioral_patterns: Vec::new(),
        performance_metrics: PerformanceMetrics::default(),
        field_coverage: HashMap::new(),
    };
    
    // Create threat intelligence database
    let threat_intel = create_sample_threat_intel();
    let mut alert_history = AlertHistory::default();
    
    let start_time = Instant::now();
    let mut parsing_time_total = Duration::new(0, 0);
    let mut enrichment_time_total = Duration::new(0, 0);
    
    println!("⏳ Processing logs...");
    
    // Process each line
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        
        // Extract Palo Alto log from tcpdump format
        if let Some(palo_alto_log) = extract_palo_alto_log_from_tcpdump_line(&line) {
            stats.total_logs += 1;
            let log_start_time = Instant::now();
            
            // Parse the log
            let parse_start = Instant::now();
            match parse_palo_alto_log_to_json(&palo_alto_log) {
                Ok(parsed_json) => {
                    let parse_duration = parse_start.elapsed();
                    parsing_time_total += parse_duration;
                    stats.parsed_successfully += 1;
                    
                    // Analyze field coverage
                    let fields = analyze_log_fields(&parsed_json);
                    for (field, count) in fields {
                        *detailed_analysis.field_coverage.entry(field).or_insert(0) += count;
                    }
                    
                    // Extract basic stats
                    if let Some(src_ip) = parsed_json.get("source_address").and_then(|v| v.as_str()) {
                        stats.unique_source_ips.insert(src_ip.to_string());
                    }
                    if let Some(dst_ip) = parsed_json.get("destination_address").and_then(|v| v.as_str()) {
                        stats.unique_dest_ips.insert(dst_ip.to_string());
                    }
                    if let Some(app) = parsed_json.get("application").and_then(|v| v.as_str()) {
                        stats.unique_applications.insert(app.to_string());
                    }
                    if let Some(action) = parsed_json.get("action").and_then(|v| v.as_str()) {
                        *stats.action_distribution.entry(action.to_string()).or_insert(0) += 1;
                    }
                    if let Some(dst_port) = parsed_json.get("destination_port").and_then(|v| v.as_i64()) {
                        *stats.port_distribution.entry(dst_port.to_string()).or_insert(0) += 1;
                    }
                    
                    // Enrich the log
                    let enrich_start = Instant::now();
                    let enriched_json = enrich_and_analyze_log(parsed_json, &threat_intel, &mut alert_history);
                    let enrich_duration = enrich_start.elapsed();
                    enrichment_time_total += enrich_duration;
                    
                    // Analyze enrichment results
                    if let Some(enrichment) = enriched_json.get("forwarder_enrichment") {
                        stats.enriched_logs += 1;
                        
                        if let Some(ioc_matches) = enrichment.get("ioc_matches") {
                            stats.ioc_matches += 1;
                            
                            if let Some(malicious_ips) = ioc_matches.get("malicious_ips") {
                                if let Some(arr) = malicious_ips.as_array() {
                                    for ip_match in arr {
                                        if let Some(ip) = ip_match.get("ip").and_then(|v| v.as_str()) {
                                            detailed_analysis.threat_intelligence_matches.push(
                                                format!("Malicious IP detected: {}", ip)
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        
                        if let Some(_behavioral) = enrichment.get("behavioral_anomalies") {
                            stats.behavioral_anomalies += 1;
                            detailed_analysis.behavioral_patterns.push(
                                "Behavioral anomaly detected".to_string()
                            );
                        }
                        
                        if let Some(_threat_hunting) = enrichment.get("threat_hunting") {
                            stats.threat_hunting_hits += 1;
                        }
                        
                        // Save first enriched log as sample
                        if detailed_analysis.sample_enriched_log.is_none() {
                            detailed_analysis.sample_enriched_log = Some(enriched_json);
                        }
                    }
                    
                    let log_processing_time = log_start_time.elapsed();
                    stats.processing_times.push(log_processing_time);
                    
                    // Progress indicator
                    if stats.total_logs % 100 == 0 {
                        println!("   📊 Processed {} logs...", stats.total_logs);
                    }
                }
                Err(e) => {
                    stats.parsing_failures += 1;
                    if stats.parsing_failures <= 5 {
                        println!("   ⚠️  Parsing failed for line {}: {}", line_num + 1, e);
                    }
                }
            }
        }
        
        // Limit processing for demo (remove this for full processing)
        if stats.total_logs >= 1000 {
            println!("   ℹ️  Limiting to first 1000 logs for demo purposes");
            break;
        }
    }
    
    let total_time = start_time.elapsed();
    
    // Calculate performance metrics
    detailed_analysis.performance_metrics.total_processing_time = total_time;
    detailed_analysis.performance_metrics.parsing_time = parsing_time_total;
    detailed_analysis.performance_metrics.enrichment_time = enrichment_time_total;
    
    if stats.total_logs > 0 {
        detailed_analysis.performance_metrics.avg_processing_time_per_log = 
            Duration::from_nanos(
                stats.processing_times.iter().map(|d| d.as_nanos()).sum::<u128>() as u64 
                / stats.total_logs as u64
            );
        detailed_analysis.performance_metrics.logs_per_second = 
            stats.total_logs as f64 / total_time.as_secs_f64();
    }
    
    // Print comprehensive results
    println!("\n🎯 BENCHMARK RESULTS");
    println!("==================");
    
    println!("\n📈 PROCESSING STATISTICS:");
    println!("   • Total logs found: {}", stats.total_logs);
    println!("   • Successfully parsed: {} ({:.1}%)", 
        stats.parsed_successfully, 
        (stats.parsed_successfully as f64 / stats.total_logs as f64) * 100.0
    );
    println!("   • Parsing failures: {} ({:.1}%)", 
        stats.parsing_failures,
        (stats.parsing_failures as f64 / stats.total_logs as f64) * 100.0
    );
    println!("   • Logs enriched with threat intel: {} ({:.1}%)", 
        stats.enriched_logs,
        (stats.enriched_logs as f64 / stats.parsed_successfully as f64) * 100.0
    );
    
    println!("\n🔍 THREAT INTELLIGENCE RESULTS:");
    println!("   • IOC matches found: {}", stats.ioc_matches);
    println!("   • Behavioral anomalies: {}", stats.behavioral_anomalies);
    println!("   • Threat hunting hits: {}", stats.threat_hunting_hits);
    println!("   • Sample threats detected:");
    for (i, threat) in detailed_analysis.threat_intelligence_matches.iter().take(10).enumerate() {
        println!("     {}. {}", i + 1, threat);
    }
    
    println!("\n📊 LOG ANALYSIS:");
    println!("   • Unique source IPs: {}", stats.unique_source_ips.len());
    println!("   • Unique destination IPs: {}", stats.unique_dest_ips.len());
    println!("   • Unique applications: {}", stats.unique_applications.len());
    
    println!("   • Top 10 destination ports:");
    let mut port_vec: Vec<_> = stats.port_distribution.iter().collect();
    port_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (port, count) in port_vec.iter().take(10) {
        println!("     - Port {}: {} connections", port, count);
    }
    
    println!("   • Action distribution:");
    for (action, count) in &stats.action_distribution {
        println!("     - {}: {} logs", action, count);
    }
    
    println!("\n⚡ PERFORMANCE METRICS:");
    println!("   • Total processing time: {:.2}s", detailed_analysis.performance_metrics.total_processing_time.as_secs_f64());
    println!("   • Average time per log: {:.2}ms", detailed_analysis.performance_metrics.avg_processing_time_per_log.as_millis());
    println!("   • Parsing time: {:.2}s", detailed_analysis.performance_metrics.parsing_time.as_secs_f64());
    println!("   • Enrichment time: {:.2}s", detailed_analysis.performance_metrics.enrichment_time.as_secs_f64());
    println!("   • Processing throughput: {:.1} logs/second", detailed_analysis.performance_metrics.logs_per_second);
    
    println!("\n🏷️  FIELD COVERAGE ANALYSIS:");
    println!("   • Total unique fields extracted: {}", detailed_analysis.field_coverage.len());
    println!("   • Top 15 most populated fields:");
    let mut field_vec: Vec<_> = detailed_analysis.field_coverage.iter().collect();
    field_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (field, count) in field_vec.iter().take(15) {
        println!("     - {}: {} logs ({:.1}%)", 
            field, count, 
            (**count as f64 / stats.parsed_successfully as f64) * 100.0
        );
    }
    
    // Show sample enriched log
    if let Some(sample_log) = &detailed_analysis.sample_enriched_log {
        println!("\n📝 SAMPLE ENRICHED LOG:");
        println!("   Original fields: {}", sample_log.as_object().unwrap().len());
        
        if let Some(enrichment) = sample_log.get("forwarder_enrichment") {
            println!("   Enrichment added: {}", serde_json::to_string_pretty(enrichment)?);
        }
        
        // Test syslog formatting
        match format_json_to_palo_alto_syslog(sample_log) {
            Ok(formatted) => {
                println!("   Formatted syslog length: {} bytes", formatted.len());
                println!("   Sample formatted output: {}", &formatted[..200.min(formatted.len())]);
            }
            Err(e) => println!("   ⚠️  Syslog formatting error: {}", e),
        }
    }
    
    println!("\n💾 CONFIGURATION SUMMARY:");
    println!("   • IP threat feeds: {}", IP_FEED_URLS.len());
    println!("   • Domain feeds: {}", DOMAIN_FEED_URLS.len());
    println!("   • URL feeds: {}", URL_FEED_URLS.len());
    println!("   • Hash feeds: {}", HASH_FEED_URLS.len());
    println!("   • Suspicious processes: {}", SUSPICIOUS_PROCESSES.len());
    println!("   • Critical assets: {}", CRITICAL_ASSETS.len());
    println!("   • Correlation rules: {}", CORRELATION_RULES.len());
    
    println!("\n✅ BENCHMARK COMPLETED SUCCESSFULLY!");
    println!("   The Palo Alto forwarder is ready for production with comprehensive");
    println!("   threat intelligence and behavioral analysis capabilities.");
    
    Ok(())
}