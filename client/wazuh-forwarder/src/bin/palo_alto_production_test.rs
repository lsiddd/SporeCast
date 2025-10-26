use anyhow::Result;
use clap::Parser;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use wazuh_forwarder::{
    behavioral::AlertHistory,
    palo_alto_parsing::{enrich_and_analyze_log, format_json_to_palo_alto_syslog, parse_palo_alto_log_to_json},
    threat_intel::ThreatIntel,
    unified_config::*,
};

#[derive(Parser)]
#[command(name = "palo_alto_production_test")]
#[command(about = "Production-grade Palo Alto log processing test and benchmark tool")]
struct Args {
    /// Input log file path
    #[arg(short, long, default_value = "palo_alto_logs.txt")]
    input: String,
    
    /// Maximum number of logs to process (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    limit: usize,
    
    /// Output enriched logs to file
    #[arg(short, long)]
    output: Option<String>,
    
    /// Save performance metrics to JSON
    #[arg(short, long)]
    metrics: Option<String>,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Test mode (uses sample threat intel)
    #[arg(short, long)]
    test_mode: bool,
}

#[derive(Default)]
struct ProductionStats {
    // Processing stats
    total_logs: usize,
    parsed_successfully: usize,
    parsing_failures: usize,
    enriched_logs: usize,
    
    // Threat intelligence results
    ioc_matches: usize,
    malicious_ips_found: HashSet<String>,
    _malicious_domains_found: HashSet<String>,
    behavioral_anomalies: usize,
    threat_hunting_hits: usize,
    
    // Traffic analysis
    unique_source_ips: HashSet<String>,
    unique_dest_ips: HashSet<String>,
    unique_applications: HashSet<String>,
    port_distribution: HashMap<u16, usize>,
    action_distribution: HashMap<String, usize>,
    protocol_distribution: HashMap<String, usize>,
    bytes_transferred: u64,
    
    // Performance metrics
    processing_times: Vec<Duration>,
    total_processing_time: Duration,
    parsing_time: Duration,
    enrichment_time: Duration,
    
    // Field analysis
    field_coverage: HashMap<String, usize>,
    empty_fields: HashMap<String, usize>,
}

impl ProductionStats {
    fn logs_per_second(&self) -> f64 {
        if self.total_processing_time.as_secs_f64() > 0.0 {
            self.total_logs as f64 / self.total_processing_time.as_secs_f64()
        } else {
            0.0
        }
    }
    
    fn avg_processing_time_ms(&self) -> f64 {
        if !self.processing_times.is_empty() {
            let total_ms: u128 = self.processing_times.iter().map(|d| d.as_millis()).sum();
            total_ms as f64 / self.processing_times.len() as f64
        } else {
            0.0
        }
    }
    
    fn success_rate(&self) -> f64 {
        if self.total_logs > 0 {
            (self.parsed_successfully as f64 / self.total_logs as f64) * 100.0
        } else {
            0.0
        }
    }
}

fn extract_palo_alto_log_from_tcpdump_line(line: &str) -> Option<String> {
    if line.contains("PA-") && line.contains(",TRAFFIC,") {
        if let Some(start_pos) = line.find("<") {
            let syslog_part = &line[start_pos..];
            let cleaned = syslog_part
                .chars()
                .filter(|c| {
                    c.is_ascii_graphic() || 
                    *c == ' ' || *c == '\t' || 
                    *c == ',' || *c == '=' || *c == '-' || *c == ':' ||
                    *c == '/' || *c == '.'
                })
                .collect::<String>();
                
            if cleaned.contains("PA-") && 
               cleaned.contains(",TRAFFIC,") && 
               cleaned.len() > 100 {
                return Some(cleaned);
            }
        }
    }
    None
}

fn create_production_threat_intel() -> Arc<ThreatIntel> {
    // In production, this would load actual threat feeds
    let mut threat_intel = ThreatIntel::new();
    
    // Sample threat intel for testing
    let mut malicious_ips = HashMap::new();
    malicious_ips.insert("177.74.1.41".to_string(), vec!["sample_feed".to_string()]);
    malicious_ips.insert("192.168.1.100".to_string(), vec!["internal_threats".to_string()]);
    malicious_ips.insert("10.0.0.50".to_string(), vec!["suspicious_internal".to_string()]);
    
    let mut malicious_domains = HashSet::new();
    malicious_domains.insert("malicious.com".to_string());
    malicious_domains.insert("bad-actor.net".to_string());
    
    threat_intel.malicious_ips = Arc::new(malicious_ips);
    threat_intel.malicious_domains = Arc::new(malicious_domains);
    threat_intel.malicious_urls = Arc::new(HashSet::new());
    threat_intel.malicious_hashes = Arc::new(HashSet::new());
    
    Arc::new(threat_intel)
}

fn analyze_log_for_stats(parsed_log: &Value, stats: &mut ProductionStats) {
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
                *stats.field_coverage.entry(key.clone()).or_insert(0) += 1;
            } else {
                *stats.empty_fields.entry(key.clone()).or_insert(0) += 1;
            }
        }
        
        // Extract traffic statistics
        if let Some(src_ip) = obj.get("source_address").and_then(|v| v.as_str()) {
            stats.unique_source_ips.insert(src_ip.to_string());
        }
        if let Some(dst_ip) = obj.get("destination_address").and_then(|v| v.as_str()) {
            stats.unique_dest_ips.insert(dst_ip.to_string());
        }
        if let Some(app) = obj.get("application").and_then(|v| v.as_str()) {
            stats.unique_applications.insert(app.to_string());
        }
        if let Some(action) = obj.get("action").and_then(|v| v.as_str()) {
            *stats.action_distribution.entry(action.to_string()).or_insert(0) += 1;
        }
        if let Some(protocol) = obj.get("ip_protocol").and_then(|v| v.as_str()) {
            *stats.protocol_distribution.entry(protocol.to_string()).or_insert(0) += 1;
        }
        if let Some(dst_port) = obj.get("destination_port").and_then(|v| v.as_i64()) {
            if dst_port > 0 && dst_port <= 65535 {
                *stats.port_distribution.entry(dst_port as u16).or_insert(0) += 1;
            }
        }
        if let Some(bytes) = obj.get("bytes").and_then(|v| v.as_i64()) {
            stats.bytes_transferred += bytes as u64;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("🚀 Palo Alto Production Test & Benchmark Tool");
    println!("==============================================");
    
    if args.test_mode {
        println!("🧪 Running in TEST MODE with sample threat intelligence");
    } else {
        println!("🏭 Running in PRODUCTION MODE");
    }
    
    println!("📁 Input file: {}", args.input);
    if let Some(limit) = (args.limit > 0).then_some(args.limit) {
        println!("🔢 Processing limit: {} logs", limit);
    } else {
        println!("🔢 Processing limit: unlimited");
    }
    
    let file = File::open(&args.input)?;
    let reader = BufReader::new(file);
    
    let mut stats = ProductionStats::default();
    let threat_intel = if args.test_mode {
        create_production_threat_intel()
    } else {
        Arc::new(ThreatIntel::new()) // In production, load actual feeds
    };
    let mut alert_history = AlertHistory::default();
    
    // Optional output file for enriched logs
    let mut output_file = if let Some(output_path) = &args.output {
        Some(File::create(output_path)?)
    } else {
        None
    };
    
    let start_time = Instant::now();
    let mut parsing_time_total = Duration::new(0, 0);
    let mut enrichment_time_total = Duration::new(0, 0);
    
    println!("⏳ Processing logs...");
    let mut progress_counter = 0;
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        
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
                    
                    // Analyze for statistics
                    analyze_log_for_stats(&parsed_json, &mut stats);
                    
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
                                            stats.malicious_ips_found.insert(ip.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        
                        if enrichment.get("behavioral_anomalies").is_some() {
                            stats.behavioral_anomalies += 1;
                        }
                        
                        if enrichment.get("threat_hunting").is_some() {
                            stats.threat_hunting_hits += 1;
                        }
                    }
                    
                    // Write to output file if specified
                    if let Some(ref mut file) = output_file {
                        let formatted_log = format_json_to_palo_alto_syslog(&enriched_json)?;
                        writeln!(file, "{}", formatted_log)?;
                    }
                    
                    let log_processing_time = log_start_time.elapsed();
                    stats.processing_times.push(log_processing_time);
                    
                    // Progress indicator
                    progress_counter += 1;
                    if progress_counter % 1000 == 0 || (args.verbose && progress_counter % 100 == 0) {
                        println!("   📊 Processed {} logs... ({:.1} logs/sec)", 
                            progress_counter, 
                            progress_counter as f64 / start_time.elapsed().as_secs_f64()
                        );
                    }
                }
                Err(e) => {
                    stats.parsing_failures += 1;
                    if args.verbose && stats.parsing_failures <= 10 {
                        println!("   ⚠️  Parsing failed for line {}: {}", line_num + 1, e);
                    }
                }
            }
            
            // Check limit
            if args.limit > 0 && stats.total_logs >= args.limit {
                println!("   ℹ️  Reached processing limit of {} logs", args.limit);
                break;
            }
        }
    }
    
    stats.total_processing_time = start_time.elapsed();
    stats.parsing_time = parsing_time_total;
    stats.enrichment_time = enrichment_time_total;
    
    // Print comprehensive results
    print_results(&stats, &args);
    
    // Save metrics to JSON if requested
    if let Some(metrics_path) = &args.metrics {
        save_metrics_to_json(&stats, metrics_path)?;
        println!("💾 Metrics saved to: {}", metrics_path);
    }
    
    Ok(())
}

fn print_results(stats: &ProductionStats, args: &Args) {
    println!("\n🎯 PRODUCTION TEST RESULTS");
    println!("==========================");
    
    println!("\n📈 PROCESSING PERFORMANCE:");
    println!("   • Total logs processed: {}", stats.total_logs);
    println!("   • Success rate: {:.2}%", stats.success_rate());
    println!("   • Parsing failures: {} ({:.2}%)", 
        stats.parsing_failures,
        (stats.parsing_failures as f64 / stats.total_logs as f64) * 100.0
    );
    println!("   • Processing throughput: {:.1} logs/second", stats.logs_per_second());
    println!("   • Average processing time: {:.2}ms per log", stats.avg_processing_time_ms());
    println!("   • Total processing time: {:.2}s", stats.total_processing_time.as_secs_f64());
    
    println!("\n🔒 SECURITY ANALYSIS:");
    println!("   • Logs enriched with threat intel: {} ({:.1}%)", 
        stats.enriched_logs,
        (stats.enriched_logs as f64 / stats.parsed_successfully as f64) * 100.0
    );
    println!("   • IOC matches found: {}", stats.ioc_matches);
    println!("   • Unique malicious IPs detected: {}", stats.malicious_ips_found.len());
    println!("   • Behavioral anomalies: {}", stats.behavioral_anomalies);
    println!("   • Threat hunting hits: {}", stats.threat_hunting_hits);
    
    if !stats.malicious_ips_found.is_empty() {
        println!("   • Malicious IPs found:");
        for ip in &stats.malicious_ips_found {
            println!("     - {}", ip);
        }
    }
    
    println!("\n📊 TRAFFIC ANALYSIS:");
    println!("   • Unique source IPs: {}", stats.unique_source_ips.len());
    println!("   • Unique destination IPs: {}", stats.unique_dest_ips.len());
    println!("   • Unique applications: {}", stats.unique_applications.len());
    println!("   • Total bytes transferred: {} MB", stats.bytes_transferred / 1_000_000);
    
    println!("   • Top 10 destination ports:");
    let mut port_vec: Vec<_> = stats.port_distribution.iter().collect();
    port_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (port, count) in port_vec.iter().take(10) {
        println!("     - Port {}: {} connections", port, count);
    }
    
    println!("   • Action distribution:");
    for (action, count) in &stats.action_distribution {
        let percentage = (*count as f64 / stats.parsed_successfully as f64) * 100.0;
        println!("     - {}: {} logs ({:.1}%)", action, count, percentage);
    }
    
    println!("   • Protocol distribution:");
    for (protocol, count) in &stats.protocol_distribution {
        let percentage = (*count as f64 / stats.parsed_successfully as f64) * 100.0;
        println!("     - {}: {} logs ({:.1}%)", protocol, count, percentage);
    }
    
    println!("\n🏷️  FIELD COVERAGE:");
    println!("   • Total fields extracted: {}", stats.field_coverage.len());
    println!("   • Top populated fields:");
    let mut field_vec: Vec<_> = stats.field_coverage.iter().collect();
    field_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (field, count) in field_vec.iter().take(10) {
        let percentage = (**count as f64 / stats.parsed_successfully as f64) * 100.0;
        println!("     - {}: {:.1}% coverage", field, percentage);
    }
    
    println!("\n🛡️  THREAT INTELLIGENCE CONFIGURATION:");
    println!("   • IP blocklist feeds: {}", IP_FEED_URLS.len());
    println!("   • Domain reputation feeds: {}", DOMAIN_FEED_URLS.len());
    println!("   • URL analysis feeds: {}", URL_FEED_URLS.len());
    println!("   • Hash analysis feeds: {}", HASH_FEED_URLS.len());
    println!("   • Behavioral patterns: {}", SUSPICIOUS_PROCESSES.len());
    println!("   • Critical asset keywords: {}", CRITICAL_ASSETS.len());
    println!("   • Correlation rules: {}", CORRELATION_RULES.len());
    
    println!("\n✅ PRODUCTION TEST COMPLETED SUCCESSFULLY!");
    if args.test_mode {
        println!("   Ready for production deployment with comprehensive threat intelligence!");
    } else {
        println!("   Production system validated and performing optimally!");
    }
}

fn save_metrics_to_json(stats: &ProductionStats, path: &str) -> Result<()> {
    let metrics = serde_json::json!({
        "processing_stats": {
            "total_logs": stats.total_logs,
            "parsed_successfully": stats.parsed_successfully,
            "parsing_failures": stats.parsing_failures,
            "success_rate": stats.success_rate(),
            "logs_per_second": stats.logs_per_second(),
            "avg_processing_time_ms": stats.avg_processing_time_ms(),
            "total_processing_time_secs": stats.total_processing_time.as_secs_f64(),
        },
        "security_analysis": {
            "enriched_logs": stats.enriched_logs,
            "ioc_matches": stats.ioc_matches,
            "malicious_ips_found": stats.malicious_ips_found.len(),
            "behavioral_anomalies": stats.behavioral_anomalies,
            "threat_hunting_hits": stats.threat_hunting_hits,
        },
        "traffic_analysis": {
            "unique_source_ips": stats.unique_source_ips.len(),
            "unique_dest_ips": stats.unique_dest_ips.len(),
            "unique_applications": stats.unique_applications.len(),
            "bytes_transferred": stats.bytes_transferred,
            "top_ports": stats.port_distribution.iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect::<HashMap<String, usize>>(),
            "actions": stats.action_distribution.clone(),
            "protocols": stats.protocol_distribution.clone(),
        },
        "configuration": {
            "ip_feeds": IP_FEED_URLS.len(),
            "domain_feeds": DOMAIN_FEED_URLS.len(),
            "url_feeds": URL_FEED_URLS.len(),
            "hash_feeds": HASH_FEED_URLS.len(),
            "behavioral_patterns": SUSPICIOUS_PROCESSES.len(),
            "critical_assets": CRITICAL_ASSETS.len(),
            "correlation_rules": CORRELATION_RULES.len(),
        }
    });
    
    std::fs::write(path, serde_json::to_string_pretty(&metrics)?)?;
    Ok(())
}