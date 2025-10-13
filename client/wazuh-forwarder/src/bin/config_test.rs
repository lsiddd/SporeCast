use std::env;
use wazuh_forwarder::config_reader::ForwarderConfig;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Usage: {} <config-file-path>", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    
    println!("Testing configuration file: {}", config_path);
    
    match ForwarderConfig::load_from_file(config_path) {
        Ok(config) => {
            println!("✓ Configuration file loaded successfully");
            
            match config.validate() {
                Ok(()) => {
                    println!("✓ Configuration validation passed");
                    println!("  Forwarder type: {}", config.forwarder.forwarder_type);
                    println!("  Syslog port: {}", config.network.syslog_port);
                    println!("  ELK host: {}:{}", config.network.elk_host, config.network.elk_port);
                    println!("  Wazuh host: {}:{}", config.network.wazuh_host, config.network.wazuh_port);
                    println!("  Log file: {}", config.logging.log_file);
                    println!("  State file: {}", config.logging.state_file);
                    println!("  Behavioral analysis: {}", config.behavioral_analysis.enable_behavioral_analysis);
                    println!("  Threat intel: {}", config.threat_intelligence.enable_threat_intel_feeds);
                    println!("  Telegram enabled: {}", config.telegram.enable_telegram);
                    
                    if config.is_fortigate() {
                        println!("  → Running in Fortigate mode");
                    } else if config.is_palo_alto() {
                        println!("  → Running in Palo Alto mode");
                    }
                }
                Err(e) => {
                    eprintln!("✗ Configuration validation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to load configuration file: {}", e);
            std::process::exit(1);
        }
    }
    
    println!("Configuration test completed successfully!");
}