use anyhow::{Context, Result};
use clap::Parser;
use log::info;

use wazuh_forwarder::{
    infrastructure::config::ForwarderConfig,
    infrastructure::logging::{configure_logging, configure_logging_with_opts},
    interface::palo_alto::{run, run_stdin},
};

#[derive(Parser)]
#[command(
    name = "palo_alto_forwarder",
    about = "Forward Palo Alto PAN-OS syslog to ELK/Wazuh with enrichment.\n\
             Production: listens on UDP syslog port.\n\
             Dev/test:   cat firewall.log | palo_alto_forwarder --stdin"
)]
struct Cli {
    #[arg(short, long, default_value = "forwarder-config.toml")]
    config: String,

    /// Read Palo Alto syslog lines from stdin instead of UDP (dev/test mode).
    /// Prints enriched JSON to stdout. Disables ELK and Wazuh forwarding.
    #[arg(long)]
    stdin: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut config = ForwarderConfig::load_from_file(&cli.config).unwrap_or_else(|e| {
        eprintln!(
            "Failed to load config from '{}': {}. Using hardcoded defaults.",
            cli.config, e
        );
        ForwarderConfig::default()
    });

    if cli.stdin {
        config.resolve_user_paths();
        configure_logging_with_opts(&config, true)?;
        return run_stdin(config).await;
    }

    config.validate().context("Config validation failed")?;
    configure_logging(&config)?;
    info!("Config loaded from: {}", cli.config);

    run(config).await
}
