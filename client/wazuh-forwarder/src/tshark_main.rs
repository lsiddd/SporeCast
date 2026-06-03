use anyhow::{Context, Result};
use clap::Parser;

use wazuh_forwarder::{
    infrastructure::config::ForwarderConfig, infrastructure::logging::configure_logging_with_opts,
    interface::tshark::run,
};

#[derive(Parser)]
#[command(
    name = "tshark_forwarder",
    about = "Forward tshark EK JSON (stdin) to ELK with GeoIP and threat-intel enrichment.\n\
             Production: sudo tshark -i any -n -l -f \"ip or ip6\" -T ek | tshark_forwarder\n\
             Dev/test:   cat capture.json | tshark_forwarder --stdout"
)]
struct Cli {
    #[arg(short, long, default_value = "forwarder-config.toml")]
    config: String,

    /// Print enriched JSON to stdout instead of sending to ELK (dev/test mode).
    /// Disables threat-intel downloads and ELK connection.
    #[arg(long)]
    stdout: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut config =
        ForwarderConfig::load_from_file(&cli.config).unwrap_or_else(|_| ForwarderConfig::default());

    config.resolve_user_paths();
    config.validate().context("Config validation failed")?;
    configure_logging_with_opts(&config, cli.stdout)?;

    run(config, cli.stdout).await
}
