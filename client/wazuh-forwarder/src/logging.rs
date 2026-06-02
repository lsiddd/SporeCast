use anyhow::Result;
use chrono::Local;
use log::{info, LevelFilter};
use std::{fs::OpenOptions, io, thread};

use crate::{config_reader::ForwarderConfig, palo_alto_config::NO_LOG_FILE};

/// Configures process-wide logging for the forwarder binary.
pub fn configure_logging(config: &ForwarderConfig) -> Result<()> {
    let mut fern_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("main"),
                message
            ))
        })
        .level(LevelFilter::Info)
        .chain(io::stdout());

    if NO_LOG_FILE {
        fern_dispatch.apply()?;
        info!("Logging configured for stdout only (log file writes disabled).");
    } else {
        let log_file_path = config.logging.log_file.as_str();
        let log_file_result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_path);
        match log_file_result {
            Ok(file) => {
                fern_dispatch = fern_dispatch.chain(file);
                fern_dispatch.apply()?;
                info!(
                    "Logging configured. Detailed logs will be written to {}.",
                    log_file_path
                );
            }
            Err(e) => {
                eprintln!(
                    "Failed to open log file {}: {}. Logging will only go to stdout.",
                    log_file_path, e
                );
                fern_dispatch.apply()?;
            }
        }
    }

    Ok(())
}
