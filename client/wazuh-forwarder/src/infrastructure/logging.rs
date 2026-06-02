use anyhow::Result;
use chrono::Local;
use log::{info, LevelFilter};
use std::{fs::OpenOptions, io, thread};

use crate::infrastructure::config::ForwarderConfig;

const NO_LOG_FILE: bool = true;

/// Configures process-wide logging for the forwarder binary.
///
/// When `use_stderr` is true, logs go to stderr (use this when stdout carries JSON data).
pub fn configure_logging_with_opts(config: &ForwarderConfig, use_stderr: bool) -> Result<()> {
    let base = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                thread::current().name().unwrap_or("main"),
                message
            ))
        })
        .level(LevelFilter::Info);

    let mut fern_dispatch = if use_stderr {
        base.chain(io::stderr())
    } else {
        base.chain(io::stdout())
    };

    if NO_LOG_FILE || use_stderr {
        fern_dispatch.apply()?;
        if !use_stderr {
            info!("Logging configured for stdout only (log file writes disabled).");
        }
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

/// Configures process-wide logging for the forwarder binary.
pub fn configure_logging(config: &ForwarderConfig) -> Result<()> {
    configure_logging_with_opts(config, false)
}
