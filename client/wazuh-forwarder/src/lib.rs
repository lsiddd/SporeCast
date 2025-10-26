// Library module definitions for shared code between forwarders

pub mod behavioral;
pub mod config;
pub mod parsing;
pub mod telegram;
pub mod threat_intel;
pub mod workers;

// Unified configuration for all forwarder binaries
pub mod unified_config;

// Palo Alto specific modules
pub mod palo_alto_config;
pub mod palo_alto_parsing;
pub mod palo_alto_workers;

// Configuration reader for TOML config files
pub mod config_reader;