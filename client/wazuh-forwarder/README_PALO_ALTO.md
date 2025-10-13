# Palo Alto Log Forwarder

An alternative implementation of the Wazuh forwarder specifically designed to handle Palo Alto PAN-OS CSV logs instead of Fortigate logs.

## Features

- **CSV Log Parsing**: Parses Palo Alto PAN-OS Traffic logs in CSV format
- **Field Mapping**: Maps 115+ Palo Alto log fields to structured JSON
- **Threat Intelligence**: Integrates with threat intelligence feeds for IOC matching  
- **Behavioral Analysis**: Detects anomalous patterns in traffic logs
- **Dual Output**: Forwards both raw logs and enriched logs to Wazuh
- **ELK Integration**: Sends structured JSON logs to Elasticsearch
- **Async Processing**: High-performance multi-threaded architecture

## Architecture

The Palo Alto forwarder follows the same multi-threaded architecture as the Fortigate version:

1. **Syslog Receiver**: Listens for Palo Alto logs on UDP port 5514
2. **Enrichment Workers**: Parse, analyze, and enrich logs with threat intelligence
3. **ELK Sender**: Forwards enriched JSON logs to Elasticsearch  
4. **Wazuh Senders**: Forward both raw and enriched logs to Wazuh

## Configuration

Key configuration constants are defined in `src/palo_alto_config.rs`:

```rust
pub const PALO_ALTO_SYSLOG_PORT: u16 = 5514;
pub const WAZUH_LOCAL_SYSLOG_HOST: &str = "127.0.0.1"; 
pub const WAZUH_LOCAL_SYSLOG_PORT: u16 = 1514;
pub const ELK_HOST: &str = "127.0.0.1";
pub const ELK_PORT: u16 = 9200;
pub const ELK_INDEX_NAME: &str = "palo-alto-logs";
```

## Building

Build the Palo Alto forwarder:

```bash
cargo build --release --bin palo_alto_forwarder
```

## Running

Run the Palo Alto forwarder:

```bash
./target/release/palo_alto_forwarder
```

## Testing

Test the parser with sample logs:

```bash
cargo run --bin test_palo_alto_parser
```

Debug CSV parsing:

```bash
cargo run --bin debug_palo_alto_parser
```

## Log Format

The forwarder expects Palo Alto logs in the standard PAN-OS Traffic log CSV format:

```
PA-5220-1 1,2025/08/07 09:08:47,013201006880,TRAFFIC,end,2562,2025/08/07 09:08:47,10.95.1.5,172.217.150.136,...
```

Key fields parsed:
- Source/Destination IP addresses and ports
- Application and application category  
- Action (allow/deny/drop)
- Traffic statistics (bytes, packets)
- Rule information
- Device and zone information

## Sample Output

The forwarder produces enriched JSON logs like:

```json
{
  "source_address": "10.95.1.5",
  "destination_address": "172.217.150.136", 
  "source_port": 63747,
  "destination_port": 443,
  "action": "allow",
  "application": "ssl",
  "bytes": 3548,
  "rule_name": "ACESSO_INTERNET_SECRETARIAS",
  "forwarder_enrichment": {
    "ioc_matches": {...},
    "threat_hunting": {...},
    "behavioral_anomalies": {...}
  }
}
```

## Differences from Fortigate Version

- **Port**: Listens on port 5514 instead of 5515
- **Parsing**: Uses CSV parser instead of key-value parser
- **Fields**: Maps Palo Alto specific fields (115+ fields vs Fortigate's subset)
- **Index**: Uses "palo-alto-logs" ELK index instead of "fortigate-logs"
- **State**: Uses separate state file `/tmp/palo_alto_forwarder_state.json`

## Files

- `src/palo_alto_main.rs` - Main entry point
- `src/palo_alto_parsing.rs` - CSV parsing and JSON formatting
- `src/palo_alto_workers.rs` - Worker threads (receiver, enrichment, senders)  
- `src/palo_alto_config.rs` - Configuration constants
- `test_logs/palo_alto_parser.py` - Reference Python implementation
- `test_logs/100_palo_alto_logs.txt` - Sample log data