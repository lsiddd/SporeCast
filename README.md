# SporeCast

High-performance security log aggregation and enrichment pipeline for Palo Alto Networks firewalls. Receives raw syslog over UDP, enriches each event with threat intelligence and behavioral anomaly scoring, then forwards batched JSON to an ELK Stack and optionally to Wazuh.

## Architecture

```
Palo Alto Firewall
       │ UDP 5514 (syslog CSV)
       ▼
┌─────────────────────────────────────────────────┐
│           palo_alto_forwarder (Rust)            │
│                                                 │
│  UDP Receiver → bounded queue (250k)            │
│       │                                         │
│  16 Enrichment Workers (parallel)               │
│    ├─ Parse CSV → JSON (115+ PAN-OS fields)     │
│    ├─ Threat Intel matching (26 feeds, O(1))    │
│    └─ Behavioral anomaly scoring (LRU caches)   │
│       │                          │              │
│  ELK Sender                 Wazuh Sender        │
│  (TCP 5142, batches 5000)   (TCP 1514, syslog)  │
└─────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
  Logstash → Elasticsearch      Wazuh SIEM
  prodepa-logs-YYYY.MM.dd
  wazuh-alerts-YYYY.MM.dd
         │
  Kibana (HTTPS :5601)
```

Both outputs are independent; disable either via config.

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| Client host | Linux, Rust 1.70+ (`rustup`), root for deploy |
| Server host | Docker 20.10+, Docker Compose 2.0+, 2 GB RAM |
| Upstream | Palo Alto firewall configured to send syslog UDP to client IP:5514 |

## Quick Start

### 1 — Server (ELK Stack)

```bash
cd server

# Create credentials file
echo "ELASTIC_PASSWORD=ChangeMe123!" > .env

# Replace the three placeholder encryption keys in docker-compose.yml
# (lines containing "replace_with_secure_32_chars") with random 32-char strings:
openssl rand -hex 16   # run 3 times, replace each placeholder

docker compose up -d
# Wait ~2 min for certificate generation and ES initialization

# Verify
docker compose ps
curl -k -u elastic:ChangeMe123! https://localhost:9200/_cluster/health
```

Kibana available at `https://localhost:5601` (user: `elastic`).

### 2 — Client (Forwarder)

```bash
cd client

# Edit forwarder-config.toml — at minimum set elk_host and wazuh_host
# to point at your ELK server IP

sudo ./deploy-palo-alto.sh
# Compiles release binary, installs systemd service, copies config

sudo systemctl status palo-alto-forwarder
journalctl -u palo-alto-forwarder -f
```

### Firewall Configuration

On the Palo Alto device, configure a syslog server profile pointing to the client host on UDP 5514 and assign it to your security log forwarding profile.

## Configuration Reference

Config file is installed to `/etc/forwarder/forwarder-config.toml`. Edit it there and restart the service.

```toml
[forwarder]
type = "palo_alto"           # Only supported type

[network]
syslog_port = 514            # UDP port to listen on (firewall default: 5514)
wazuh_host = "127.0.0.1"
wazuh_port = 1514
elk_host = "127.0.0.1"
elk_port = 5142              # Logstash JSON-lines port
socket_timeout_secs = 10

[logging]
log_file = "/var/log/forwarder.log"
state_file = "/var/lib/forwarder/state.json"

[performance]
max_receiver_queue_size = 50000       # UDP receive buffer depth
max_enrichment_queue_size = 40000
max_wazuh_queue_size = 40000
enrichment_worker_count = 8           # CPU-bound; tune to core count
elk_batch_size = 1000                 # Events per TCP write to Logstash
elk_batch_flush_interval_secs = 1     # Max latency before flush

[threat_intelligence]
enable_threat_intel_feeds = true
threat_intel_refresh_interval_secs = 86400   # 24 hours
threat_intel_cache_dir = "/var/lib/forwarder/threat_intel_cache"

[behavioral_analysis]
enable_behavioral_analysis = true
behavior_window_minutes = 5        # Sliding window for frequency analysis
high_severity_threshold = 10       # Events in window before flagging anomaly
```

**Internal defaults** (in `unified_config.rs`, override requires recompile):

| Constant | Default | Purpose |
|----------|---------|---------|
| `MAX_RECEIVER_QUEUE_SIZE` | 250,000 | Hard cap on UDP backlog |
| `ELK_BATCH_SIZE` | 5,000 | Batch size to Logstash |
| `CONNECTION_POOL_SIZE` | 4 | TCP connections to Logstash |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | 5 | Failures before opening breaker |
| `CIRCUIT_BREAKER_TIMEOUT_SECS` | 30 | Cooldown before retry |
| `HIGH_WORKLOAD_THRESHOLD` | 0.8 | Queue fill ratio that disables behavioral analysis |

`RUST_LOG=debug` enables verbose per-event logging.

## Threat Intelligence

On startup and every 24 hours, the forwarder downloads and caches 26 public blocklists:

- **15 IP feeds** — blocklist.de, FireHOL L1/L2, DShield, Spamhaus DROP/EDROP, Feodo, Tor exit nodes, and others
- **5 domain feeds** — MalwareDomainList, Hagezi Pro, CERT.pl, Spam404, Dandelion Sprout
- **3 URL feeds** — URLhaus, OpenPhish, Phishing Army
- **3 hash feeds** — MalwareBazaar SHA256/MD5, Maltrail

Feeds are stored in `threat_intel_cache_dir`. If a feed is unreachable at refresh time the previous cache is retained. Matched indicators are appended to the enriched log as a `threat_intel` object.

**Outbound network access** from the forwarder host to these HTTPS sources is required. If the host is air-gapped, pre-populate the cache directory manually and set `enable_threat_intel_feeds = false`.

## Behavioral Analysis

Per source IP, user, and rule ID, the engine maintains LRU caches (250k IPs, 100k users, 10k rules) tracking event counts within a configurable sliding window. When a source exceeds `high_severity_threshold` events in `behavior_window_minutes`, the event is tagged with an anomaly flag. Under high queue pressure (>80% fill), behavioral analysis is automatically suspended to protect throughput.

The engine also applies 15 correlation rules (regex-based) covering brute force, port scan, lateral movement, C2 beaconing, privilege escalation, crypto mining, and others. Matched rules are annotated on the log.

## ELK Index Layout

| Index pattern | Source |
|--------------|--------|
| `prodepa-logs-YYYY.MM.dd` | Palo Alto enriched JSON via Logstash TCP 5142 |
| `wazuh-alerts-YYYY.MM.dd` | Wazuh via Logstash TCP 5140 |

Create index patterns in Kibana at **Stack Management → Index Patterns** using the wildcards above.

## Development

```bash
cd client/wazuh-forwarder

# Build
cargo build --release

# Run locally (no systemd)
./target/release/palo_alto_forwarder --config ../forwarder-config.toml

# Tests
cargo test

# Lints
cargo clippy -- -D warnings

# Audit dependencies
cargo install cargo-audit
cargo audit
```

The binary writes logs to stdout in development mode; the file sink only activates when `log_file` is writable.

## Service Management

```bash
systemctl status palo-alto-forwarder
systemctl restart palo-alto-forwarder
journalctl -u palo-alto-forwarder -f          # Live logs
journalctl -u palo-alto-forwarder --since "1h ago"

# Config lives at:
/etc/forwarder/forwarder-config.toml
# Binary at:
/usr/local/bin/palo_alto_forwarder
```

To uninstall:

```bash
sudo ./client/removal-palo-alto.sh
```

## Troubleshooting

**Logs not arriving in Kibana**

1. Confirm firewall is sending: `sudo tcpdump -i any udp port 5514`
2. Check forwarder is running and parsing: `journalctl -u palo-alto-forwarder -f`
3. Confirm Logstash is receiving: `docker compose logs -f logstash`
4. Check Elasticsearch health: `curl -k -u elastic:pass https://localhost:9200/_cluster/health`

**Queue full / events dropping**

Increase `max_receiver_queue_size` and `enrichment_worker_count` in config, or reduce `elk_batch_flush_interval_secs`. Monitor queue fill with `RUST_LOG=debug`.

**Threat feed download failures**

The feed cache TTL is 24 hours. Stale caches continue working. Check outbound HTTPS connectivity from the forwarder host. Cache files are plaintext in `threat_intel_cache_dir`.

**ELK stack won't start**

```bash
docker compose down -v          # Wipe data and certs, then re-up
docker compose up -d
```

## Known Issues

The following dependency advisories are outstanding (per Phase 1 audit):

| Crate | Advisory | Fix |
|-------|----------|-----|
| `bytes 1.10.1` | RUSTSEC-2026-0007 | Upgrade to ≥1.11.1 |
| `slab 0.4.10` | RUSTSEC-2025-0047 (yanked) | Upgrade to ≥0.4.11 |
| `lru 0.16.0` | RUSTSEC-2026-0002 | Upgrade to ≥0.16.4 or 0.18.0 |
| `rustls-pemfile 1.0.4` | unmaintained | Pulled in by `reqwest` |

Run `cargo audit` to check current status before deploying a new build.

## Security Notes

- The systemd unit runs as root but applies `ProtectSystem=strict`, `PrivateTmp=yes`, and `NoNewPrivileges=yes`. Write access is limited to `/var/log`, `/var/lib/palo-alto-forwarder`, and `/tmp`.
- ELK inter-service communication uses TLS with auto-generated self-signed certificates. Certificates are regenerated on `docker compose down -v`.
- `ELASTIC_PASSWORD` must be set in `server/.env` before first run. Do not commit this file.
- The three Kibana encryption keys in `docker-compose.yml` must be replaced with random 32-character strings before production use.
