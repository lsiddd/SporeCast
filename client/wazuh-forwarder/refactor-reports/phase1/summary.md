# Phase 1 Baseline

Date: 2026-06-02

## Project Layout

- Repository root has no `Cargo.toml`; Rust crate root is `client/wazuh-forwarder`.
- Single package: `wazuh_forwarder` v0.1.0, edition 2021.
- Targets:
  - Library: `src/lib.rs`
  - Binary: `palo_alto_forwarder` at `src/palo_alto_main.rs`
- Rust modules:
  - `behavioral.rs` (246 lines)
  - `config_reader.rs` (158 lines)
  - `lib.rs` (17 lines)
  - `palo_alto_config.rs` (16 lines)
  - `palo_alto_main.rs` (255 lines)
  - `palo_alto_parsing.rs` (491 lines)
  - `palo_alto_workers.rs` (491 lines)
  - `performance.rs` (314 lines)
  - `threat_intel.rs` (337 lines)
  - `unified_config.rs` (232 lines)

Files over the requested architecture threshold:

- `palo_alto_parsing.rs`
- `palo_alto_workers.rs`
- `performance.rs`
- `threat_intel.rs`

## Direct Dependencies

- `anyhow`
- `chrono` with `serde`
- `clap` with `derive`
- `crossbeam-channel`
- `csv`
- `env_logger`
- `fern` with `colored`
- `lazy_static`
- `log`
- `regex`
- `reqwest` with `json`
- `serde` with `derive`
- `serde_json`
- `signal-hook`
- `sha2`
- `tokio` with `full`
- `futures`
- `toml`
- `parking_lot`
- `dashmap`
- `once_cell`
- `lru`

Potentially unnecessary direct dependencies based on source usage:

- `env_logger`: not referenced by source code; logging is configured through `fern`.
- `futures`: not referenced by source code; async fan-out uses `tokio::task::JoinSet`.

Notable outdated or vulnerable dependencies from `cargo update --dry-run` and `cargo audit`:

- `bytes` 1.10.1 has RUSTSEC-2026-0007; compatible fix is >= 1.11.1.
- `slab` 0.4.10 has RUSTSEC-2025-0047 and is yanked; compatible fix is >= 0.4.11.
- `lru` 0.16.0 has RUSTSEC-2026-0002; compatible update available in 0.16.4 and newer line 0.18.0.
- `rustls-pemfile` 1.0.4 is unmaintained through `reqwest` 0.11.27.
- Many compatible transitive updates are available; see `cargo-update-dry-run.txt`.

## Command Baseline

Outputs are saved in this directory:

- `cargo-check.txt`
- `cargo-clippy-D-warnings.txt`
- `cargo-test.txt`
- `cargo-audit.txt`
- `cargo-tree-normal.txt`
- `cargo-metadata-no-deps.json`
- `cargo-update-dry-run.txt`

Results:

- `cargo check`: passed, 0 compiler warnings.
- `cargo clippy -- -D warnings`: failed with 6 Clippy errors.
- `cargo test`: passed, but there are 0 tests.
- `cargo audit`: failed with 2 vulnerabilities and 3 warnings.

Clippy errors:

- `threat_intel.rs`: needless borrow in `starts_with`.
- `performance.rs`: `single_match` in circuit breaker success handling.
- `performance.rs`: `QueueMonitor::new` without `Default`.
- `palo_alto_workers.rs`: three manual `% n == 0` checks where `is_multiple_of` is available.

Initial correctness risks identified:

- `unwrap()` on `Mutex::lock`, `JoinHandle::await`, and thread `join()` can convert recoverable task/thread failures into process panics.
- `logid as u32` can silently truncate large log IDs and corrupt behavioral counters.
- Several long-running counters use unchecked `+= 1`; in release builds integer overflow wraps.
- Queue and batch sizes loaded from config are not validated against zero.
- `cargo audit` advisories include integer overflow and out-of-bounds issues in transitive crates.
