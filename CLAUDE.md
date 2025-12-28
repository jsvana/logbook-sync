# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

logbook-sync is a multi-user Rust web application for amateur radio log (QSO) management. It syncs ADIF files to cloud services like QRZ.com, LoTW, eQSL, ClubLog, HRDLog, Ham2K LoFi, Wavelog, and POTA.

## Build & Development Commands

```bash
cargo build                                    # Debug build
cargo build --release                          # Release build
cargo test                                     # Run all tests
cargo test <test_name>                         # Run single test
cargo test --all-features                      # Run tests with all features
cargo fmt --check                              # Check formatting
cargo clippy --all-targets --all-features -- -D warnings  # Lint (CI uses -D warnings)
```

**Running locally:**
```bash
export LOGBOOK_SYNC_MASTER_KEY="$(./target/debug/logbook-sync generate-master-key)"
cargo run -- -c config.test.toml web          # Start dev server
RUST_LOG=debug cargo run -- -c config.test.toml web  # With debug logging
```

**Pre-commit hooks** (install with `pip install pre-commit && pre-commit install`):
- `cargo fmt` on commit
- `cargo clippy` on commit
- `cargo test` on push only

## Architecture

### Core Data Flow

1. **Upload**: ADIF file → `adif/parser.rs` → `db/mod.rs` (store QSOs) → sync workers upload to cloud services
2. **Download**: Sync workers fetch from cloud services → merge into database → track confirmations

### Key Modules

- **`web/mod.rs`** (~3800 LOC): Axum web server, REST API, SSE for live updates, session auth
- **`db/mod.rs`** (~2200 LOC): SQLite operations, QSO storage, duplicate detection
- **`db/users.rs`**: User management, Argon2 password hashing
- **`db/integrations.rs`**: Per-user encrypted integration configs
- **`sync_worker.rs`** / **`sync/mod.rs`**: Background sync threads, interval-based polling
- **`crypto/mod.rs`**: XChaCha20-Poly1305 encryption, master key + per-user key derivation

### Cloud Integrations

Each integration follows the same pattern:
- Client module with API calls (`qrz/`, `lofi/`, `lotw.rs`, `eqsl.rs`, etc.)
- Config stored encrypted in `integrations` table
- Sync worker handles upload/download based on configured intervals

### Database

- SQLite via `rusqlite` with bundled SQLite
- User-scoped QSO access (all queries filter by `user_id`)
- `Database::in_memory()` available for tests

## Testing

Tests use inline `#[cfg(test)]` modules in each file. The `Database::in_memory()` method creates an isolated test database:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        let db = Database::in_memory().unwrap();
        // ...
    }
}
```

## Configuration

- TOML config file (server settings only)
- Per-user integration settings stored encrypted in database
- `LOGBOOK_SYNC_MASTER_KEY` env var required for credential encryption
- Config can be overridden via `LOGBOOK_SYNC__SECTION__KEY` env vars

## Rust Edition

Uses Rust 2024 edition (nightly). The project uses async/await throughout with Tokio runtime.
