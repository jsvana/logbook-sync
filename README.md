# logbook-sync

[![CI](https://github.com/jsvana/logbook-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/jsvana/logbook-sync/actions/workflows/ci.yml)
[![Release](https://github.com/jsvana/logbook-sync/actions/workflows/release.yml/badge.svg)](https://github.com/jsvana/logbook-sync/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/jsvana/logbook-sync?include_prereleases)](https://github.com/jsvana/logbook-sync/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Multi-user web application for amateur radio log management. Upload ADIF files and sync QSOs to cloud services like QRZ.com, LoTW, eQSL, ClubLog, and Ham2K LoFi.

## Features

- **Multi-User Support**: Each user has their own QSO database and integration settings
- **Web Interface**: Upload ADIF files, view QSOs, and manage integrations via browser
- **Per-User Integrations**: Configure QRZ, LoTW, eQSL, ClubLog, HRDLog, and Ham2K LoFi per user
- **Encrypted Storage**: User integration credentials are encrypted at rest
- **Light/Dark Theme**: User-selectable theme preference
- **Duplicate Detection**: Tracks synced QSOs to avoid duplicates
- **Confirmation Tracking**: Downloads and tracks LotW/QSL confirmations

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/jsvana/logbook-sync.git
cd logbook-sync

# Build release binary
cargo build --release
cp target/release/logbook-sync ~/.local/bin/
```

## Quick Start

### 1. Generate a Master Key

The master key is used to encrypt user integration credentials:

```bash
logbook-sync generate-master-key
# Output: <base64-encoded-key>

# Save it securely and set as environment variable
export LOGBOOK_SYNC_MASTER_KEY="<your-key>"
```

### 2. Create Configuration

Create a configuration file at `/etc/logbook-sync/config.toml` (or `~/.config/logbook-sync/config.toml`):

```toml
[database]
path = "/var/lib/logbook-sync/logbook.db"

[server]
port = 3000
bind_address = "127.0.0.1"

[general]
log_level = "info"

# Optional: retry/resilience settings
[resilience]
max_retries = 5
initial_backoff_ms = 1000
max_backoff_ms = 60000
```

### 3. Create Initial User

```bash
logbook-sync -c /path/to/config.toml user-add --username admin --admin
# You'll be prompted for a password (minimum 12 characters)
```

### 4. Start the Web Server

```bash
export LOGBOOK_SYNC_MASTER_KEY="<your-key>"
logbook-sync -c /path/to/config.toml web
# Server starts on http://127.0.0.1:3000
```

## Configuration

The configuration file only contains server-level settings. All integration settings (QRZ, LoFi, etc.) are configured per-user through the web interface.

### Required Settings

```toml
[database]
path = "/path/to/logbook.db"  # SQLite database location
```

### Optional Settings

```toml
[server]
port = 3000                    # Web server port (default: 3000)
bind_address = "127.0.0.1"     # Bind address (default: 127.0.0.1)

[general]
log_level = "info"             # Log level: trace, debug, info, warn, error

[resilience]
max_retries = 5                # Max retry attempts for transient failures
initial_backoff_ms = 1000      # Initial backoff delay
max_backoff_ms = 60000         # Maximum backoff delay
backoff_multiplier = 2.0       # Exponential backoff multiplier
jitter = true                  # Add jitter to backoff delays
```

### Environment Variables

- `LOGBOOK_SYNC_MASTER_KEY` - **Required**: Master encryption key for user credentials

Configuration values can also be set via environment variables with the `LOGBOOK_SYNC__` prefix:
- `LOGBOOK_SYNC__DATABASE__PATH`
- `LOGBOOK_SYNC__SERVER__PORT`

## CLI Commands

```bash
# Run the web server
logbook-sync web [--bind <address:port>]

# Validate configuration
logbook-sync config

# User management
logbook-sync user-add --username <name> [--email <email>] [--callsign <call>] [--admin]
logbook-sync user-list [--format table|json|csv]
logbook-sync user-remove <username> [--force]
logbook-sync user-reset-pw <username>
logbook-sync user-set-active <username> --active <true|false>

# Database maintenance
logbook-sync db vacuum      # Compact database
logbook-sync db info        # Show database statistics
logbook-sync db optimize    # Vacuum and analyze
logbook-sync db export -o <file.adi>  # Export all QSOs to ADIF

# Generate master encryption key
logbook-sync generate-master-key [--format hex|base64]
```

### Global Options

```
-c, --config <PATH>   Configuration file path [default: /etc/logbook-sync/config.toml]
-v, --verbose         Increase verbosity (-v, -vv, -vvv)
-q, --quiet           Suppress non-error output
--json-logs           Output logs in JSON format
```

## Web Interface

After starting the server, access the web interface at `http://localhost:3000`.

### Features

- **Dashboard**: View recent QSOs and sync status
- **Upload**: Upload ADIF files to import QSOs
- **QSO Browser**: View and search your QSO history
- **Integrations**: Configure cloud service connections:
  - QRZ.com
  - Ham2K LoFi (for PoLo app sync)
  - LoTW (Logbook of The World)
  - eQSL
  - ClubLog
  - HRDLog
- **Settings**: Update profile, change password, select theme

### Ham2K LoFi Setup

To sync QSOs from the [Ham2K PoLo](https://polo.ham2k.com/) mobile app:

1. Go to **Integrations** in the web interface
2. Click **Set Up LoFi**
3. Enter your email address
4. Check your email and click the confirmation link
5. Return to the app and confirm the link

QSOs logged in PoLo will sync to your logbook automatically.

## Running as a Service

### systemd (Linux)

Create `/etc/systemd/system/logbook-sync.service`:

```ini
[Unit]
Description=Logbook Sync Web Server
After=network.target

[Service]
Type=simple
User=logbook-sync
Environment=LOGBOOK_SYNC_MASTER_KEY=<your-key>
ExecStart=/usr/local/bin/logbook-sync -c /etc/logbook-sync/config.toml web
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now logbook-sync
sudo systemctl status logbook-sync
journalctl -u logbook-sync -f
```

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- -c config.toml web
```

### Pre-commit Hooks

The repository includes a pre-commit hook that runs `cargo fmt --check`, `cargo clippy`, and `cargo test`:

```bash
# The hook is at .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### CI/CD

GitHub Actions automatically runs on every push and pull request:
- Format checking (`cargo fmt`)
- Linting (`cargo clippy`)
- Tests (`cargo test`)
- Release builds for Linux and macOS

## Project Structure

```
src/
├── main.rs          # CLI and command handlers
├── lib.rs           # Library exports
├── config.rs        # Server configuration
├── crypto.rs        # Encryption for user credentials
├── error.rs         # Error types
├── adif/
│   ├── parser.rs    # ADIF file parsing
│   └── writer.rs    # ADIF file generation
├── db/
│   ├── mod.rs       # SQLite database operations
│   ├── users.rs     # User management
│   └── integrations.rs  # Per-user integration configs
├── web/
│   └── mod.rs       # Axum web server and API handlers
├── qrz/             # QRZ.com API client
├── lofi/            # Ham2K LoFi API client
├── lotw.rs          # LoTW client
├── eqsl.rs          # eQSL client
├── clublog.rs       # ClubLog client
├── hrdlog.rs        # HRDLog client
├── ntfy.rs          # ntfy.sh notifications
└── wavelog.rs       # Wavelog client
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please open an issue or pull request.

## See Also

- [QRZ Logbook API](https://www.qrz.com/docs/logbook/QRZLogbookAPI.html)
- [ADIF Specification](https://adif.org/)
- [POTA - Parks on the Air](https://pota.app)
- [Ham2K PoLo](https://polo.ham2k.com/) - Mobile logging app with LoFi cloud sync
