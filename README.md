# logbook-sync

[![CI](https://github.com/jsvana/logbook-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/jsvana/logbook-sync/actions/workflows/ci.yml)
[![Release](https://github.com/jsvana/logbook-sync/actions/workflows/release.yml/badge.svg)](https://github.com/jsvana/logbook-sync/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/jsvana/logbook-sync?include_prereleases)](https://github.com/jsvana/logbook-sync/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ADIF log synchronization daemon for amateur radio operators. Automatically syncs QSO logs from local ADIF files to cloud services like QRZ.com.

## Features

- **File Watching**: Monitors directories for new/changed ADIF files
- **QRZ Integration**: Uploads QSOs to QRZ.com logbook automatically
- **Ham2K LoFi Integration**: Syncs operations and QSOs from Ham2K PoLo mobile app
- **Duplicate Detection**: Tracks synced QSOs to avoid duplicates
- **Confirmation Tracking**: Downloads and tracks LotW/QSL confirmations
- **systemd Integration**: Runs as a background service with proper notifications
- **Flexible Configuration**: TOML-based config with environment variable overrides

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/jsvana/logbook-sync.git
cd logbook-sync

# Install for current user
./install.sh --user

# Or install system-wide (requires sudo)
sudo ./install.sh --system
```

### Manual Build

```bash
cargo build --release
cp target/release/logbook-sync ~/.local/bin/
```

## Configuration

Create a configuration file at `~/.config/logbook-sync/config.toml`:

```toml
[general]
callsign = "W6JSV"
sync_interval = 300  # seconds

[local]
watch_dir = "/home/user/Documents/prior"  # POTA app default
output_dir = "/home/user/logbook-sync/output"
patterns = ["*.adi", "*.adif", "*.ADI", "*.ADIF"]
debounce_secs = 2
process_existing = true

[database]
path = "/home/user/.local/share/logbook-sync/logbook.db"

[qrz]
enabled = true
api_key = "YOUR-QRZ-API-KEY"  # From https://logbook.qrz.com/logbook
user_agent = "logbook-sync/0.1.0"
upload = true
download = true
download_interval = 3600

# Optional: Ham2K LoFi integration (for PoLo app sync)
# Run 'logbook-sync lofi setup' to generate credentials
[lofi]
enabled = true
client_key = "YOUR-UUID-V4-KEY"
client_secret = "YOUR-64-CHAR-SECRET"
callsign = "W6JSV"
# bearer_token is stored in the database (set by 'lofi register')
device_linked = true  # Set after email confirmation
```

### Environment Variables

Configuration values can be overridden with environment variables:

- `LOGBOOK_SYNC_CALLSIGN` - Your callsign
- `LOGBOOK_SYNC_QRZ_API_KEY` - QRZ API key (recommended for security)

## Usage

### Commands

```bash
# Run as daemon (for systemd)
logbook-sync daemon

# One-time sync
logbook-sync sync

# Show status and statistics
logbook-sync status

# Upload specific ADIF file
logbook-sync upload /path/to/file.adi

# Download confirmations from QRZ
logbook-sync download

# Validate configuration
logbook-sync config
logbook-sync config --validate

# Watch directory (debug mode)
logbook-sync watch

# LoFi commands (Ham2K PoLo integration)
logbook-sync lofi setup     # Generate client credentials
logbook-sync lofi link -e your@email.com  # Link device (sends confirmation email)
logbook-sync lofi status    # Check LoFi configuration and sync status
logbook-sync lofi sync      # One-time sync from LoFi
```

### Options

```
-c, --config <PATH>   Configuration file path [default: /etc/logbook-sync/config.toml]
-v, --verbose         Increase verbosity (-v, -vv, -vvv)
-q, --quiet           Suppress non-error output
```

### systemd Service

```bash
# Enable and start (user service)
systemctl --user enable --now logbook-sync

# Check status
systemctl --user status logbook-sync

# View logs
journalctl --user -u logbook-sync -f

# Restart after config changes
systemctl --user restart logbook-sync
```

## How It Works

1. **File Detection**: Watches configured directory for ADIF files matching patterns
2. **Parsing**: Parses ADIF files and extracts QSO records
3. **Deduplication**: Checks local SQLite database for existing QSOs
4. **Upload**: Uploads new QSOs to QRZ.com with automatic retry on failures
5. **Tracking**: Records sync status and QRZ log IDs locally

### Duplicate Detection

QSOs are considered duplicates if they match on:
- Callsign
- Date (QSO_DATE)
- Time (TIME_ON, normalized to 6 digits)
- Band
- Mode

### Retry Logic

Failed uploads are retried with exponential backoff:
- Initial delay: 1 second
- Maximum delay: 60 seconds
- Maximum attempts: 5

Permanent errors (invalid data, wrong callsign) are not retried.

## POTA Integration

logbook-sync works great with the [POTA app](https://pota.app):

1. Set `watch_dir` to your POTA app's export directory (usually `~/Documents/prior`)
2. After each activation, the app exports an ADIF file
3. logbook-sync detects the new file and uploads to QRZ automatically

## Ham2K LoFi Integration

logbook-sync can sync your QSOs from [Ham2K PoLo](https://polo.ham2k.com/) mobile logging app via the LoFi cloud service:

### Setup Process

1. **Generate credentials**:
   ```bash
   logbook-sync lofi setup
   ```
   This generates a UUID client key and secret. Add them to your config.toml.

2. **Link your device**:
   ```bash
   logbook-sync lofi link -e your@email.com
   ```
   This sends a confirmation email. Click the link in the email to authorize the connection.
   (The bearer token is automatically obtained during this step if not already present.)

3. **Enable device linking** in config:
   ```toml
   device_linked = true
   ```

4. **Sync your data**:
   ```bash
   logbook-sync lofi sync
   ```

Note: The bearer token is stored securely in the database, not in the config file. It is automatically obtained and refreshed as needed - no manual registration required.

### Automatic Sync

When running as a daemon, logbook-sync automatically syncs from LoFi at the configured interval (default: every 20 seconds). This keeps your local database up-to-date with any QSOs logged in the PoLo app.

### What Gets Synced

- **Operations**: POTA activations, SOTA summits, and other special activities
- **QSOs**: All contact records with full metadata
- **References**: Park/summit references for P2P and S2S contacts

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
RUST_LOG=debug cargo run -- -c config.test.toml sync
```

### Pre-commit Hooks

Set up pre-commit hooks to run `cargo fmt`, `cargo clippy`, and `cargo test` automatically:

**Option 1: Using pre-commit framework (recommended)**
```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type pre-push
```

**Option 2: Using git hooks directly**
```bash
git config core.hooksPath .githooks
```

The hooks will:
- **pre-commit**: Run `cargo fmt --check` and `cargo clippy`
- **pre-push**: Run `cargo test`

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
├── config.rs        # Configuration loading
├── error.rs         # Error types
├── adif/
│   ├── parser.rs    # ADIF file parsing
│   └── writer.rs    # ADIF file generation
├── db/mod.rs        # SQLite database operations
├── qrz/mod.rs       # QRZ.com API client
├── lofi/
│   ├── mod.rs       # Ham2K LoFi module exports
│   ├── client.rs    # LoFi API client
│   ├── models.rs    # Data structures for operations/QSOs
│   └── sync.rs      # LoFi sync service
├── sync/mod.rs      # Sync service coordinator
└── watcher/mod.rs   # File system watcher
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
