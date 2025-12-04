#!/bin/bash
# Installation script for logbook-sync with multitenancy support
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Installing logbook-sync..."

# Create system user
if ! id logbook-sync &>/dev/null; then
    sudo useradd --system --home-dir /var/lib/logbook-sync --create-home --shell /usr/sbin/nologin logbook-sync
    echo "Created system user: logbook-sync"
fi

# Create directories
sudo mkdir -p /etc/logbook-sync
sudo mkdir -p /var/lib/logbook-sync

# Install binary
if [ -f "$PROJECT_ROOT/target/release/logbook-sync" ]; then
    sudo cp "$PROJECT_ROOT/target/release/logbook-sync" /usr/local/bin/
    sudo chmod 755 /usr/local/bin/logbook-sync
    echo "Installed binary: /usr/local/bin/logbook-sync"
else
    echo "ERROR: Binary not found. Run 'cargo build --release' first."
    exit 1
fi

# Create default config if it doesn't exist
if [ ! -f /etc/logbook-sync/config.toml ]; then
    sudo tee /etc/logbook-sync/config.toml > /dev/null << 'EOF'
[general]
callsign = "N0CALL"
sync_interval = 300

[database]
path = "/var/lib/logbook-sync/logbook.db"

[local]
watch_dir = "/var/lib/logbook-sync/logs"
output_dir = "/var/lib/logbook-sync/output"
patterns = ["*.adi", "*.adif", "*.ADI", "*.ADIF"]
debounce_secs = 2

[qrz]
enabled = false
api_key = ""
upload = false
download = false
EOF
    echo "Created default config: /etc/logbook-sync/config.toml"
fi

# Generate master key if not exists
if [ ! -f /etc/logbook-sync/env ]; then
    MASTER_KEY=$(/usr/local/bin/logbook-sync generate-master-key 2>/dev/null)
    echo "LOGBOOK_SYNC_MASTER_KEY=$MASTER_KEY" | sudo tee /etc/logbook-sync/env > /dev/null
    sudo chmod 600 /etc/logbook-sync/env
    echo "Generated master key: /etc/logbook-sync/env"
    echo ""
    echo "IMPORTANT: Back up /etc/logbook-sync/env - it contains the encryption key!"
fi

# Create log and output directories
sudo mkdir -p /var/lib/logbook-sync/logs
sudo mkdir -p /var/lib/logbook-sync/output

# Set permissions
sudo chown -R logbook-sync:logbook-sync /var/lib/logbook-sync
sudo chown -R root:logbook-sync /etc/logbook-sync
sudo chmod 750 /etc/logbook-sync
sudo chmod 640 /etc/logbook-sync/config.toml
sudo chmod 600 /etc/logbook-sync/env

# Install systemd unit
sudo cp "$SCRIPT_DIR/logbook-sync.service" /etc/systemd/system/
sudo systemctl daemon-reload
echo "Installed systemd unit: /etc/systemd/system/logbook-sync.service"

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/logbook-sync/config.toml to set your callsign"
echo "  2. Create first admin user:"
echo "     sudo -u logbook-sync LOGBOOK_SYNC_MASTER_KEY=\$(cat /etc/logbook-sync/env | cut -d= -f2) \\"
echo "       logbook-sync -c /etc/logbook-sync/config.toml user-add --username admin --admin"
echo "  3. Enable and start the service:"
echo "     sudo systemctl enable logbook-sync"
echo "     sudo systemctl start logbook-sync"
echo "  4. Access the web interface at http://127.0.0.1:3000"
