#!/bin/bash
# Logbook Sync Installation Script
# Usage: ./install.sh [--user|--system]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-user}"

print_usage() {
    echo "Usage: $0 [--user|--system]"
    echo ""
    echo "Options:"
    echo "  --user    Install for current user only (default)"
    echo "  --system  Install system-wide (requires sudo)"
    echo ""
}

install_user() {
    echo "Installing logbook-sync for user $USER..."

    # Build release binary
    echo "Building release binary..."
    cargo build --release

    # Create directories
    mkdir -p ~/.local/bin
    mkdir -p ~/.config/logbook-sync
    mkdir -p ~/.local/share/logbook-sync
    mkdir -p ~/.config/systemd/user

    # Install binary
    echo "Installing binary to ~/.local/bin/logbook-sync"
    cp target/release/logbook-sync ~/.local/bin/

    # Install config if not exists
    if [ ! -f ~/.config/logbook-sync/config.toml ]; then
        echo "Installing example config to ~/.config/logbook-sync/config.toml"
        cp contrib/config.toml.example ~/.config/logbook-sync/config.toml
        echo "IMPORTANT: Edit ~/.config/logbook-sync/config.toml with your settings!"
    else
        echo "Config already exists, skipping..."
    fi

    # Install systemd user service
    echo "Installing systemd user service..."
    cp contrib/systemd/logbook-sync.user.service ~/.config/systemd/user/logbook-sync.service

    # Reload systemd
    systemctl --user daemon-reload

    echo ""
    echo "Installation complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Edit ~/.config/logbook-sync/config.toml"
    echo "  2. Set your callsign, watch_dir, and QRZ API key"
    echo "  3. Test: logbook-sync -c ~/.config/logbook-sync/config.toml status"
    echo "  4. Enable service: systemctl --user enable --now logbook-sync"
    echo "  5. Check logs: journalctl --user -u logbook-sync -f"
    echo ""
}

install_system() {
    echo "Installing logbook-sync system-wide..."

    if [ "$EUID" -ne 0 ]; then
        echo "Error: System install requires root. Use: sudo $0 --system"
        exit 1
    fi

    # Build release binary
    echo "Building release binary..."
    cargo build --release

    # Create directories
    mkdir -p /etc/logbook-sync
    mkdir -p /var/lib/logbook-sync

    # Install binary
    echo "Installing binary to /usr/local/bin/logbook-sync"
    cp target/release/logbook-sync /usr/local/bin/
    chmod 755 /usr/local/bin/logbook-sync

    # Install config if not exists
    if [ ! -f /etc/logbook-sync/config.toml ]; then
        echo "Installing example config to /etc/logbook-sync/config.toml"
        cp contrib/config.toml.example /etc/logbook-sync/config.toml
        chmod 600 /etc/logbook-sync/config.toml
        echo "IMPORTANT: Edit /etc/logbook-sync/config.toml with your settings!"
    else
        echo "Config already exists, skipping..."
    fi

    # Install systemd service
    echo "Installing systemd service..."
    cp contrib/systemd/logbook-sync.service /etc/systemd/system/

    # Reload systemd
    systemctl daemon-reload

    echo ""
    echo "Installation complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Edit /etc/logbook-sync/config.toml"
    echo "  2. Set your callsign, watch_dir, and QRZ API key"
    echo "  3. Test: logbook-sync -c /etc/logbook-sync/config.toml status"
    echo "  4. Enable service: systemctl enable --now logbook-sync"
    echo "  5. Check logs: journalctl -u logbook-sync -f"
    echo ""
}

case "$MODE" in
    --user|-u|user)
        install_user
        ;;
    --system|-s|system)
        install_system
        ;;
    --help|-h|help)
        print_usage
        ;;
    *)
        echo "Unknown option: $MODE"
        print_usage
        exit 1
        ;;
esac
