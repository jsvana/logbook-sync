#!/bin/bash
# Logbook Sync Uninstall Script
# Usage: ./uninstall.sh [--user|--system]

set -e

MODE="${1:-user}"

print_usage() {
    echo "Usage: $0 [--user|--system]"
    echo ""
    echo "Options:"
    echo "  --user    Uninstall user installation (default)"
    echo "  --system  Uninstall system-wide (requires sudo)"
    echo ""
}

uninstall_user() {
    echo "Uninstalling logbook-sync for user $USER..."

    # Stop and disable service
    systemctl --user stop logbook-sync 2>/dev/null || true
    systemctl --user disable logbook-sync 2>/dev/null || true

    # Remove files
    rm -f ~/.local/bin/logbook-sync
    rm -f ~/.config/systemd/user/logbook-sync.service

    # Reload systemd
    systemctl --user daemon-reload

    echo ""
    echo "Uninstall complete!"
    echo ""
    echo "The following were preserved:"
    echo "  - ~/.config/logbook-sync/ (configuration)"
    echo "  - ~/.local/share/logbook-sync/ (database)"
    echo ""
    echo "To remove all data: rm -rf ~/.config/logbook-sync ~/.local/share/logbook-sync"
    echo ""
}

uninstall_system() {
    echo "Uninstalling logbook-sync system-wide..."

    if [ "$EUID" -ne 0 ]; then
        echo "Error: System uninstall requires root. Use: sudo $0 --system"
        exit 1
    fi

    # Stop and disable service
    systemctl stop logbook-sync 2>/dev/null || true
    systemctl disable logbook-sync 2>/dev/null || true

    # Remove files
    rm -f /usr/local/bin/logbook-sync
    rm -f /etc/systemd/system/logbook-sync.service

    # Reload systemd
    systemctl daemon-reload

    echo ""
    echo "Uninstall complete!"
    echo ""
    echo "The following were preserved:"
    echo "  - /etc/logbook-sync/ (configuration)"
    echo "  - /var/lib/logbook-sync/ (database)"
    echo ""
    echo "To remove all data: rm -rf /etc/logbook-sync /var/lib/logbook-sync"
    echo ""
}

case "$MODE" in
    --user|-u|user)
        uninstall_user
        ;;
    --system|-s|system)
        uninstall_system
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
