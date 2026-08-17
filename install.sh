#!/bin/bash
# P³ Agent Cell — One-shot installer
set -euo pipefail

PROJECT_DIR=~/Стільниця/p3-agent-cell
CONFIG_DIR=~/.config/p3-agent-cell

echo "P³ Agent Cell — Installer"
echo ""

# 1. Config directory
mkdir -p "$CONFIG_DIR"
echo "✅ Config dir: $CONFIG_DIR"

# 2. Ask for token
read -rsp "GitHub Token (gist scope): " TOKEN
echo ""
echo "GITHUB_TOKEN=$TOKEN" > "$CONFIG_DIR/token.env"
chmod 600 "$CONFIG_DIR/token.env"
echo "✅ Token saved (chmod 600)"

# 3. Copy config
cp "$PROJECT_DIR/config/cell.conf" "$CONFIG_DIR/cell.conf"
echo "✅ Config copied"

# 4. Install systemd service
mkdir -p ~/.config/systemd/user
cp "$PROJECT_DIR/systemd/p3-warden.service" ~/.config/systemd/user/
systemctl --user daemon-reload
echo "✅ Systemd service installed"

# 5. Enable and start
systemctl --user enable p3-warden.service
systemctl --user start p3-warden.service
echo "✅ Warden started (systemd --user)"

# 6. Check
systemctl --user status p3-warden.service --no-pager
echo ""
echo "P³ Agent Cell installed!"
echo "  Cell management: $PROJECT_DIR/warden/p3-cell.sh {build|start|stop|shell}"
echo "  View logs:       journalctl --user -u p3-warden -f"
