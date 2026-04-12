#!/bin/bash
# ─────────────────────────────────────────────────────────────
# OEDR Agent — Raspberry Pi Installer
# Run on the Pi as root after building:
#   sudo bash build.sh
#   sudo bash install.sh
# ─────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edr"
DATA_DIR="/var/lib/edr"
LOG_DIR="/var/log/edr"
BINARY="$SCRIPT_DIR/edr-agent"
SERVICE="edr-agent"

echo "═══════════════════════════════════════════════════"
echo "  OEDR Agent Installer — Raspberry Pi"
echo "═══════════════════════════════════════════════════"

# Check root
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run as root (sudo bash install.sh)"
  exit 1
fi

# Check binary exists
if [ ! -f "$BINARY" ]; then
  echo "ERROR: Binary not found at $BINARY"
  echo "Run 'bash build.sh' first."
  exit 1
fi

echo ""
echo "▶ Creating directories..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$DATA_DIR/quarantine"
chmod 700 "$DATA_DIR" "$DATA_DIR/quarantine"

echo "▶ Installing binary..."
cp "$BINARY" "$INSTALL_DIR/edr-agent"
chmod 755 "$INSTALL_DIR/edr-agent"

echo "▶ Installing config..."
if [ -f "$CONFIG_DIR/agent.yaml" ]; then
  echo "  Config exists, saving new as agent.yaml.new"
  cp "$SCRIPT_DIR/config/agent-rpi.yaml" "$CONFIG_DIR/agent.yaml.new"
else
  cp "$SCRIPT_DIR/config/agent-rpi.yaml" "$CONFIG_DIR/agent.yaml"
fi

# Prompt for backend URL
echo ""
read -p "Backend URL (e.g. 192.168.1.100:50051) [localhost:50051]: " BACKEND_URL
BACKEND_URL="${BACKEND_URL:-localhost:50051}"
# Sanitize input: strip characters that could break sed or YAML.
BACKEND_URL=$(printf '%s' "$BACKEND_URL" | tr -cd 'a-zA-Z0-9.:/-')
sed -i "s|backend_url: \"localhost:50051\"|backend_url: \"$BACKEND_URL\"|" "$CONFIG_DIR/agent.yaml"
echo "  Backend: $BACKEND_URL"

echo ""
echo "▶ Installing systemd service..."
cat > /etc/systemd/system/${SERVICE}.service << EOF
[Unit]
Description=OEDR Endpoint Detection Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edr-agent --config /etc/edr/agent.yaml
Restart=always
RestartSec=5
User=root
LimitMEMLOCK=infinity
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE}

echo ""
echo "▶ Starting agent..."
systemctl restart ${SERVICE}
sleep 3

if systemctl is-active --quiet ${SERVICE}; then
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  ✅ OEDR Agent installed and running!"
  echo "═══════════════════════════════════════════════════"
  echo ""
  echo "  Binary:  $INSTALL_DIR/edr-agent"
  echo "  Config:  $CONFIG_DIR/agent.yaml"
  echo "  Logs:    $LOG_DIR/agent.log"
  echo ""
  echo "  Commands:"
  echo "    sudo systemctl status edr-agent"
  echo "    sudo systemctl stop edr-agent"
  echo "    sudo systemctl restart edr-agent"
  echo "    sudo journalctl -u edr-agent -f"
  echo "    curl http://127.0.0.1:9999/health"
  echo ""
else
  echo ""
  echo "  ⚠️  Agent may not have started correctly."
  echo "  Check: sudo journalctl -u $SERVICE -n 20"
fi
