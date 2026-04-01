#!/bin/bash
# ─────────────────────────────────────────────────────────────
# TraceGuard Agent — Raspberry Pi Installer
# Run on the Pi as root:  sudo bash install.sh
# ─────────────────────────────────────────────────────────────

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/edr"
DATA_DIR="/var/lib/edr"
LOG_DIR="/var/log/edr"
BINARY="edr-agent-rpi"
SERVICE="edr-agent"

echo "═══════════════════════════════════════════════════"
echo "  TraceGuard Agent Installer — Raspberry Pi"
echo "═══════════════════════════════════════════════════"

# Check root
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Run as root (sudo bash install.sh)"
  exit 1
fi

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
  echo "ERROR: This binary is for ARM64 (aarch64), got $ARCH"
  exit 1
fi

# Check binary exists
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$SCRIPT_DIR/$BINARY" ]; then
  echo "ERROR: Binary $BINARY not found in $SCRIPT_DIR"
  exit 1
fi

echo ""
echo "▶ Creating directories..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$DATA_DIR/quarantine"
chmod 700 "$DATA_DIR" "$DATA_DIR/quarantine"

echo "▶ Installing binary..."
cp "$SCRIPT_DIR/$BINARY" "$INSTALL_DIR/edr-agent"
chmod 755 "$INSTALL_DIR/edr-agent"

echo "▶ Installing config..."
if [ -f "$CONFIG_DIR/agent.yaml" ]; then
  echo "  Config already exists, not overwriting. New config saved as agent.yaml.new"
  cp "$SCRIPT_DIR/config/agent-rpi.yaml" "$CONFIG_DIR/agent.yaml.new"
else
  cp "$SCRIPT_DIR/config/agent-rpi.yaml" "$CONFIG_DIR/agent.yaml"
fi

# Prompt for backend URL
echo ""
read -p "Backend URL [localhost:50051]: " BACKEND_URL
BACKEND_URL="${BACKEND_URL:-localhost:50051}"
sed -i "s|backend_url: \"localhost:50051\"|backend_url: \"$BACKEND_URL\"|" "$CONFIG_DIR/agent.yaml"
echo "  Backend set to: $BACKEND_URL"

echo ""
echo "▶ Installing systemd service..."
cat > /etc/systemd/system/${SERVICE}.service << EOF
[Unit]
Description=TraceGuard Endpoint Detection Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edr-agent --config /etc/edr/agent.yaml
Restart=always
RestartSec=5
User=root
LimitMEMLOCK=infinity
StandardOutput=journal
StandardError=journal

# Resource limits for Pi
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE}

echo ""
echo "▶ Starting agent..."
systemctl start ${SERVICE}
sleep 2

if systemctl is-active --quiet ${SERVICE}; then
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  ✅ TraceGuard Agent installed and running!"
  echo "═══════════════════════════════════════════════════"
  echo ""
  echo "  Binary:  $INSTALL_DIR/edr-agent"
  echo "  Config:  $CONFIG_DIR/agent.yaml"
  echo "  Logs:    $LOG_DIR/agent.log"
  echo "  Service: systemctl status $SERVICE"
  echo ""
  echo "  Commands:"
  echo "    sudo systemctl status edr-agent   # Check status"
  echo "    sudo systemctl stop edr-agent     # Stop"
  echo "    sudo systemctl restart edr-agent  # Restart"
  echo "    sudo journalctl -u edr-agent -f   # Live logs"
  echo ""
else
  echo ""
  echo "  ⚠️  Agent installed but may not be running."
  echo "  Check: sudo journalctl -u $SERVICE -n 20"
fi
