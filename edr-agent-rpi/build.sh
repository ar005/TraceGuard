#!/bin/bash
# ─────────────────────────────────────────────────────────────
# OEDR Agent — Build Script for Raspberry Pi
# Run this ON the Pi after copying the project files.
#
# Prerequisites: Go 1.21+ installed on Pi
#   sudo apt install golang gcc
# ─────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_SRC="$SCRIPT_DIR/../edr-agent"
OUTPUT="$SCRIPT_DIR/edr-agent"

echo "═══════════════════════════════════════════════════"
echo "  OEDR Agent — Raspberry Pi Build"
echo "═══════════════════════════════════════════════════"

# Check Go
if ! command -v go &>/dev/null; then
  echo "ERROR: Go is not installed."
  echo "Install: sudo apt install golang"
  exit 1
fi
echo "Go: $(go version)"

# Check GCC (needed for CGO/SQLite)
if ! command -v gcc &>/dev/null; then
  echo "ERROR: gcc is not installed."
  echo "Install: sudo apt install gcc"
  exit 1
fi
echo "GCC: $(gcc --version | head -1)"

# Check source exists
if [ ! -f "$AGENT_SRC/go.mod" ]; then
  echo "ERROR: Agent source not found at $AGENT_SRC"
  echo "Make sure the full edr/ project is copied to the Pi."
  echo ""
  echo "Expected structure:"
  echo "  edr/"
  echo "  ├── edr-agent/        ← agent source code"
  echo "  └── edr-agent-rpi/    ← this directory"
  exit 1
fi

echo ""
echo "▶ Building agent (CGO_ENABLED=1 for SQLite)..."
cd "$AGENT_SRC"
CGO_ENABLED=1 go build -ldflags="-w -s" -o "$OUTPUT" ./cmd/agent/

if [ -f "$OUTPUT" ]; then
  SIZE=$(du -h "$OUTPUT" | cut -f1)
  ARCH=$(file "$OUTPUT" | grep -oP 'ARM aarch64|Intel 80386|x86-64' || echo "unknown")
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  ✅ Build successful!"
  echo "═══════════════════════════════════════════════════"
  echo "  Binary: $OUTPUT"
  echo "  Size:   $SIZE"
  echo "  Arch:   $ARCH"
  echo ""
  echo "  Next: sudo bash install.sh"
else
  echo "ERROR: Build failed — no binary produced."
  exit 1
fi
