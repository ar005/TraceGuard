# TraceGuard Agent — Raspberry Pi

Pre-built ARM64 EDR agent for Raspberry Pi 3/4/5.

## What Works

12 out of 15 monitors run on Pi (eBPF monitors disabled due to no kernel BTF):

| Monitor | Status | What it detects |
|---------|--------|----------------|
| Kernel modules (kmod) | ✅ | Rootkit module loading, unsigned drivers |
| USB devices | ✅ | USB connect/disconnect, mass storage |
| Memory injection (memmon) | ✅ | Shellcode, anonymous RWX memory |
| Cron parsing (cronmon) | ✅ | Suspicious cron jobs, reverse shells |
| Named pipes (pipemon) | ✅ | C2 named pipes in /tmp, /dev/shm |
| Network shares (sharemount) | ✅ | NFS/CIFS mount detection |
| TLS SNI | ✅ | HTTPS domains per-process |
| Auth/login | ✅ | SSH brute force, sudo |
| Commands | ✅ | Shell history, reverse shells |
| Registry/config | ✅ | /etc changes + Pi boot config |
| Packages/vulns | ✅ | dpkg inventory, CVE matching |
| Browser monitor | ✅ | Extension receiver on localhost |
| Process (eBPF) | ❌ | Needs kernel BTF |
| Network (eBPF) | ❌ | Needs kernel BTF |
| File (eBPF) | ❌ | Needs kernel BTF |

## Quick Install

Copy this entire `edr-agent-rpi/` directory to the Pi, then:

```bash
sudo bash install.sh
```

The installer will:
1. Copy binary to `/usr/local/bin/edr-agent`
2. Install config to `/etc/edr/agent.yaml`
3. Prompt for backend URL
4. Create systemd service
5. Start the agent

## Manual Install

```bash
# Copy binary
sudo cp edr-agent-rpi /usr/local/bin/edr-agent
sudo chmod 755 /usr/local/bin/edr-agent

# Copy config
sudo mkdir -p /etc/edr
sudo cp config/agent-rpi.yaml /etc/edr/agent.yaml

# Edit backend URL
sudo nano /etc/edr/agent.yaml
# Change backend_url to your backend IP:50051

# Run
sudo /usr/local/bin/edr-agent --config /etc/edr/agent.yaml
```

## Configure Backend URL

Edit `/etc/edr/agent.yaml`:

```yaml
agent:
  backend_url: "YOUR_BACKEND_IP:50051"
  tags: [rpi, arm64, iot]
```

If your backend is on the same Tailscale network:
```yaml
  backend_url: "100.x.x.x:50051"
```

## Resource Usage

| Resource | Expected |
|----------|----------|
| RAM | ~50-80MB |
| CPU | ~2-5% idle |
| Disk | 14MB binary + 64MB max buffer |
| Network | ~1-5KB/s to backend |

## Pi-Specific Config

The Pi config adds monitoring of boot config files:

```yaml
monitors:
  registry:
    extra_paths:
      - /boot/firmware/config.txt   # Pi boot config
      - /boot/firmware/cmdline.txt  # Kernel boot params
```

Changes to these files (gpu_mem, enable_uart, kernel params) generate alerts.

## Troubleshooting

```bash
# Check service status
sudo systemctl status edr-agent

# Live logs
sudo journalctl -u edr-agent -f

# Check if monitors are running
curl http://127.0.0.1:9999/health  # Browser monitor

# Manual run with debug logging
sudo /usr/local/bin/edr-agent --config /etc/edr/agent.yaml
```

## Supported Pi Models

| Model | Architecture | Binary | Tested |
|-------|-------------|--------|--------|
| Pi 5 | ARM64 | edr-agent-rpi | ✅ |
| Pi 4 | ARM64 | edr-agent-rpi | ✅ |
| Pi 3 B+ | ARM64 | edr-agent-rpi | Should work |
| Pi Zero 2 W | ARM64 | edr-agent-rpi | Should work |
| Pi Zero/1/2 | ARM32 | Not included | Needs ARMv7 build |
