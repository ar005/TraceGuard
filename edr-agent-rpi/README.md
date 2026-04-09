# OEDR Agent — Raspberry Pi

Build and run the OEDR EDR agent on Raspberry Pi (ARM64).

## Prerequisites

On the Pi:
```bash
sudo apt install golang gcc
```

## Quick Start

**1. Copy the entire project to Pi:**
```bash
# From your dev machine
scp -r /path/to/edr/ pi@YOUR_PI_IP:~/edr/
```

**2. On the Pi — build:**
```bash
cd ~/edr/edr-agent-rpi
bash build.sh
```

**3. Install and start:**
```bash
sudo bash install.sh
# It will ask for your backend URL (e.g. 192.168.1.100:50051)
```

**4. Verify:**
```bash
sudo systemctl status edr-agent
sudo journalctl -u edr-agent -f
curl http://127.0.0.1:9999/health
```

## What Runs on Pi

12 out of 15 monitors (eBPF disabled — no kernel BTF):

| Monitor | What it detects |
|---------|----------------|
| kmod | Rootkit module loading, unsigned drivers |
| usb | USB connect/disconnect, mass storage |
| memmon | Shellcode, anonymous RWX memory |
| cronmon | Suspicious cron jobs, reverse shells |
| pipemon | C2 named pipes in /tmp, /dev/shm |
| sharemount | NFS/CIFS mount detection |
| tlssni | HTTPS domains per-process |
| auth | SSH brute force, sudo |
| cmd | Shell history, reverse shells |
| registry | /etc changes + Pi boot config |
| vuln | dpkg inventory, CVE matching |
| browser | Extension receiver on localhost |

## Files

```
edr-agent-rpi/
├── build.sh              # Build script (run on Pi)
├── install.sh            # Install + systemd service
├── config/
│   └── agent-rpi.yaml    # Pi-optimized config
└── README.md
```

The build script uses the agent source from `../edr-agent/`. The full project must be present.

## Configuration

Edit `/etc/edr/agent.yaml` after install:

```yaml
agent:
  backend_url: "YOUR_BACKEND_IP:50051"
  tags: [rpi, arm64, iot]

monitors:
  # Adjust poll intervals for your needs
  kmod:
    poll_interval_s: 15    # Check kernel modules every 15s
  usb:
    poll_interval_s: 10    # Check USB every 10s
  memmon:
    poll_interval_s: 30    # Check memory every 30s
```

## Manage

```bash
sudo systemctl status edr-agent    # Status
sudo systemctl stop edr-agent      # Stop
sudo systemctl restart edr-agent   # Restart
sudo journalctl -u edr-agent -f    # Live logs
```

## Uninstall

```bash
sudo systemctl stop edr-agent
sudo systemctl disable edr-agent
sudo rm /etc/systemd/system/edr-agent.service
sudo rm /usr/local/bin/edr-agent
sudo rm -rf /etc/edr /var/lib/edr /var/log/edr
sudo systemctl daemon-reload
```
