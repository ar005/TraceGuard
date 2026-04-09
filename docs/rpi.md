# OEDR Agent for Raspberry Pi — Implementation Plan

## Overview

Port the OEDR agent to Raspberry Pi (ARM/ARM64 Linux). The Pi runs Linux, so most of the agent code works as-is — the main challenges are ARM eBPF compilation, resource constraints, and GPIO/peripheral monitoring unique to Pi deployments.

## Difficulty: Low-Medium

The Pi runs Linux with kernel eBPF support (kernel 5.10+ on Raspberry Pi OS). Go cross-compiles to ARM natively. Most monitors are pure userspace (no eBPF) and will work without changes.

---

## Architecture

```
Raspberry Pi (ARM/ARM64)
├── edr-agent (Go binary, cross-compiled)
│   ├── eBPF monitors (process, network, file) — need ARM BPF objects
│   ├── Userspace monitors (kmod, usb, memmon, cronmon, pipemon, sharemount, tlssni, auth, cmd, registry, vuln, browser) — work as-is
│   └── Pi-specific monitors (GPIO, temperature, boot config)
└── gRPC → Backend (same backend, no changes needed)
```

---

## Phase 1 — Cross-Compile Existing Agent (1-2 days)

### What works immediately (no changes)

All 12 userspace monitors work on ARM Linux:

| Monitor | Method | ARM Compatible |
|---------|--------|---------------|
| kmod | /proc/modules polling | ✅ Yes |
| usb | /sys/bus/usb/devices polling | ✅ Yes |
| memmon | /proc/*/maps polling | ✅ Yes |
| cronmon | Event bus + file parsing | ✅ Yes |
| pipemon | Filesystem scan for FIFOs | ✅ Yes |
| sharemount | /proc/mounts polling | ✅ Yes |
| tlssni | AF_PACKET raw socket | ✅ Yes |
| auth | auth.log tailing | ✅ Yes |
| cmd | Shell history monitoring | ✅ Yes |
| registry | Config file watching | ✅ Yes |
| vuln | dpkg-query / rpm | ✅ Yes (dpkg on Pi OS) |
| browser | HTTP receiver on localhost | ✅ Yes |

### Cross-compilation

```bash
# For Raspberry Pi 3/4/5 (ARM64)
GOOS=linux GOARCH=arm64 go build -o edr-agent-arm64 ./cmd/agent/

# For Raspberry Pi Zero/1/2 (ARM 32-bit)
GOOS=linux GOARCH=arm GOARM=7 go build -o edr-agent-arm32 ./cmd/agent/
```

### What needs change

The Go binary will compile, but **eBPF probes won't load** because:
1. `.bpf.o` files are compiled for x86_64 — need ARM BPF objects
2. `vmlinux.h` is architecture-specific — need ARM version
3. Some kernel tracepoints differ on ARM

**Workaround for Phase 1**: Disable eBPF monitors (process, network, file) in the Pi config. The 12 userspace monitors provide good coverage without eBPF.

```yaml
# config/agent-rpi.yaml
monitors:
  process:
    enabled: false  # Needs ARM eBPF (Phase 2)
  network:
    enabled: false  # Needs ARM eBPF (Phase 2)
  file:
    enabled: false  # Needs ARM eBPF (Phase 2)
  # Everything else works
  kmod:
    enabled: true
  usb:
    enabled: true
  memmon:
    enabled: true
  cronmon:
    enabled: true
  pipemon:
    enabled: true
  sharemount:
    enabled: true
  tlssni:
    enabled: true
  browser:
    enabled: true
```

### Deployment on Pi

```bash
# Copy binary to Pi
scp edr-agent-arm64 pi@raspberrypi:/usr/local/bin/edr-agent

# Copy config
scp config/agent-rpi.yaml pi@raspberrypi:/etc/edr/agent.yaml

# Run
ssh pi@raspberrypi 'sudo /usr/local/bin/edr-agent --config /etc/edr/agent.yaml'
```

### systemd service for Pi

```ini
# /etc/systemd/system/edr-agent.service
[Unit]
Description=OEDR Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edr-agent --config /etc/edr/agent.yaml
Restart=always
RestartSec=5
User=root
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

---

## Phase 2 — ARM eBPF Compilation (3-5 days)

### Requirements

- Raspberry Pi with kernel >= 5.10 (Pi OS Bookworm has 6.1+)
- `clang` and `llvm` installed on Pi (or cross-compile BPF objects)
- ARM64 `vmlinux.h` generated from Pi kernel BTF

### Steps

1. **Generate ARM64 vmlinux.h on the Pi**:
   ```bash
   sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux-arm64.h
   ```

2. **Cross-compile BPF objects for ARM64**:
   ```bash
   # On build machine with clang
   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
     -I./ebpf/headers \
     -c ebpf/process/process.bpf.c -o ebpf/process/process-arm64.bpf.o

   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
     -c ebpf/network/network.bpf.c -o ebpf/network/network-arm64.bpf.o

   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
     -c ebpf/file/file.bpf.c -o ebpf/file/file-arm64.bpf.o
   ```

3. **Generate Go bindings with bpf2go for ARM64**:
   ```bash
   GOARCH=arm64 go generate ./ebpf/...
   ```

4. **Conditional loading in monitor code**:
   ```go
   // Detect architecture at runtime
   if runtime.GOARCH == "arm64" {
       spec, err = loadProcessArm64()
   } else {
       spec, err = loadProcessBpfel()
   }
   ```

### ARM eBPF kernel tracepoint differences

| Tracepoint | x86_64 | ARM64 | Change needed |
|-----------|--------|-------|---------------|
| sys_enter_execve | ✅ | ✅ | Same |
| sched_process_fork | ✅ | ✅ | Same |
| sys_enter_ptrace | ✅ | ✅ | Same |
| tcp_connect | ✅ | ✅ | Same (kprobe) |
| vfs_write | ✅ | ✅ | Same (kprobe) |

Most tracepoints are architecture-independent. The main difference is the `struct pt_regs` layout for reading syscall arguments — ARM64 uses `regs[0-7]` instead of `di, si, dx`.

---

## Phase 3 — Pi-Specific Monitors (2-3 days)

### GPIO Monitor

Raspberry Pi has GPIO pins used for physical security (door sensors, motion detectors, tamper switches). An EDR on a Pi should monitor GPIO state changes.

```go
// monitor/gpio/monitor.go
type Config struct {
    Enabled bool
    WatchPins []int  // GPIO pin numbers to monitor
    PollIntervalMs int
}

// Polls /sys/class/gpio/gpioN/value
// Emits GPIO_CHANGE events when pin state changes
```

**Event type**: `GPIO_CHANGE`
```go
type GPIOEvent struct {
    BaseEvent
    Pin       int    `json:"pin"`
    Value     int    `json:"value"`     // 0 or 1
    Direction string `json:"direction"` // "in" or "out"
    Label     string `json:"label"`     // user-assigned label
}
```

**Use cases**:
- Door open/close sensor → alert when door opens after hours
- Tamper switch → alert when Pi enclosure is opened
- Motion sensor → alert on physical presence

### Temperature Monitor

Pi has built-in CPU temperature sensor. Overheating can indicate crypto-mining malware.

```go
// Read /sys/class/thermal/thermal_zone0/temp
// Value is in millidegrees Celsius (e.g., 45000 = 45.0°C)
// Emit TEMP_ALERT when > threshold (default 75°C)
```

### Boot Config Monitor

Watch `/boot/config.txt` and `/boot/cmdline.txt` for tampering:
- Changed `enable_uart` could indicate debugging backdoor
- Modified `gpu_mem` could indicate crypto-mining
- Changed kernel parameters in cmdline.txt

---

## Phase 4 — Resource Optimization (1-2 days)

Raspberry Pi has limited resources. Optimize for:

| Resource | Pi Zero | Pi 4 | Pi 5 | Optimization |
|----------|---------|------|------|-------------|
| RAM | 512MB | 2-8GB | 4-8GB | Reduce buffer sizes, smaller event bus channels |
| CPU | 1 core | 4 cores | 4 cores | Longer poll intervals, fewer concurrent goroutines |
| Storage | SD card | SD/SSD | SD/NVMe | Smaller SQLite buffer, aggressive retention |
| Network | WiFi | GbE | GbE | Batch more events, compress gRPC stream |

### Pi-specific config defaults

```yaml
# config/agent-rpi.yaml
buffer:
  path: "/var/lib/edr/events.db"
  max_size_mb: 64        # 64MB instead of 512MB
  flush_interval_s: 10   # 10s instead of 5s

monitors:
  memmon:
    poll_interval_s: 30  # 30s instead of 15s
  kmod:
    poll_interval_s: 15  # 15s instead of 5s
  usb:
    poll_interval_s: 30  # 30s instead of 10s
  tlssni:
    enabled: true        # Low overhead on Pi
```

---

## Build Matrix

| Target | GOOS | GOARCH | GOARM | eBPF | Binary Name |
|--------|------|--------|-------|------|-------------|
| Pi Zero/1 | linux | arm | 6 | No | edr-agent-armv6 |
| Pi 2 | linux | arm | 7 | No | edr-agent-armv7 |
| Pi 3/4/5 | linux | arm64 | — | Yes (Phase 2) | edr-agent-arm64 |

### Makefile additions

```makefile
build-rpi-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o edr-agent-arm64 ./cmd/agent/

build-rpi-arm32:
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-w -s" -o edr-agent-armv7 ./cmd/agent/

build-rpi-zero:
	GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-w -s" -o edr-agent-armv6 ./cmd/agent/
```

---

## Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | 1-2 days | Cross-compiled agent with 12 userspace monitors |
| Phase 2 | 3-5 days | ARM64 eBPF process/network/file monitors |
| Phase 3 | 2-3 days | GPIO, temperature, boot config monitors |
| Phase 4 | 1-2 days | Resource optimization for Pi constraints |
| **Total** | **7-12 days** | **Full Pi agent with 15+ monitors** |

---

## Testing Checklist

- [ ] Cross-compile binary for ARM64
- [ ] Binary runs on Pi 4/5
- [ ] All 12 userspace monitors collect events
- [ ] Events stream to backend via gRPC
- [ ] Events appear in UI dashboard
- [ ] Package scan (dpkg-query) works
- [ ] Browser monitor receives extension events
- [ ] TLS SNI captures HTTPS domains
- [ ] USB device detection works
- [ ] systemd service starts on boot
- [ ] Memory usage < 100MB idle
- [ ] CPU usage < 5% idle
- [ ] ARM64 eBPF probes load (Phase 2)
- [ ] GPIO monitor detects pin changes (Phase 3)
- [ ] Temperature alerts fire > 75°C (Phase 3)
