# EDR Agent — Linux

A production-grade Endpoint Detection & Response agent for Linux using eBPF.

## Architecture

```
edr-agent/
├── cmd/agent/          # Main entrypoint
├── internal/
│   ├── agent/          # Core agent lifecycle (start/stop/reload)
│   ├── events/         # Canonical event types + ring buffer
│   ├── monitor/
│   │   ├── process/    # eBPF process monitor (execve, exit, fork)
│   │   ├── network/    # eBPF network monitor (tcp/udp connections)
│   │   ├── file/       # fanotify/inotify file integrity monitor
│   │   └── registry/   # Linux "registry" — critical config file watcher
│   ├── selfprotect/    # Watchdog + anti-tamper
│   ├── buffer/         # Local SQLite event buffer (offline resilience)
│   ├── transport/      # gRPC client to backend
│   ├── config/         # YAML config loader + hot-reload
│   └── logger/         # Structured logger (zerolog)
├── ebpf/
│   ├── process/        # process.bpf.c — execve/exit/fork probes
│   ├── network/        # network.bpf.c — tcp/udp socket hooks
│   └── file/           # file.bpf.c — vfs read/write hooks
└── pkg/
    ├── types/          # Shared types (ProcessEvent, NetworkEvent, etc.)
    └── utils/          # Hash, IP conversion, string helpers
```

## Requirements

- Linux kernel >= 5.8 (for eBPF ring buffer support)
- Go >= 1.21
- clang >= 14 + llvm
- libbpf-dev >= 1.0
- linux-headers for your kernel version
- Root or CAP_BPF + CAP_SYS_ADMIN capabilities

## Build

```bash
# Install deps (Ubuntu/Debian)
sudo apt-get install -y golang clang llvm libbpf-dev linux-headers-$(uname -r)

# Generate eBPF skeletons (compile .bpf.c → Go-embeddable bytecode)
make ebpf

# Build agent binary
make build

# Build + run (requires root)
make run
```

## Configuration

Edit `config/agent.yaml` before running. Key fields:

```yaml
agent:
  id: ""              # auto-generated UUID if empty
  hostname: ""        # auto-detected
  backend_url: "localhost:50051"
  tls:
    cert: "/etc/edr/agent.crt"
    key:  "/etc/edr/agent.key"
    ca:   "/etc/edr/ca.crt"

monitors:
  process:  { enabled: true }
  network:  { enabled: true }
  file:     { enabled: true, watch_paths: ["/etc", "/usr/bin", "/tmp"] }
  registry: { enabled: true }

buffer:
  path: "/var/lib/edr/events.db"
  max_size_mb: 512
  flush_interval_s: 5

log:
  level: "info"   # debug | info | warn | error
  format: "json"  # json | text
  path: "/var/log/edr/agent.log"
```

## Running as a systemd service

```bash
sudo cp edr-agent /usr/local/bin/
sudo cp config/agent.yaml /etc/edr/
sudo cp deploy/edr-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now edr-agent
```
