# TraceGuard — Open Endpoint Detection & Response

A self-hosted EDR platform for Linux. Monitors endpoints with eBPF, detects threats in real time, and provides a web interface for investigation. No SaaS, no vendor lock-in — runs entirely on your infrastructure.

---

## Architecture

```
Endpoints                          Backend                         Analysts
┌──────────────┐                ┌──────────────────┐            ┌──────────────┐
│  edr-agent   │  gRPC stream   │   edr-backend    │  REST API  │   edr-ui     │
│  (Go + eBPF) │───────────────>│   (Go + Gin)     │<──────────>│  (Flask)     │
│              │    :50051       │                  │   :8080    │   :5000      │
│  23 eBPF     │                │  Detection engine│            │  Dashboard   │
│  hooks       │  Live Response │  21 rules        │            │  Alerts      │
│  SQLite buf  │<──────────────>│  Incidents       │            │  Incidents   │
│  Containment │   bidi gRPC    │  PostgreSQL      │            │  Hunt        │
└──────────────┘                └──────────────────┘            │  Live Shell  │
                                                                │  Vulns       │
                                        ┌──────────────┐       │  Process tree│
                                        │  edr-admin   │       │  Rule builder│
                                        │  (Flask)     │       └──────────────┘
                                        │   :5001      │
                                        │  User/key    │
                                        │  management  │
                                        └──────────────┘
```

| Component | Language | Port(s) | Purpose |
|-----------|----------|---------|---------|
| **edr-agent** | Go + eBPF C | — | Endpoint sensor: process, network, file, auth monitoring via eBPF; live response shell; network containment |
| **edr-backend** | Go | :8080 (REST), :50051 (gRPC) | Event ingestion, detection engine, incident correlation, vulnerability tracking, REST API, PostgreSQL storage |
| **edr-ui** | Python/Flask | :5000 | Analyst dashboard with live event stream, threat hunting, live response, vulnerability view, process tree, rule builder |
| **edr-admin** | Python/Flask | :5001 | Admin portal for user management, API keys, audit log |

---

## What it monitors

### Process monitoring (eBPF)
- Every `execve` — PID, PPID, full command line, exe path, username, args, cwd
- Process forking via `sched_process_fork` with clone flags
- `ptrace` injection detection (ATTACH, POKETEXT, SETREGS, SEIZE)
- Fileless execution detection (memfd paths)
- Full process ancestry chain and parent process context
- Process tree reconstruction from stored events
- **Container awareness** — automatic detection of Docker, containerd, Podman, CRI-O containers; enriches every process event with container ID, runtime, image name, Kubernetes pod name, and namespace

### Network monitoring (eBPF + DNS snooper)
- Outbound TCP connections via `fentry/tcp_connect`
- Inbound TCP accepts via `fexit/inet_csk_accept`
- TCP state transitions and close events with byte counters
- UDP send/receive via kprobes
- **DNS snooping** — parses DNS response packets from raw UDP socket, emits `NET_DNS` events with queried domain + all resolved IPs
- Async reverse-DNS resolution with caching (4096 entries)
- `/proc/net/tcp` polling as fallback when eBPF is unavailable
- IPv4 and IPv6 support

### File monitoring (eBPF)
- File writes (`vfs_write`) with byte count and **SHA-256 hash**
- File creation (`vfs_create`) with mode bits and hash
- File deletion (`vfs_unlink`)
- File renames (`vfs_rename`) with old/new paths
- Permission changes via `security_inode_setattr`
- Async hash worker pool (4 goroutines) for non-blocking SHA-256 computation

### Authentication monitoring (log tailing)
- `/var/log/auth.log` and `/var/log/secure` tailing with auto-detection
- `LOGIN_SUCCESS` events — SSH accepted logins with method (password/publickey) and source IP
- `LOGIN_FAILED` events — SSH failed attempts, generic login failures
- `SUDO_EXEC` events — sudo commands with target user, TTY, and full command
- `su` session tracking

### Command monitoring (polling)
- Shell command capture via `/proc` scanning every 2 seconds
- Bash/zsh/sh history tailing for all users
- 38 built-in regex patterns for suspicious command detection
- Tags events with labels like `curl-pipe-shell`, `history-evasion`, `netcat-revshell`

### Vulnerability detection (package inventory)
- Periodic package inventory collection (every 6 hours)
- Auto-detects Debian (`dpkg-query`) and RHEL (`rpm`) package managers
- Emits `PKG_INVENTORY` events with full package list, OS name, and version
- Backend stores packages and matches against CVE databases

### Self-protection
- Agent watchdog with auto-restart and exponential backoff
- Anti-tamper detection (ptrace on agent PID, binary deletion/modification)
- Optional immutable binary via `chattr +i`


---

## Incident correlation

Alerts are automatically grouped into **incidents** using a 30-minute sliding correlation window per agent. When a new alert fires:

1. Backend checks for an existing OPEN/INVESTIGATING incident on the same agent within the last 30 minutes
2. If found — alert is appended to the existing incident (severity escalated, MITRE IDs merged, alert count incremented)
3. If not found — a new incident is created

Incidents aggregate severity, alert count, affected hosts, and MITRE ATT&CK techniques across all correlated alerts. Each incident has its own lifecycle: OPEN → INVESTIGATING → CLOSED.

---

## Live response

Remote investigation and remediation shell over gRPC bidirectional streaming.

### How it works
1. Agent connects to backend via the `LiveResponse` gRPC bidi stream
2. Analyst selects an agent in the **Live** tab and sends commands
3. Backend routes commands to the agent; agent executes and streams results back
4. Output displayed in the UI terminal

### Available commands

| Command | Description | Example |
|---------|-------------|---------|
| `ps` | List running processes | `ps` |
| `ls` | List files/directories | `ls /tmp` |
| `cat` | Read file contents | `cat /etc/passwd` |
| `netstat` | Show network connections (via `ss`) | `netstat` |
| `who` | Show logged-in users | `who` |
| `uname` | System information | `uname` |
| `uptime` | System uptime | `uptime` |
| `df` | Disk usage | `df` |
| `id` | User identity | `id` |
| `exec` | Run arbitrary command | `exec lsof -i :443` |
| `find` | Search for files | `find /tmp -name '*.sh'` |
| `sha256sum` | Hash a file | `sha256sum /usr/bin/curl` |
| `kill` | Kill a process | `kill -9 1234` |
| `isolate` | **Network containment** — block all traffic except backend | `isolate` |
| `release` | **Release containment** — restore normal networking | `release` |

Dangerous patterns (`rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`) are blocked. Output is capped at 1MB stdout / 64KB stderr.

---

## Network containment

Isolates a compromised endpoint from the network while maintaining EDR management access.

When activated via the `isolate` live response command:
- iptables rules are applied to block all inbound and outbound traffic
- **Exceptions**: loopback, established connections to backend, DNS for backend resolution
- Agent remains fully manageable through the gRPC channel
- Release via the `release` command removes all containment rules

---

## Threat hunting

SQL-like query language for searching across all raw telemetry. See [query-guide.md](query-guide.md) for the full reference.

### Quick examples

```sql
-- All bash executions in the last hour
event_type = 'PROCESS_EXEC' AND payload->>'exe_path' LIKE '%bash%'
  AND timestamp > NOW() - INTERVAL '1 hour'

-- External outbound connections
event_type = 'NET_CONNECT' AND payload->>'direction' = 'OUTBOUND'
  AND (payload->>'is_private')::boolean = false

-- Failed SSH logins
event_type = 'LOGIN_FAILED' AND payload->>'service' = 'sshd'

-- Files written to /etc/
event_type = 'FILE_WRITE' AND payload->>'path' LIKE '/etc/%'

-- Processes running in containers
event_type = 'PROCESS_EXEC' AND payload->'process'->>'container_id' != ''

-- Full-text search across all events
payload::text ILIKE '%mimikatz%'
```

**API:** `POST /api/v1/hunt` with `{"query": "...", "limit": 100}`

---

## Quick start

**Prerequisites:** Docker, Go 1.22+, Python 3.9+, Linux kernel 5.8+ (for agent), clang, libbpf-dev

```bash
# 1. Start backend + PostgreSQL
cd edr-backend
make docker-up
# REST API → http://localhost:8080
# gRPC     → localhost:50051

# 2. Build and run the agent (needs root for eBPF)
cd edr-agent
make all            # check-deps → vmlinux → ebpf → generate → build
sudo ./edr-agent --config config/agent.yaml

# 3. Start the web UI
source venv/bin/activate  # or create one
pip install flask flask-wtf requests psycopg2-binary
python edr-ui/app.py      # → http://localhost:5000
python edr-admin/app.py   # → http://localhost:5001
```

On first run, the backend creates an admin user and prints credentials to the log.

---

## Build commands

### edr-agent
```bash
make check-deps      # verify clang, go, libbpf, etc.
make ebpf            # compile .bpf.c → .bpf.o
make generate        # bpf2go → Go bindings
make build           # go build with version ldflags
make run             # build + sudo run
make test            # go test ./... -v -race
make lint            # golangci-lint
make all             # full rebuild from scratch
./edr-agent --version  # prints version, commit, branch, build time, Go version
```

### edr-backend
```bash
make build           # go build → ./edr-backend
make run             # build + run with config/server.yaml
make test            # go test ./... -v -race
make docker-up       # docker compose up (backend + postgres)
make docker-down     # stop containers
make gen-certs       # generate self-signed TLS certs
```



## Security features

- **JWT authentication** with role-based access control (admin / analyst)
- **CSRF protection** — Flask-WTF CSRFProtect on both UI apps, all forms and AJAX calls
- **API key management** with prefix+hash storage, rotation, expiration, revocation
- **Per-IP rate limiting** — token bucket algorithm (configurable: 20 rps, burst 40 by default)
- **Optional gRPC mTLS** between agent and backend
- **Agent self-protection** — watchdog, anti-tamper, optional immutable binary
- **Network containment** — remote iptables-based host isolation via live response
- **Alert deduplication** — 10-minute sliding window prevents alert storms
- **Incident correlation** — 30-minute sliding window groups related alerts
- **Audit logging** — all user actions tracked
- **Data retention** — configurable auto-purge (events: 90 days default, alerts: configurable via UI)
- **Hunt query safety** — keyword blocklist prevents DDL/DML injection in threat hunting queries

---

## UI tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Dashboard with event counts, alert stats, agent status |
| **Alerts** | Alert triage — filter by status/severity, update assignee/notes, view timeline |
| **Incidents** | Correlated alert groups — severity, alert count, affected hosts, MITRE IDs |
| **Commands** | Captured shell commands and history entries |
| **Events** | Raw event stream with filtering and live SSE updates |
| **Endpoints** | Registered agents with status, version, last seen |
| **Search** | Full-text event search |
| **Hunt** | SQL-like threat hunting query editor with result table |
| **Vulns** | Vulnerability dashboard — severity breakdown + CVE table per agent |
| **Live** | Remote investigation shell — select agent, run commands, view output |
| **Rules** | Detection rule management |
| **Suppression** | Suppression rule management |
| **Rule Builder** | Visual rule builder with condition editor and preview |
| **Settings** | Retention policy, LLM/Ollama configuration |

---

## Configuration

### Backend (`edr-backend/config/server.yaml`)
```yaml
server:
  grpc_addr: ":50051"
  http_addr: ":8080"
  tls:
    enabled: false
    cert_file: "/etc/edr/tls/server.crt"
    key_file:  "/etc/edr/tls/server.key"

database:
  host: "postgres"
  port: 5432
  name: "edr"
  user: "edr"
  password: "edr"

rate_limit:
  enabled: true
  requests_per_second: 20
  burst: 40

retention:
  event_days: 90
  alert_days: 0     # 0 = keep all
```

All settings overridable via `EDR_` environment variables (e.g., `EDR_DATABASE_HOST`, `EDR_RATE_LIMIT_ENABLED`).

### Agent (`edr-agent/config/agent.yaml`)
Supports hot-reload. Configures backend URL, TLS, monitor enable/disable, buffer path.

---

## Agent versioning

The agent embeds full build metadata via ldflags:
```
$ sudo ./edr-agent --version
edr-agent v0.1.0 (commit=abc12345 branch=main built=2026-03-18T14:00:00Z go=go1.22.12 linux/amd64)
```

Version info is included in `AGENT_START` lifecycle events sent to the backend, and in every gRPC registration and event envelope.

---

## Tests

```bash
# Detection engine — 53 test cases
cd edr-backend && go test -v -race ./internal/detection/

# Rate limiter — 5 test cases
cd edr-backend && go test -v -race ./internal/api/

# Process tree E2E test
./scripts/test_process_tree.sh
```

---

## Key environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `EDR_BACKEND` | edr-ui, edr-admin | Backend URL (default: `http://localhost:8080`) |
| `EDR_JWT_SECRET` | edr-backend | JWT signing key (random if unset) |
| `OLLAMA_ENABLED` | edr-backend | Enable LLM alert explanation |
| `OLLAMA_MODEL` | edr-backend | Ollama model name |
| `EDR_DATABASE_*` | edr-backend | PostgreSQL connection overrides |
| `EDR_RATE_LIMIT_ENABLED` | edr-backend | Enable/disable rate limiting |
| `EDR_RATE_LIMIT_REQUESTS_PER_SECOND` | edr-backend | Rate limit RPS |

---

## Roadmap

See [TODO.md](TODO.md) for the full improvement roadmap. Completed items:

- [x] Detection engine unit tests (53 cases)
- [x] Per-IP API rate limiting
- [x] DNS monitoring with DGA/rare-TLD detection rules
- [x] Process tree reconstruction (API + UI)
- [x] Database retention worker (hourly sweep)
- [x] Agent build versioning (commit, branch, build time)
- [x] CSRF protection on both Flask UIs
- [x] Alert correlation / incident grouping (30-min window)
- [x] Live response shell (gRPC bidi stream, 15 commands)
- [x] Network containment (iptables isolation via live response)
- [x] User/login monitoring (auth.log tailing, 3 detection rules)
- [x] File hash enrichment (SHA-256 on file events)
- [x] Vulnerability detection (package inventory + DB schema)
- [x] Container/Kubernetes awareness (cgroup parsing, process enrichment)
- [x] Advanced threat hunting query language (SQL-like, with safety validation)

Next priorities: HTTPS, IOC feed integration, SIEM/webhook export, Prometheus metrics.

---

## Documentation

- [TODO.md](TODO.md) — Full improvement roadmap
- [query-guide.md](query-guide.md) — Threat hunting query language reference
- [comparison.md](comparison.md) — Feature comparison with MDE, CrowdStrike, SentinelOne, Elastic, Wazuh
