# TraceGuard — Open EDR/XDR Platform

A self-hosted EDR/XDR platform for Linux and Windows. Monitors endpoints with eBPF (Linux) and ETW (Windows), detects threats in real time, correlates alerts into incidents, provides deception via canary tokens, detects data exfiltration, and exposes a Next.js analyst dashboard. No SaaS, no vendor lock-in — runs entirely on your infrastructure.

---

## Architecture

```
Endpoints                          Backend                         Analysts
┌──────────────┐                ┌──────────────────┐            ┌───────────────────┐
│  edr-agent   │  gRPC stream   │   edr-backend    │  REST API  │   edr-ui-new      │
│  (Go + eBPF) │───────────────>│   (Go + Gin)     │<──────────>│  (Next.js 16)     │
│              │    :50051       │                  │   :8080    │   :5002           │
│  17 monitors │                │  Detection engine│            │  50+ pages        │
│  SQLite buf  │  Live Response │  Incidents       │            │  XDR dashboard    │
│  Containment │<──────────────>│  PostgreSQL      │            └───────────────────┘
└──────────────┘   bidi gRPC    └──────────────────┘
                                        │                        ┌───────────────────┐
┌──────────────┐                        │  REST API              │   edr-ui (legacy) │
│ edr-agent-win│  gRPC stream           └───────────────────────>│  (Flask)  :5000   │
│  (Go + ETW)  │───────────────────────────────────────────────> │   edr-admin       │
│  18 monitors │                                                  │  (Flask)  :5001   │
└──────────────┘                                                  └───────────────────┘
```

| Component | Language | Port(s) | Purpose |
|-----------|----------|---------|---------|
| **edr-agent** | Go 1.21 + eBPF C | — (browser receiver :9999) | Linux endpoint sensor: 17 monitors via eBPF/procfs; live response; network containment; scheduled task executor |
| **edr-agent-win** | Go 1.25 + ETW | — (browser receiver :9999) | Windows endpoint sensor: 18 monitors via ETW/Win32 API; scheduled task executor (PowerShell) |
| **edr-backend** | Go 1.23 + Gin | :8080 (REST), :50051 (gRPC) | Event ingestion, detection engine, incident correlation, IOC matching, SOAR playbooks, XDR sources, DNS intelligence, canary tokens, DLP/exfil detection, scheduled tasks, PostgreSQL storage |
| **edr-ui-new** | Next.js 16 + React 19 | :5002 | Primary analyst dashboard — 50+ pages covering all EDR/XDR features |
| **edr-ui** | Python/Flask | :5000 | Legacy analyst dashboard (maintained but not where new UI work goes) |
| **edr-admin** | Python/Flask | :5001 | Admin portal for user management, API keys, audit log |
| **extensions/chrome** | JavaScript MV3 | — | Browser monitor (posts to agent :9999) |
| **extensions/firefox** | JavaScript WebExtensions | — | Browser monitor (posts to agent :9999) |

---

## What it monitors

### Linux agent monitors (17)

| Monitor | Events emitted | Method |
|---------|---------------|--------|
| Process | PROCESS_EXEC, PROCESS_EXIT, PROCESS_FORK, PROCESS_PTRACE | eBPF tracepoints |
| Network | NET_CONNECT, NET_ACCEPT, NET_CLOSE, NET_DNS, NET_TLS_SNI | eBPF kprobes + raw socket |
| File | FILE_CREATE, FILE_WRITE, FILE_DELETE, FILE_RENAME, FILE_EXEC, FILE_CHMOD | eBPF kprobes |
| Auth | LOGIN_SUCCESS, LOGIN_FAILED, SUDO_EXEC | auth.log tailing |
| Command | CMD_EXEC, CMD_HISTORY | /proc polling + history tailing |
| Registry (critical configs) | REG_SET, REG_DELETE | inotify on /etc |
| Vulnerability | PKG_INVENTORY | dpkg/rpm polling |
| Browser | BROWSER_REQUEST | HTTP receiver :9999 |
| Kernel module | KERNEL_MODULE_LOAD, KERNEL_MODULE_UNLOAD | /proc/modules polling |
| USB | USB_CONNECT, USB_DISCONNECT | /sys/bus/usb polling |
| Memory injection | MEMORY_INJECT | /proc/*/maps polling |
| Cron | CRON_MODIFY | file event subscription |
| Named pipe | PIPE_CREATE | directory polling |
| Network share | SHARE_MOUNT, SHARE_UNMOUNT | /proc/mounts polling |
| TLS SNI | NET_TLS_SNI | AF_INET raw socket |
| YARA scan | (via scan task) | scheduled task executor |
| Agent lifecycle | AGENT_START, AGENT_STOP, AGENT_TAMPER, AGENT_HEARTBEAT | internal |

### Windows agent monitors (18)

| Monitor | Events emitted | Method |
|---------|---------------|--------|
| Process | PROCESS_EXEC, PROCESS_EXIT, EventCmdExec | ETW Kernel-Process |
| Network | NET_CONNECT, NET_ACCEPT, NET_CLOSE | ETW Kernel-Network |
| File | FILE_CREATE, FILE_WRITE, FILE_DELETE, FILE_RENAME | ETW Kernel-File |
| File integrity (FIM) | FILE_WRITE | ReadDirectoryChangesW |
| DNS | NET_DNS | ETW DNS-Client |
| Auth | LOGIN_SUCCESS, LOGIN_FAILED, WinEventLogEvent | Security Event Log |
| Command | EventCmdExec | PowerShell + cmd ETW |
| Registry | EventRegistrySet, EventRegistryDelete | ETW Kernel-Registry |
| Vulnerability | PKG_INVENTORY | winget/WMI |
| Browser | BROWSER_REQUEST | HTTP receiver :9999 |
| Driver | KERNEL_MODULE_LOAD, KERNEL_MODULE_UNLOAD | EnumDeviceDrivers |
| USB | USB_CONNECT, USB_DISCONNECT | WMI |
| Memory injection | MEMORY_INJECT | VirtualQueryEx |
| Scheduled task | (task monitor) | Task Scheduler COM |
| Named pipe | PIPE_CREATE | \\.\pipe\ enumeration |
| Network share | SHARE_MOUNT | NetShareEnum |
| Windows Event Log | WinEventLogEvent | WMI/ETW |
| Agent lifecycle | AGENT_START, AGENT_STOP, AGENT_HEARTBEAT | internal |

---

## Incident correlation

Alerts are automatically grouped into **incidents** using a 30-minute sliding correlation window per agent. When a new alert fires:

1. Backend checks for an existing OPEN/INVESTIGATING incident on the same agent within the last 30 minutes
2. If found — alert is appended (severity escalated, MITRE IDs merged, alert count incremented)
3. If not found — a new incident is created

Incidents aggregate severity, alert count, affected hosts, and MITRE ATT&CK techniques across all correlated alerts. Each incident has its own lifecycle: OPEN → INVESTIGATING → CLOSED.

---

## Scheduled tasks (heartbeat delivery)

The backend can schedule tasks to run on remote agents. Tasks are delivered via the heartbeat mechanism:

1. A task is created via `POST /api/v1/agents/:id/tasks` (or triggered on-demand via the `/run` endpoint)
2. On each agent heartbeat, the backend claims any due tasks and returns them in `HeartbeatResponse.pending_tasks[]`
3. The agent's `tasks.Executor` dispatches each task in its own goroutine
4. Results are collected and sent back in the next `HeartbeatRequest.task_results[]`

**Task types:**
| Type | Linux | Windows | Description |
|------|-------|---------|-------------|
| `script` | bash -c | powershell.exe | Run an arbitrary shell command. Payload: `{"cmd": "..."}` |
| `collect` | uname/uptime/df/free | PowerShell CIM queries | Gather system information snapshot |
| `scan` | find + newer | Get-ChildItem by date | File integrity spot-check. Payload: `{"path": "/etc", "maxdepth": 2}` |
| `remediate` | kill -TERM | taskkill /F /T | Terminate a process by PID. Payload: `{"pid": 1234}` |

Output is capped at 64 KB combined stdout+stderr. Script timeout is 5 minutes; collect/scan timeout is 30 seconds.

---

## XDR features

### DNS Intelligence
Queries and aggregates DNS events (`NET_DNS`) from all agents. Backend exposes `GET /api/v1/dns/events` and `GET /api/v1/dns/stats` (top 50 domains by query count over a configurable time window, max 168 hours).

### Canary Tokens
Deception tokens that generate a critical alert when accessed. Four types: `credential`, `file`, `url`, `dns`. The trigger webhook (`POST /api/canary/trigger/:token`) is unauthenticated — the canary callback URL contains only the token. Triggers create an alert with severity 5, rule ID `rule-canary-trigger`, and MITRE IDs T1078 + T1555.

### Data Exfiltration Detection (DLP)
The `internal/exfil/detector.go` background detector watches for:
- USB bulk transfer > 50 MB
- Outbound network transfer > 100 MB
- Cloud upload > 25 MB

Detection results are stored in `exfil_signals` table. Backend exposes `GET /api/v1/dlp/events` and `GET /api/v1/dlp/stats`.

### SOAR Playbooks
Automated response rules that fire on alerts. Actions: Slack notify, PagerDuty page, email, isolate host, block IP, disable identity. Five seeded playbooks ship by default.

### XDR Sources & Identity Graph
Ingest from cloud, network, and identity sources in addition to endpoints. Events are normalized to OCSF. Identity graph tracks cross-source user identities with risk scoring. Impossible-travel and cross-source lateral movement rules are included.

---

## Live response

Remote investigation and remediation shell over gRPC bidirectional streaming.

### Available commands

| Command | Description |
|---------|-------------|
| `ps` | List running processes |
| `ls` | List files/directories |
| `cat` | Read file contents |
| `netstat` | Show network connections (via ss) |
| `who` | Show logged-in users |
| `uname` | System information |
| `uptime` | System uptime |
| `df` | Disk usage |
| `id` | User identity |
| `exec` | Run arbitrary command |
| `find` | Search for files |
| `sha256sum` | Hash a file |
| `kill` | Kill a process |
| `isolate` | Network containment — block all traffic except backend |
| `release` | Release containment — restore normal networking |

Dangerous patterns (`rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`) are blocked. Output is capped at 1 MB stdout / 64 KB stderr.

---

## Threat hunting

SQL-like query language for searching across all raw telemetry. See [query-guide.md](query-guide.md) for the full reference.

**API:** `POST /api/v1/hunt` with `{"query": "...", "limit": 100}`

---

## Quick start

**Prerequisites:** Docker, Go 1.22+, Python 3.9+, Node.js 18+, Linux kernel 5.8+ (for Linux agent)

```bash
# 1. Start backend + PostgreSQL
cd edr-backend
make docker-up
# REST API → http://localhost:8080
# gRPC     → localhost:50051

# 2. Build and run the Linux agent (needs root for eBPF)
cd edr-agent
go build -o edr-agent ./cmd/agent
sudo ./edr-agent --config config/agent.yaml

# 3. Start the primary dashboard
cd edr-ui-new
npm install
npm run dev   # → http://localhost:5002

# Optional: legacy Flask UIs
pip install flask flask-wtf requests psycopg2-binary
python edr-ui/app.py      # → http://localhost:5000
python edr-admin/app.py   # → http://localhost:5001
```

On first run, the backend creates an admin user and prints credentials to the log. When `EDR_AUTH_BOOTSTRAP_FILE` is set (the default in `edr-backend/deploy/docker-compose.yml` writes to `/app/bootstrap/cred.txt` → host `edr-backend/deploy/bootstrap/cred.txt`), the same `username=` / `password=` pair is also written to that path with mode `0600`. Save the password and delete the file.

---

## Build commands

### edr-agent (Linux)
```bash
cd edr-agent
make check-deps      # verify clang, go, libbpf, etc.
make ebpf            # compile .bpf.c → .bpf.o
make generate        # bpf2go → Go bindings
make build           # go build with version ldflags
make all             # full rebuild from scratch
make test            # go test ./... -v -race
```
eBPF compiled objects (`*_bpfel.go`) are committed; plain `go build` works without clang.

### edr-agent-win (Windows — cross-compile from Linux)
```bash
cd edr-agent-win
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o edr-agent.exe ./cmd/agent/
```
Uses `modernc.org/sqlite` (pure Go), so CGO is not required. See `edr-agent-win/docs/BUILD.md`.

### edr-backend
```bash
cd edr-backend
make build           # go build → ./edr-backend
make run             # build + run with config/server.yaml
make test            # go test ./... -v -race
make docker-up       # docker compose up (backend + postgres)
make gen-certs       # generate self-signed TLS certs
```

### edr-ui-new
```bash
cd edr-ui-new
npm install
npm run dev          # :5002, hot reload
npm run build && npm start -- -p 5002 -H 0.0.0.0
npm run lint
```

---

## Security features

- **JWT authentication** with role-based access control (admin / analyst)
- **TOTP / MFA** — per-user TOTP with backup codes (admin-managed)
- **CSRF protection** — Flask-WTF CSRFProtect on both Flask UIs
- **API key management** with prefix+hash storage, rotation, expiration, revocation, per-key role
- **Per-IP rate limiting** — token bucket algorithm (20 rps, burst 40 by default)
- **Per-tenant rate-limit overrides** — configurable in `tenant_rate_limits` table
- **Optional gRPC mTLS** between agent and backend
- **Agent self-protection** — watchdog, anti-tamper, optional immutable binary
- **Network containment** — remote iptables-based host isolation via live response
- **Alert deduplication** — 10-minute sliding window prevents alert storms
- **Incident correlation** — 30-minute sliding window groups related alerts
- **Audit logging** — all user actions tracked in `audit_log`
- **Hunt query safety** — keyword blocklist prevents DDL/DML injection
- **Multi-tenancy** — tenant_id isolation on all major tables

---

## Dashboard pages (edr-ui-new)

### Core
Dashboard, Alerts, Incidents, Cases, Agents

### Investigate
Events, Commands, Browser Activity, USB Devices, Email Threats, Hunt, Search

### Detect
Rules, YARA Rules, Suppressions, IOCs, IOC Feeds, DNS Intelligence, Vulnerabilities, MITRE Heatmap

### XDR
Sources, Network Events, Cloud Events, Identity Events, User Risk, Host Risk, UEBA Timeline, Asset Inventory, Containers, Data Exfiltration

### Operate
Live Response, Playbooks, Playbook Runs, Auto-Remediation, Compliance, Canary Tokens, Scheduled Tasks, Auto-Case Policies, Response Actions, Export / SIEM, Reports, Metrics, Settings

---

## Configuration

### Backend (`edr-backend/config/server.yaml`)
```yaml
server:
  grpc_addr: ":50051"
  http_addr: ":8080"
  tls:
    enabled: false

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
```

All settings overridable via `EDR_` environment variables (e.g., `EDR_DATABASE_HOST`, `EDR_RATE_LIMIT_ENABLED`).

---

## Tests

```bash
# Detection engine
cd edr-backend && go test -v -race ./internal/detection/

# Rate limiter
cd edr-backend && go test -v -race ./internal/api/

# Process tree E2E
./scripts/test_process_tree.sh

# All rules E2E (requires running backend)
EDR_TOKEN=... ./scripts/test-all-rules.sh
```

---

## Key environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `EDR_BACKEND` | edr-ui, edr-admin | Backend URL (default: `http://localhost:8080`) |
| `NEXT_PUBLIC_BACKEND_URL` | edr-ui-new | Backend URL for Next.js dashboard |
| `EDR_JWT_SECRET` | edr-backend | JWT signing key (random if unset) |
| `OLLAMA_ENABLED` | edr-backend | Enable LLM alert explanation |
| `OLLAMA_MODEL` | edr-backend | Ollama model name |
| `EDR_DATABASE_*` | edr-backend | PostgreSQL connection overrides |
| `EDR_RATE_LIMIT_ENABLED` | edr-backend | Enable/disable rate limiting |

---

## Documentation

- [query-guide.md](query-guide.md) — Threat hunting query language reference
- [docs/agent.md](docs/agent.md) — Linux agent deep-dive
- [docs/backend.md](docs/backend.md) — Backend architecture and API
- [docs/dashboard.md](docs/dashboard.md) — edr-ui-new pages and design system
- [docs/api-reference.md](docs/api-reference.md) — Full REST API reference
- [docs/windows.md](docs/windows.md) — Windows agent documentation
