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
│  hooks       │                │  18 rules        │            │  Alerts      │
│  SQLite buf  │                │  PostgreSQL      │            │  Events      │
└──────────────┘                └──────────────────┘            │  Process tree│
                                                                 │  Rule builder│
                                        ┌──────────────┐        └──────────────┘
                                        │  edr-admin   │
                                        │  (Flask)     │
                                        │   :5001      │
                                        │  User/key    │
                                        │  management  │
                                        └──────────────┘
```

| Component | Language | Port(s) | Purpose |
|-----------|----------|---------|---------|
| **edr-agent** | Go + eBPF C | — | Endpoint sensor: process, network, file monitoring via eBPF |
| **edr-backend** | Go | :8080 (REST), :50051 (gRPC) | Event ingestion, detection engine, REST API, PostgreSQL storage |
| **edr-ui** | Python/Flask | :5000 | Analyst dashboard with live event stream, process tree, rule builder |
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
- File writes (`vfs_write`) with byte count
- File creation (`vfs_create`) with mode bits
- File deletion (`vfs_unlink`)
- File renames (`vfs_rename`) with old/new paths
- Permission changes via `security_inode_setattr`

### Command monitoring (polling)
- Shell command capture via `/proc` scanning every 2 seconds
- Bash/zsh/sh history tailing for all users
- 38 built-in regex patterns for suspicious command detection
- Tags events with labels like `curl-pipe-shell`, `history-evasion`, `netcat-revshell`

### Self-protection
- Agent watchdog with auto-restart and exponential backoff
- Anti-tamper detection (ptrace on agent PID, binary deletion/modification)
- Optional immutable binary via `chattr +i`

---

## Detection engine

18 built-in rules, two rule types:

**Match rules** — fire when a single event satisfies all conditions.

**Threshold rules** — fire when N events match within a sliding time window, grouped by configurable key (agent, IP, PID, etc.).

### Built-in rules

| Rule | Severity | MITRE ATT&CK |
|------|----------|---------------|
| Web Server Spawning Shell | HIGH | T1059.004 |
| Process Injection via ptrace | HIGH | T1055 |
| Fileless Execution (memfd) | CRITICAL | T1620 |
| sudoers File Modified | CRITICAL | T1548.003 |
| Cron Persistence | HIGH | T1053.003 |
| Outbound High Port | MEDIUM | T1571 |
| LD_PRELOAD Hijack | CRITICAL | T1574.006 |
| Reverse Shell Command | CRITICAL | T1059.004 |
| History Evasion | HIGH | T1070.003 |
| Port Scanner Executed | HIGH | T1046 |
| Credential Dumper | CRITICAL | T1003 |
| Sudo Root Shell Escalation | HIGH | T1548.003 |
| Port Scan Burst (threshold) | HIGH | T1046 |
| Brute Force (threshold) | HIGH | T1110 |
| Beaconing (threshold) | MEDIUM | T1071 |
| Exec Burst (threshold) | MEDIUM | T1059 |
| DGA Domain Detection | HIGH | T1568.002 |
| DNS to Rare TLD | MEDIUM | T1071.004 |

Condition operators: `eq`, `ne`, `gt`, `lt`, `gte`, `lte`, `in`, `startswith`, `contains`, `regex`

Suppression rules filter known-good noise before detection runs.

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

---

## REST API

Base URL: `http://localhost:8080` — all endpoints return JSON. Authenticated via JWT or API key (`Authorization: Bearer <token>`).

### Public
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Basic metrics |
| POST | `/api/v1/setup` | First-user setup |
| POST | `/api/v1/auth/login` | Login → JWT token |
| POST | `/api/v1/auth/refresh` | Refresh JWT |

### Events & Process Tree
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/events` | Query events (filters: agent_id, event_type, q, since, until, pid, hostname, limit, offset) |
| GET | `/api/v1/events/:id` | Single event |
| POST | `/api/v1/events/inject` | Inject test event |
| GET | `/api/v1/events/stream` | SSE live event stream |
| GET | `/api/v1/processes/:pid/tree` | Reconstructed process tree (params: agent_id, depth) |

### Alerts
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/alerts` | Query alerts (filters: status, agent_id, rule_id, min_severity) |
| GET | `/api/v1/alerts/:id` | Single alert |
| PATCH | `/api/v1/alerts/:id` | Update status/assignee/notes |
| GET | `/api/v1/alerts/:id/events` | Events that triggered the alert |
| GET | `/api/v1/alerts/:id/timeline` | Events within time window around alert |
| POST | `/api/v1/alerts/:id/explain` | LLM-powered explanation (requires Ollama) |

### Rules & Suppressions
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/rules` | List all rules |
| POST | `/api/v1/rules` | Create rule |
| PUT | `/api/v1/rules/:id` | Update rule |
| DELETE | `/api/v1/rules/:id` | Delete rule |
| POST | `/api/v1/rules/:id/backtest` | Test rule against historical events |
| POST | `/api/v1/rules/reload` | Force reload rules |
| GET/POST/PUT/DELETE | `/api/v1/suppressions[/:id]` | CRUD suppression rules |

### Agents & Admin
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/agents` | List agents |
| GET/PATCH | `/api/v1/agents/:id` | Get/update agent |
| GET/POST | `/api/v1/settings/retention` | Retention policy |
| POST | `/api/v1/migrate/export` | Export rules/alerts |
| POST | `/api/v1/migrate/import` | Import rules/alerts |
| GET/POST/PATCH/DELETE | `/api/v1/admin/users[/:id]` | User management (admin only) |
| GET/POST/DELETE | `/api/v1/keys[/:id]` | API key management |
| GET | `/api/v1/admin/audit` | Audit log |

---

## Security features

- **JWT authentication** with role-based access control (admin / analyst)
- **API key management** with prefix+hash storage, rotation, expiration, revocation
- **Per-IP rate limiting** — token bucket algorithm (configurable: 20 rps, burst 40 by default)
- **Optional gRPC mTLS** between agent and backend
- **Agent self-protection** — watchdog, anti-tamper, optional immutable binary
- **Alert deduplication** — 10-minute sliding window prevents alert storms
- **Audit logging** — all user actions tracked
- **Data retention** — configurable auto-purge (events: 90 days default, alerts: configurable via UI)

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

## Limitations

- **Agent needs root** — eBPF requires CAP_BPF + CAP_SYS_ADMIN
- **Linux only** — agent uses Linux eBPF; backend and UI run anywhere
- **Single backend** — no HA/clustering yet; agents buffer locally during outages
- **Command monitoring is polling-based** — 2s `/proc` scan interval; very short-lived commands may be missed (history tailing catches most)
- **No Windows support** — registry monitor is a placeholder

---

## Roadmap

See [TODO.md](TODO.md) for the full improvement roadmap. Completed items:

- [x] Detection engine unit tests (53 cases)
- [x] Per-IP API rate limiting
- [x] DNS monitoring with DGA/rare-TLD detection rules
- [x] Process tree reconstruction (API + UI)
- [x] Database retention worker (hourly sweep)
- [x] Agent build versioning (commit, branch, build time)

Next priorities: CSRF protection, HTTPS, alert correlation, threat intel feeds, Prometheus metrics.
