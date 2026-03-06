# TraceGuard — Open Endpoint Detection & Response

A self-hosted EDR system that monitors Linux endpoints, detects suspicious activity, and lets you review and respond to it through a web interface. No SaaS, no vendor lock-in, runs entirely on your own infrastructure.

---

## What it actually is

Three programs that work together:

1. **Agent** — a Go binary you run as root on each machine you want to monitor. It watches process execution, shell commands, file changes, and network connections, then streams events to the backend.

2. **Backend** — a Go server that receives events from agents over gRPC, evaluates them against detection rules, creates alerts when rules fire, and serves a REST API.

3. **Web UI** — a Flask app that proxies requests to the backend and serves the dashboard. The reason it's a separate server rather than a static HTML file is to avoid browser CORS restrictions when calling the backend API.

Everything stores in PostgreSQL. The agent has a local SQLite buffer so events don't get lost if the backend is temporarily unreachable.

---

## What the MVP covers

**Monitoring that actually works today:**

- Process execution — every `execve` call on the system, captured via eBPF. You see the PID, parent PID, full command line, username, and exe path.
- Command activity — real-time monitoring of commands run inside shells (bash/zsh/sh/etc) by polling `/proc` every 2 seconds and matching against parent PIDs. Also tails `~/.bash_history` and `/root/.bash_history` to catch commands that slip through.
- Bash history tailing — follows history files for all users, picks up new lines as they're written, skips timestamps and deduplicates consecutive identical commands.
- Agent heartbeat — the agent pings the backend every 20 seconds. The backend marks an agent offline if it hasn't been heard from in 90 seconds.
- Local buffering — if the backend goes down, the agent keeps writing events to a local SQLite database and replays them when connectivity is restored.
- Fully Modular - backend, db, Webui everything is modular yet fully connected to each other via api, making it resilient.

**Detection:**

Rules are stored in PostgreSQL and loaded into memory. Each rule specifies which event types it applies to and a list of conditions (field / operator / value). All conditions in a rule must match for it to fire. When a rule fires, an alert is created.

The command monitor has 38 hardcoded regex patterns that run client-side in the agent before events even reach the backend. These tag events with labels like `curl-pipe-shell` or `history-evasion` so the backend rules can match on those tags rather than repeating the regex logic.

**What's a stub / not yet real:**

- Network monitor — started but not fully implemented. It registers and runs but doesn't actually capture network connections yet. The plan is fanotify/eBPF for this.
- File monitor — same situation. The structure is there but it doesn't actually watch file changes yet.
- Registry monitor — Linux doesn't have a registry. This exists as a placeholder for when/if Windows support is added.

---

## How it's built

**Agent** (`edr-agent`, Go)
- Uses eBPF (via cilium/ebpf) to hook `execve`, `fork`, `clone`, and `ptrace` syscalls
- Requires Linux kernel 5.8+ and root/CAP_BPF privileges
- Events go through an internal bus — monitors publish, the transport and local buffer both subscribe
- gRPC streaming connection to backend (port 50051 by default)
- Config file at `config/agent.yaml`, or runs with insecure defaults if no config is provided

**Backend** (`edr-backend`, Go)
- gRPC server on port 50051 receives event streams from agents
- REST API on port 8080
- Detection engine runs in-memory, re-evaluating rules on every incoming event
- PostgreSQL for persistent storage of agents, events, alerts, and rules
- Runs in Docker by default (`make docker-up`)

**Web UI** (`edr-ui`, Python/Flask)
- Serves on port 5000
- All API calls go through Flask routes to avoid CORS issues
- Single-page app, no framework, vanilla JS
- Auto-refreshes data every 30 seconds

---

## Running it

**Prerequisites:** Docker, Go 1.21+, Python 3.9+, Linux kernel 5.8+ (for the agent)

```bash
# 1. Extract all three components
python3 setup_edr_backend.py
python3 setup_edr_agent.py
python3 setup_edr_ui.py

# 2. Start backend + PostgreSQL
cd edr-backend
make docker-up
# Backend REST API → http://localhost:8080
# gRPC ingest     → localhost:50051

# 3. Build and run the agent (needs root for eBPF)
cd edr-agent
make all
sudo ./edr-agent
# With a config file: sudo ./edr-agent --config config/agent.yaml

# 4. Start the web UI
cd edr-ui
pip install flask requests
python app.py
# Dashboard → http://localhost:5000
```

The backend uses a config file at `config/backend.yaml`. The default PostgreSQL credentials are `edr:edr@localhost/edr`.

---

## REST API

Base URL: `http://localhost:8080`

All endpoints return JSON. Errors return `{"error": "message"}`.

---

### Health

```
GET /health
```
Returns `{"status":"ok"}` plus uptime and version. Use this to check if the backend is running.

---

### Dashboard

```
GET /api/v1/dashboard
```
Returns a summary for the overview page: online/total agent counts, events in last 24h, open alert count, alert breakdown by severity, and recent alerts.

---

### Agents

```
GET /api/v1/agents
```
Returns all registered agents with their online status, OS, IP, version, and first/last seen timestamps.

```
GET /api/v1/agents/:id
```
Returns a single agent by ID.

Agents are created automatically when an agent binary connects and registers itself. There's no manual registration step.

---

### Events

```
GET /api/v1/events
```

Query parameters:

| Parameter    | Type   | Description                                          |
|-------------|--------|------------------------------------------------------|
| `event_type` | string | Filter by type: `PROCESS_EXEC`, `CMD_EXEC`, `CMD_HISTORY`, `NET_CONNECT`, `FILE_WRITE`, etc. |
| `agent_id`   | string | Filter to one specific agent                         |
| `q`          | string | Text search across event payload                     |
| `since`      | string | ISO 8601 timestamp — only events after this time     |
| `until`      | string | ISO 8601 timestamp — only events before this time    |
| `limit`      | int    | Max results, default 50                              |
| `offset`     | int    | Pagination offset, default 0                         |

```
GET /api/v1/events/:id
```
Returns a single event by ID. The `payload` field is a JSON object whose shape depends on the event type.

---

### Alerts

```
GET /api/v1/alerts
```

Query parameters:

| Parameter      | Type   | Description                                      |
|---------------|--------|--------------------------------------------------|
| `status`       | string | `OPEN`, `INVESTIGATING`, or `RESOLVED`           |
| `agent_id`     | string | Filter to one agent                              |
| `rule_id`      | string | Filter to alerts from one specific rule          |
| `min_severity` | int    | Only alerts at or above this severity (1–4)      |
| `limit`        | int    | Default 50                                       |
| `offset`       | int    | Pagination offset                                |

```
GET /api/v1/alerts/:id
```
Returns a single alert.

```
PATCH /api/v1/alerts/:id
```
Updates an alert. All fields are optional.

Request body:
```json
{
  "status":   "INVESTIGATING",
  "assignee": "alice",
  "notes":    "Confirmed false positive — internal scanner"
}
```

Valid status values: `OPEN`, `INVESTIGATING`, `RESOLVED`

---

### Detection Rules

```
GET /api/v1/rules
```
Returns all rules including enabled/disabled state, severity, event types they apply to, conditions, and MITRE ATT&CK IDs.

```
GET /api/v1/rules/:id
```
Returns a single rule.

```
POST /api/v1/rules
```
Creates a new rule. The detection engine reloads automatically.

Request body:
```json
{
  "name": "Netcat Reverse Shell",
  "description": "nc used with -e flag to spawn a shell",
  "enabled": true,
  "severity": 4,
  "event_types": ["CMD_EXEC", "CMD_HISTORY"],
  "conditions": [
    { "field": "tags", "op": "contains", "value": "netcat-revshell" }
  ],
  "mitre_ids": ["T1059.004"],
  "author": "your-name"
}
```

```
PUT /api/v1/rules/:id
```
Replaces a rule. Same body as POST. Only the fields you send are updated — omitted fields keep their existing values.

```
DELETE /api/v1/rules/:id
```
Deletes a rule permanently. The detection engine reloads automatically.

```
POST /api/v1/rules/reload
```
Force-reloads the detection engine from the database. Normally you don't need this — create/update/delete all trigger it automatically.

---

## Rule conditions

Each condition is an object with three fields:

```json
{ "field": "cmdline", "op": "contains", "value": "passwd" }
```

Available operators: `eq`, `ne`, `contains`, `startswith`, `regex`, `gt`, `lt`, `gte`, `lte`, `in`

Fields you can match on depend on the event type. Common ones:

| Field | Available on | Example value |
|-------|-------------|---------------|
| `cmdline` | CMD_EXEC, CMD_HISTORY | `/bin/bash -i >& /dev/tcp/...` |
| `username` | CMD_EXEC, CMD_HISTORY | `root` |
| `shell_name` | CMD_EXEC | `bash` |
| `tags` | CMD_EXEC, CMD_HISTORY | `curl-pipe-shell` |
| `detection` | CMD_EXEC, CMD_HISTORY | free text from pattern match |
| `source` | CMD_EXEC, CMD_HISTORY | `proc` or `history:.bash_history` |
| `process.comm` | PROCESS_EXEC | `nginx` |
| `process.exe_path` | PROCESS_EXEC | `/usr/bin/python3` |
| `path` | FILE_WRITE, FILE_CREATE | `/etc/sudoers` |
| `dst_port` | NET_CONNECT | `4444` |
| `hostname` | all | `webserver-01` |
| `severity` | CMD_EXEC, CMD_HISTORY | `3` (numeric) |

All rules require all conditions to match (AND logic). There's no OR at the condition level — if you need OR, create two separate rules.

---

## Severity levels

| Level | Meaning |
|-------|---------|
| 0 / INFO | Pure telemetry, no detection |
| 1 / LOW | Worth logging, unlikely to need immediate action |
| 2 / MEDIUM | Investigate when time allows |
| 3 / HIGH | Should be reviewed today |
| 4 / CRITICAL | Drop what you're doing |

---

## Default detection rules

These are seeded into the database on first run:

| Rule | Severity | Triggers on |
|------|----------|------------|
| Web Server Spawning Shell | HIGH | nginx/apache/php spawning bash/python/perl |
| Process Injection via ptrace | HIGH | ptrace ATTACH or POKETEXT |
| Fileless Execution (memfd) | CRITICAL | binary executed from memfd |
| sudoers File Modified | CRITICAL | write to /etc/sudoers |
| Cron Persistence Established | HIGH | file created in /etc/cron* or /var/spool/cron |
| Unusual Outbound on High Port | MEDIUM | outbound connection to non-private IP on port >49151 |
| LD_PRELOAD Hijack Attempt | CRITICAL | write to /etc/ld.so.preload |
| Reverse Shell Command | CRITICAL | CMD event tagged with revshell patterns |
| History Evasion | HIGH | `history -c`, `unset HISTFILE`, `HISTSIZE=0` |
| Port Scanner Executed | HIGH | nmap/masscan/zmap/rustscan in terminal |
| Credential Dumper Executed | CRITICAL | mimikatz/lazagne/secretsdump in terminal |
| Sudo Root Shell Escalation | HIGH | `sudo -i`, `sudo su`, `sudo bash` |

---

## Limitations worth knowing

- **The agent needs root.** eBPF requires it. There's no way around this.
- **Linux only.** The agent uses Linux-specific syscalls and eBPF. The backend and UI run anywhere.
- **No authentication on the API.** There's an API key field in the config but it's not enforced on all routes yet. Don't expose port 8080 to the internet.
- **No encryption between agent and backend in dev mode.** The default config disables TLS so the agent connects without a cert. For production you need to set up certs and flip `insecure: false` in the agent config.
- **Command monitoring is polling-based.** The `/proc` scan runs every 2 seconds, so very short-lived commands might be missed. Bash history tailing catches most of these, but there's a theoretical gap.
- **No Windows support.** The file and registry monitors are stubs that exist in anticipation of a Windows port, but nothing there works yet.
- **Single backend only.** There's no clustering or HA. If the backend goes down, agents buffer events locally and replay when it comes back up.