# TraceGuard Backend Documentation

## Overview

The TraceGuard Backend (`edr-backend`) is the central server component of the Open EDR platform. It ingests telemetry from agents via gRPC, stores events and alerts in PostgreSQL, runs a real-time detection engine against incoming events, and exposes a REST API for the analyst UI and admin portal.

The backend is written in Go, uses the Gin web framework for REST, and supports JWT + API key authentication, SSE live event streaming, LLM-powered alert explanation, live response (remote command execution), IOC threat intelligence feeds, and automated data retention.

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Go | 1.22+ | For building the backend binary |
| PostgreSQL | 14+ | Event and alert storage |
| Docker + Docker Compose | (optional) | For containerized deployment |

## Build Instructions

```bash
cd edr-backend

# Build the backend binary
make build        # go build -> ./edr-backend

# Build and run with config/server.yaml
make run

# Docker Compose (backend + PostgreSQL)
make docker-up    # docker compose up
make docker-down

# Generate self-signed TLS certificates
make gen-certs    # outputs to deploy/certs/

# Run tests
make test         # go test ./... -v -race -count=1
```

## Configuration

Configuration is loaded from `config/server.yaml`. Environment variables with the `EDR_` prefix override YAML keys (e.g., `EDR_DATABASE_HOST`). Viper is used for config loading.

### `server` -- Server addresses and TLS

| Key | Type | Default | Description |
|---|---|---|---|
| `server.grpc_addr` | string | `:50051` | gRPC ingest server listen address. |
| `server.http_addr` | string | `:8080` | REST API listen address. |
| `server.tls.enabled` | bool | `false` | Enable TLS on the gRPC server. |
| `server.tls.cert_file` | string | `/etc/edr/tls/server.crt` | Server TLS certificate path. |
| `server.tls.key_file` | string | `/etc/edr/tls/server.key` | Server TLS private key path. |
| `server.tls.ca_file` | string | `""` | CA certificate for mutual TLS (client cert required when set). |

### `database` -- PostgreSQL connection

| Key | Type | Default | Description |
|---|---|---|---|
| `database.host` | string | `postgres` | PostgreSQL host. |
| `database.port` | int | `5432` | PostgreSQL port. |
| `database.name` | string | `edr` | Database name. |
| `database.user` | string | `edr` | Database user. |
| `database.password` | string | `edr` | Database password. |
| `database.ssl_mode` | string | `disable` | PostgreSQL SSL mode. |

### `log` -- Logging

| Key | Type | Default | Description |
|---|---|---|---|
| `log.level` | string | `info` | Log level: `debug`, `info`, `warn`, `error`. |
| `log.format` | string | `json` | Log format: `json` or `text`. |

### `auth` -- Authentication

| Key | Type | Default | Description |
|---|---|---|---|
| `auth.api_key` | string | `""` | Legacy single API key fallback. |

JWT signing key is set via `EDR_JWT_SECRET` environment variable. If unset, a random ephemeral key is generated on startup.

### `rate_limit` -- Per-IP rate limiting

| Key | Type | Default | Description |
|---|---|---|---|
| `rate_limit.enabled` | bool | `true` | Enable per-IP token bucket rate limiting. |
| `rate_limit.requests_per_second` | float | `20` | Sustained request rate per IP. |
| `rate_limit.burst` | int | `40` | Maximum burst size per IP. |

### `ioc_feed` -- Threat intelligence feeds

| Key | Type | Default | Description |
|---|---|---|---|
| `ioc_feed.enabled` | bool | `true` | Enable automatic IOC feed synchronization. |
| `ioc_feed.sync_interval` | string | `6h` | How often to refresh feeds (minimum 1m). |

Feeds include: Abuse.ch Feodo Tracker (C2 IPs), URLhaus (malicious domains), MalwareBazaar (malware hashes), Emerging Threats (compromised IPs).

### `retention` -- Data retention

| Key | Type | Default | Description |
|---|---|---|---|
| `retention.event_days` | int | `90` | Delete events older than N days (0 = keep all). |
| `retention.alert_days` | int | `0` | Delete closed alerts older than N days (0 = keep all). |

## Database Schema

The backend auto-applies schema migrations at startup via `RunMigrations()`. Each migration is idempotent (IF NOT EXISTS). A `schema_migrations` table tracks which migrations have been applied.

### Tables

| Table | Description |
|---|---|
| `agents` | Registered endpoint agents. Columns: id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen, is_online, config_ver, tags, env, notes. |
| `events` | All telemetry events. Columns: id, agent_id (FK), hostname, event_type, timestamp, payload (JSONB), received_at, severity, rule_id, alert_id. Indexed on agent_id, event_type, timestamp (DESC), and payload (GIN). |
| `alerts` | Detection alerts. Columns: id, title, description, severity, status, rule_id, rule_name, mitre_ids, event_ids, agent_id (FK), hostname, first_seen, last_seen, assignee, notes, hit_count, incident_id. |
| `rules` | Detection rules. Columns: id, name, description, enabled, severity, event_types, conditions (JSONB), mitre_ids, created_at, updated_at, author, rule_type, threshold_count, threshold_window_s, group_by. |
| `suppression_rules` | Rules to suppress false-positive events. Columns: id, name, description, enabled, event_types, conditions (JSONB), created_at, updated_at, author, hit_count, last_hit_at. |
| `incidents` | Groups of related alerts. Columns: id, title, description, severity, status, alert_ids, agent_ids, hostnames, mitre_ids, alert_count, first_seen, last_seen, assignee, notes, created_at, updated_at. |
| `iocs` | Indicators of Compromise. Columns: id, type, value, source, severity, description, tags, enabled, expires_at, created_at, hit_count, last_hit_at. Unique index on (type, value). |
| `users` | User accounts. Columns: id, username, email, password_hash, role, enabled, created_at, last_login_at, created_by. |
| `api_keys` | API keys for programmatic access. Columns: id, name, prefix, hash, created_at, expires_at, last_used_at, created_by, enabled. |
| `audit_log` | Administrative action log. Columns: id (BIGSERIAL), timestamp, actor_id, actor_name, action, target_type, target_id, target_name, ip, details. |
| `settings` | Key-value configuration store. Columns: key, value, updated_at. Seeded with `retention_events_days=30`, `retention_alerts_days=90`. |
| `agent_packages` | Installed packages per agent. Columns: id (BIGSERIAL), agent_id (FK), name, version, arch, collected_at. |
| `vulnerabilities` | Known CVEs matched against agent packages. Columns: id (BIGSERIAL), agent_id (FK), package_name, package_version, cve_id, severity, description, fixed_version, detected_at. |
| `schema_migrations` | Tracks applied migrations. Columns: name, applied_at. |

## gRPC Ingest Server

The ingest server (`internal/ingest/server.go`) implements the `EventService` defined in `proto/edr.proto`. It listens on `:50051` by default.

### RPCs

#### `Register(RegisterRequest) -> RegisterResponse`

Called once when an agent starts. Creates or updates the agent record in PostgreSQL.

- **Request:** agent_id, hostname, os, os_version, agent_ver, ip, tags, env, notes
- **Response:** ok, assigned_id, config_version

#### `StreamEvents(stream EventEnvelope) -> StreamResponse`

Client-streaming RPC. The agent continuously sends `EventEnvelope` messages. Each envelope contains:

- agent_id, hostname, event_id, event_type, timestamp (Unix nanoseconds), payload (JSON bytes), os, agent_ver

The server processes each event asynchronously:
1. Validates the JSON payload
2. Generates an event ID if missing
3. Stores the event in PostgreSQL
4. Publishes to the SSE broker for live UI updates
5. Runs the detection engine against the event

When the stream closes, the agent is marked offline.

#### `Heartbeat(HeartbeatRequest) -> HeartbeatResponse`

Unary RPC called every 30 seconds. Updates the agent's `last_seen` timestamp.

- **Request:** agent_id, hostname, timestamp, agent_ver, os, stats (events_sent, events_dropped, buffer_size, cpu_pct, mem_bytes)
- **Response:** ok, server_time (Unix nanoseconds for clock sync), config_version

#### `LiveResponse(stream)` -- Bidirectional

Bidirectional streaming RPC for remote command execution. The agent connects, registers with its agent_id, then listens for commands and sends results back.

### gRPC Server Configuration

- Max receive message size: 8 MB
- Max send message size: 1 MB
- Keepalive: max idle 5 min, max connection age 2 hours, ping every 30s, timeout 10s
- TLS: Supports server-only TLS and mutual TLS (when `ca_file` is set)
- Minimum TLS version: 1.3

## Detection Engine

The detection engine (`internal/detection/engine.go`) evaluates rules against every incoming event in real time. It supports two rule types:

### Match Rules

Fire immediately when a single event satisfies all conditions. Conditions are evaluated against a flattened map of the event payload.

**Supported operators:**
- `eq` -- equals
- `in` -- value is in a list
- `startswith` -- string prefix match
- `regex` -- regular expression match (cached)
- `gt`, `lt` -- numeric comparison
- `contains` -- array contains value
- `length_gte` -- array length >= value

### Threshold Rules

Fire when N matching events occur within a sliding time window, grouped by a configurable key.

- Uses in-memory sliding windows per (rule_id, group_key)
- Windows are pruned lazily on each event and periodically (every 5 minutes)
- When the threshold is reached, the window is reset to prevent firing on every subsequent event
- Group-by keys can be any event field: `agent_id`, `dst_ip`, `process.pid`, `source_ip`, `domain`, etc.

### IOC Matching

The engine maintains in-memory caches of IOCs (IPs, domains, SHA256/MD5 hashes) loaded from the database every 60 seconds. Every incoming event is checked against these caches for O(1) lookup performance.

### Suppression Rules

Before evaluating detection rules, each event is checked against suppression rules. If a suppression matches, the event is skipped entirely (no alert is generated). Suppression rules track hit counts and last-hit timestamps.

### Alert Generation

When a rule fires, an alert is created with:
- Title and description from the rule
- Severity from the rule
- MITRE ATT&CK IDs from the rule
- Associated event IDs
- Agent and hostname from the event
- Status: `OPEN`
- Hit count (incremented on dedup)

Alerts are deduplicated -- if an existing open alert exists for the same rule and agent, its `last_seen` and `hit_count` are updated rather than creating a new alert.

## Seeded Detection Rules

The backend ships with the following built-in detection rules, automatically seeded on first migration:

### Match Rules

| ID | Name | Severity | Event Types | MITRE |
|---|---|---|---|---|
| `rule-suspicious-shell` | Web Server Spawning Shell | HIGH | PROCESS_EXEC | T1059.004, T1190 |
| `rule-ptrace-injection` | Process Injection via ptrace | HIGH | PROCESS_PTRACE | T1055.008 |
| `rule-memfd-exec` | Fileless Execution (memfd) | CRITICAL | PROCESS_EXEC | T1620 |
| `rule-sudoers-write` | sudoers File Modified | CRITICAL | FILE_WRITE, FILE_CREATE | T1548.003 |
| `rule-cron-write` | Cron Persistence Established | HIGH | FILE_WRITE, FILE_CREATE | T1053.003 |
| `rule-outbound-high-port` | Unusual Outbound Connection on High Port | MEDIUM | NET_CONNECT | T1071 |
| `rule-ld-preload-write` | LD_PRELOAD Hijack Attempt | CRITICAL | FILE_WRITE, FILE_CREATE | T1574.006 |
| `rule-cmd-revshell` | Reverse Shell Command Detected | CRITICAL | CMD_EXEC, CMD_HISTORY | T1059.004 |
| `rule-cmd-history-evasion` | History Evasion Detected | HIGH | CMD_EXEC, CMD_HISTORY | T1070.003 |
| `rule-cmd-port-scan` | Port Scanner Executed | HIGH | CMD_EXEC, CMD_HISTORY | T1046 |
| `rule-cmd-cred-dumper` | Credential Dumper Executed | CRITICAL | CMD_EXEC, CMD_HISTORY | T1003 |
| `rule-cmd-sudo-root` | Sudo Root Shell Escalation | HIGH | CMD_EXEC, CMD_HISTORY | T1548.003 |
| `rule-sudo-root-shell` | Sudo to Root Shell | MEDIUM | SUDO_EXEC | T1548.003 |
| `rule-browser-form-submit-unknown` | Credential Submission to Non-Allowlisted Domain | HIGH | BROWSER_REQUEST | T1056.004 |
| `rule-browser-ioc-domain-visit` | Browser Visited IOC-Flagged Domain | CRITICAL | BROWSER_REQUEST | T1566.002 |
| `rule-browser-redirect-chain` | Suspicious Redirect Chain Detected | MEDIUM | BROWSER_REQUEST | T1566.002 |
| `rule-browser-rare-tld-form` | Form Submission to Rare TLD | HIGH | BROWSER_REQUEST | T1566.002 |

### Threshold Rules

| ID | Name | Severity | Threshold | Window | Group By | MITRE |
|---|---|---|---|---|---|---|
| `rule-thresh-port-scan` | Port Scan Detected (threshold) | HIGH | 20 events | 30s | process.pid | T1046 |
| `rule-thresh-brute-force` | SSH Brute Force (threshold) | HIGH | 20 events | 60s | agent_id | T1110 |
| `rule-thresh-beaconing` | C2 Beaconing Detected (threshold) | HIGH | 10 events | 300s | dst_ip | T1071 |
| `rule-thresh-exec-burst` | Execution Burst (threshold) | MEDIUM | 30 events | 60s | agent_id | T1059 |
| `rule-thresh-login-brute` | Login Brute Force (threshold) | HIGH | 10 events | 120s | agent_id | T1110.001 |
| `rule-ssh-brute-source` | SSH Brute Force from Single IP (threshold) | HIGH | 5 events | 60s | source_ip | T1110.001 |
| `rule-browser-high-volume` | Browser High Volume Requests (threshold) | MEDIUM | 50 events | 60s | domain | T1204.001 |

## SSE Broker

The SSE (Server-Sent Events) broker (`internal/sse/`) provides live event streaming to connected browser clients. When an event is stored, it is also published to the SSE broker, which fans it out to all connected UI sessions. Clients connect via `GET /api/v1/events/stream`.

## LLM Integration

The backend supports optional AI-powered alert explanation via multiple LLM providers. Configuration is managed at runtime through the Settings API.

### Supported Providers

| Provider | Env Vars | Notes |
|---|---|---|
| **Ollama** | `OLLAMA_ENABLED=true`, `OLLAMA_URL`, `OLLAMA_MODEL` | Local/self-hosted. Default model: `llama3.2`. Default URL: `http://localhost:11434`. |
| **OpenAI** | Via Settings API | Requires API key. |
| **Anthropic** | Via Settings API | Requires API key. |
| **Gemini** | Via Settings API | Requires API key. |

The LLM client supports hot-swapping providers at runtime via `POST /api/v1/settings/llm`. Use `POST /api/v1/settings/llm/test` to verify connectivity before saving.

Alert explanation is triggered via `POST /api/v1/alerts/:id/explain`.

## Live Response

The backend supports remote command execution on connected agents via the Live Response feature:

- Agents maintain a bidirectional gRPC stream (`LiveResponse` RPC)
- The REST API exposes `GET /api/v1/liveresponse/agents` to list agents with active sessions
- `POST /api/v1/liveresponse/command` sends a command to an agent and waits for the result
- Commands include an action, arguments, and a timeout
- Results contain exit code, stdout, stderr, and error information

## Authentication

### JWT Authentication

- Users authenticate via `POST /api/v1/auth/login` with username/password
- A JWT token is returned on success
- Tokens can be refreshed via `POST /api/v1/auth/refresh`
- JWT secret is set via `EDR_JWT_SECRET` environment variable (random ephemeral if unset)
- All authenticated endpoints require a `Bearer <token>` header

### API Key Authentication

- API keys are created via `POST /api/v1/keys` (admin only)
- Keys are stored as prefix + hash (the full key is only returned on creation)
- Keys can be revoked, have expiration dates, and track last-used timestamps
- API keys are passed as `Bearer <key>` in the Authorization header

### Roles

- `analyst` -- standard user with read access and alert management
- `admin` -- full access including user management, API keys, and audit log

## Data Retention

The backend runs automated data retention jobs:

- Event retention: configurable via `retention.event_days` (YAML) or `POST /api/v1/settings/retention` (API)
- Alert retention: configurable separately; only closed/resolved alerts are deleted
- Default database settings: 30 days for events, 90 days for alerts
- Default YAML settings: 90 days for events, alerts kept indefinitely
- Set to 0 to disable retention for a category

## Initial Setup

When no users exist in the database, the setup endpoints are available:

- `GET /api/v1/setup/status` -- check if setup is needed
- `POST /api/v1/setup` -- create the initial admin user

These endpoints are intentionally unauthenticated and only function when the users table is empty.
