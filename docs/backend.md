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

**Bootstrap admin credentials.** On first run against an empty `users` table the backend creates an admin user with a generated 20-character password and logs the pair as a warning. When the `EDR_AUTH_BOOTSTRAP_FILE` env var is set, the same `username=` / `password=` pair is also written to that path with mode `0600`. `edr-backend/deploy/docker-compose.yml` sets it to `/app/bootstrap/cred.txt` and mounts `./bootstrap:/app/bootstrap`, so the host file path is `edr-backend/deploy/bootstrap/cred.txt`. The file is written **only on first run** — subsequent restarts find an existing user and skip both the log line and the file write. **Delete the file once the password is saved**; anyone who can read it gets full admin access.

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
| `agents` | Registered endpoint agents. Columns: id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen, is_online, config_ver, tags, env, notes, winevent_config (JSONB), risk_score, risk_factors, risk_updated_at. |
| `events` | All telemetry events. Extended with OCSF fields: class_uid, category_uid, activity_id, source_type, source_id, tenant_id, user_uid, src_ip, dst_ip, process_name, raw_log, enrichments (JSONB). Indexed on agent_id, event_type, timestamp (DESC), payload (GIN), source_type, user_uid, src/dst IP. |
| `alerts` | Detection alerts. Columns include: hit_count, incident_id, user_uid, source_types, triage_verdict, triage_score, triage_notes, triage_at, src_ip, enrichments (JSONB), risk_score, tenant_id. |
| `rules` | Detection rules. Extended with: rule_type (match/threshold/sequence_cross), threshold_count, threshold_window_s, group_by, source_types, sequence_window_s, sequence_by, sequence_steps (JSONB). |
| `suppression_rules` | Rules to suppress false-positive events. Columns: id, name, description, enabled, event_types, conditions (JSONB), created_at, updated_at, author, hit_count, last_hit_at. |
| `incidents` | Groups of related alerts. Extended with: user_uids, src_ips, source_types, tenant_id. |
| `cases` | Analyst investigation cases. Columns: id, title, description, status, severity, assignee, tags, mitre_ids, alert_count, created_by, created_at, updated_at, closed_at, tenant_id. |
| `case_alerts` | Many-to-many join between cases and alerts. Columns: case_id, alert_id, linked_at, linked_by. |
| `case_notes` | Notes on a case. Columns: id, case_id, body, author, created_at, updated_at. |
| `iocs` | Indicators of Compromise. Columns: id, type, value, source, severity, description, tags, enabled, expires_at, created_at, hit_count, last_hit_at. Unique index on (type, value). |
| `users` | User accounts. Columns: id, username, email, password_hash, role, enabled, created_at, last_login_at, created_by, totp_secret, totp_enabled, totp_backup_codes, tenant_id. |
| `api_keys` | API keys for programmatic access. Columns: id, name, prefix, hash, created_at, expires_at, last_used_at, created_by, enabled, role. |
| `audit_log` | Administrative action log. Columns: id (BIGSERIAL), timestamp, actor_id, actor_name, action, target_type, target_id, target_name, ip, details. |
| `settings` | Key-value configuration store. Seeded with `retention_events_days`, `retention_alerts_days`, `retention_flows_days`. |
| `agent_packages` | Installed packages per agent. Columns: id (BIGSERIAL), agent_id (FK), name, version, arch, collected_at. |
| `vulnerabilities` | Known CVEs matched against agent packages. |
| `cve_cache` | CVE metadata fetched from NVD. Columns include: cve_id, severity, description, exploit_available, cisa_kev, raw_json. |
| `pending_commands` | Queued live-response commands. Columns: id, agent_id, action, args (JSONB), created_by, status, result (JSONB), executed_at. |
| `playbooks` | SOAR automation playbooks. Columns: id, name, description, enabled, trigger_type, trigger_filter (JSONB), actions (JSONB), run_count. |
| `playbook_runs` | SOAR execution audit trail. Columns: id, playbook_id, playbook_name, trigger_type, trigger_id, status, started_at, finished_at, actions_log (JSONB). |
| `response_actions` | Response action audit trail. Columns: id, action_type, target_type, target_id, status, triggered_by, playbook_run_id, params/result (JSONB), reversed_at. |
| `export_destinations` | SIEM / notification sinks. dest_type: slack, pagerduty, webhook, syslog_cef, email. |
| `xdr_sources` | External data source connector registry. Columns: id, name, source_type, connector, config (JSONB), enabled, last_seen_at, events_today. |
| `identity_graph` | Normalized cross-source user identities. Columns: canonical_uid, display_name, risk_score, risk_factors, is_privileged, is_service_acct, account_ids (JSONB), agent_ids, email, aliases. |
| `asset_inventory` | Unified endpoint + cloud + network device registry. Columns: id, asset_type, hostname, ip_addresses, os, cloud_provider, cloud_region, cloud_account, cloud_resource_id, agent_id, risk_score. |
| `xdr_network_flows` | High-volume network flow data (partitioned by start_time). Columns: id, source_id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_in, bytes_out, packets_in/out, flow_state. |
| `container_inventory` | Container instances detected via process events. Columns: container_id, agent_id, runtime, image_name, pod_name, namespace, event_count. |
| `login_sessions` | Cross-source login session records. Columns: id, tenant_id, user_uid, agent_id, src_ip, logged_in_at, logged_out_at. |
| `behavioral_baselines` | EWMA behavioral baseline per user (UEBA). Columns: user_uid, tenant_id, ewma, ewma_sq, n. |
| `beaconing_state` | C2 beaconing detection state per agent+dst. Columns: agent_id, dst_ip, dst_port, intervals_s[], alert_fired. |
| `network_lateral_state` | Network lateral movement detection state. Columns: agent_id, dst_port, unique_ips, window_start. |
| `canary_tokens` | Deception canary tokens. Columns: id, tenant_id, name, type (credential/file/url/dns), token, deployed_to, description, triggered_at, trigger_count. |
| `exfil_signals` | Data exfiltration detection signals. Columns: id, tenant_id, agent_id, hostname, signal_type, detail (JSONB), bytes, detected_at, alert_id. |
| `agent_tasks` | Scheduled tasks for remote agents. Columns: id, tenant_id, agent_id, name, type, schedule, payload (JSONB), status, last_run_at, next_run_at, created_by. |
| `agent_task_events` | Audit trail for task execution. Columns: id, task_id, tenant_id, agent_id, task_name, task_type, action, actor, detail (JSONB), occurred_at. |
| `yara_rules` | YARA rule definitions. Columns: id, name, description, rule_text, enabled, severity, mitre_ids, tags. |
| `reports` | Generated reports. Columns: id, tenant_id, title, type, format, status, params (JSONB), row_count, data, created_by. |
| `auto_case_policies` | Auto-case creation policies. Columns: id, tenant_id, name, min_severity, rule_ids, mitre_ids, enabled. |
| `auto_remediation_rules` | Automatic remediation trigger rules. Columns: id, tenant_id, name, trigger_type, trigger_value, action, playbook_id, min_severity, enabled. |
| `custom_ioc_feeds` | Custom IOC feed URLs. Columns: id, tenant_id, name, url, format, feed_type, enabled, last_synced_at, entry_count. |
| `stix_imports` | STIX bundle import audit trail. |
| `sigma_imports` | Sigma rule import audit trail. |
| `tenant_rate_limits` | Per-tenant rate limit overrides. |
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

Unary RPC called every 30 seconds. Updates the agent's `last_seen` timestamp. Also the delivery channel for scheduled tasks.

- **Request:** agent_id, hostname, timestamp, os, `task_results[]` — results from previously delivered tasks (task_id, status, output, error)
- **Response:** ok, server_time (Unix nanoseconds for clock sync), config_version, `pending_tasks[]` — tasks due for execution (id, name, type, payload)

On each heartbeat, the backend claims any agent tasks where `next_run_at <= NOW()` and status is `active`, delivers them in the response, and updates `last_run_at` / `next_run_at`. The agent executes tasks in parallel goroutines and reports results in the next heartbeat request.

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

**Transport**: PostgreSQL `LISTEN`/`NOTIFY` on the `edr_events` channel. Every backend node runs a listener goroutine; `Publish()` calls `pg_notify`, and every node receives the notification and fans the JSON to its own SSE clients. Browser clients connecting to any node therefore see the full event stream regardless of which node holds the agent gRPC connection.

**Payload size handling**. `pg_notify` enforces an 8 000-byte payload ceiling. For events whose JSON exceeds 7 900 bytes the broker:

1. Publishes a slim marker — `{id, event_type, agent_id, tenant_id, _truncated: true}` — through `pg_notify`.
2. On the receive side, `listenLoop` detects the `_truncated: true` flag, calls `EventFetcher.GetEvent(ctx, id, tenantID)` against the store, and fans the **full** event JSON. The `tenant_id` field in the slim marker keeps the lookup correctly scoped under multi-tenancy.
3. UI clients always see the documented event shape; there is no special-case path for oversize events on the consumer side.

Wire the fetcher with `broker.SetEventFetcher(st)` after `sse.New(...)` in `cmd/server/main.go`. If the fetcher is unset (e.g. test-mode brokers), the slim marker is forwarded as-is.

## Pagination responses

All paginated list handlers (events, alerts, incidents, agent packages, vulnerabilities, IOCs, containers, container events, DNS events, DLP signals) return JSON of the form:

```json
{
  "events": [ ... page of items ... ],
  "total":  12847,
  "limit":  50,
  "offset": 100
}
```

`total` is the result of a `SELECT COUNT(*)` with the same `WHERE` clause as the page query — not the page length. The UI uses it to render `"101–150 of 12 847"` strings and to disable the Next/Last buttons at the end of the result set. The wrapping key (`events`, `alerts`, `incidents`, …) varies per endpoint; the meta keys are stable.

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

## Scheduled Tasks API

The backend manages a `agent_tasks` table. Tasks are delivered to agents via the heartbeat mechanism (see Heartbeat RPC above).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/agents/:id/tasks` | any | List tasks for an agent. Filter by `?status=`. |
| POST | `/api/v1/agents/:id/tasks` | admin | Create a task. Body: name, type, schedule, payload. |
| PUT | `/api/v1/agents/:id/tasks/:tid` | admin | Update task name, schedule, status, or payload. |
| DELETE | `/api/v1/agents/:id/tasks/:tid` | admin | Delete a task. |
| POST | `/api/v1/agents/:id/tasks/:tid/run` | any | On-demand trigger — sets `next_run_at = NOW()` so the task is claimed on the next heartbeat. |
| GET | `/api/v1/agents/:id/tasks/history` | any | Task execution event log. Filter by `?task_id=`. |
| GET | `/api/v1/tasks` | any | Global task list across all agents. |
| GET | `/api/v1/tasks/history` | any | Global task history across all agents. Filter by `?agent_id=` and/or `?task_id=`. |

**Task status values:** `active`, `paused`, `completed`, `deleted`

**Task types:** `script`, `collect`, `scan`, `remediate`

## DNS Intelligence API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/dns/events` | any | Query DNS events. Params: `agent_id`, `domain`, `limit` (max 500), `offset`. |
| GET | `/api/v1/dns/stats` | any | Top 50 queried domains. Param: `hours` (1–168, default 24). Response: `{top_domains: [...], hours: N}`. |

## Canary Tokens API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/canary/tokens` | any | List canary tokens for the tenant. |
| POST | `/api/v1/canary/tokens` | admin | Create a canary token. Body: name, type (credential/file/url/dns), deployed_to, description. Returns token UUID. |
| DELETE | `/api/v1/canary/tokens/:id` | admin | Delete a canary token. |
| POST | `/api/canary/trigger/:token` | **none** | Unauthenticated webhook endpoint. Records a trigger and fires a severity-5 alert. Always returns 200 OK (does not reveal token existence). |

## DLP / Exfil API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/dlp/events` | any | Query exfil signals. Params: `agent_id`, `limit`, `offset`. Response: `{signals: [...], total: N}`. |
| GET | `/api/v1/dlp/stats` | any | Per-agent exfil summary. Param: `hours` (default 24). Response: `{agents: [...], hours: N}`. |

## Initial Setup

When no users exist in the database, the setup endpoints are available:

- `GET /api/v1/setup/status` -- check if setup is needed
- `POST /api/v1/setup` -- create the initial admin user

These endpoints are intentionally unauthenticated and only function when the users table is empty.
