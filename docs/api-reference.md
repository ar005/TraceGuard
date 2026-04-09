# OEDR REST API Reference

Base URL: `http://localhost:8080`

All authenticated endpoints require a `Bearer` token (JWT or API key) in the `Authorization` header:

```
Authorization: Bearer <token>
```

---

## Health

### `GET /health`

**Auth:** None

Returns server health status.

**Response:**
```json
{
  "status": "ok"
}
```

### `GET /metrics`

**Auth:** None

Returns server metrics.

---

## Setup

These endpoints only work when no users exist in the database (first-run setup).

### `GET /api/v1/setup/status`

**Auth:** None

Check whether initial setup is required.

**Response:**
```json
{
  "setup_required": true
}
```

### `POST /api/v1/setup`

**Auth:** None

Create the initial admin user.

**Request:**
```json
{
  "username": "admin",
  "password": "changeme",
  "email": "admin@example.com"
}
```

**Response:**
```json
{
  "ok": true,
  "user_id": "usr-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

---

## Auth

### `POST /api/v1/auth/login`

**Auth:** None

Authenticate with username and password.

**Request:**
```json
{
  "username": "admin",
  "password": "changeme"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "usr-xxx",
    "username": "admin",
    "role": "admin"
  }
}
```

### `POST /api/v1/auth/refresh`

**Auth:** None (uses existing valid/near-expiry token)

Refresh a JWT token.

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## Dashboard

### `GET /api/v1/dashboard`

**Auth:** Required

Returns aggregated dashboard statistics (agent counts, event counts, alert counts, recent activity).

### `GET /api/v1/me`

**Auth:** Required

Returns the current authenticated user's profile.

**Response:**
```json
{
  "id": "usr-xxx",
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin"
}
```

---

## Agents

### `GET /api/v1/agents`

**Auth:** Required

List all registered agents.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |
| `search` | string | Filter by hostname or ID |

**Response:**
```json
{
  "agents": [
    {
      "id": "agent-xxx",
      "hostname": "web-01",
      "os": "linux",
      "os_version": "Ubuntu 22.04",
      "ip": "10.0.1.5",
      "agent_ver": "1.0.0",
      "is_online": true,
      "first_seen": "2025-01-01T00:00:00Z",
      "last_seen": "2025-01-15T12:00:00Z",
      "tags": ["prod", "webserver"],
      "env": "production",
      "notes": ""
    }
  ],
  "total": 1
}
```

### `GET /api/v1/agents/:id`

**Auth:** Required

Get a single agent by ID.

### `PATCH /api/v1/agents/:id`

**Auth:** Required

Update agent metadata (tags, env, notes).

**Request:**
```json
{
  "tags": ["prod", "webserver"],
  "env": "production",
  "notes": "Primary web server"
}
```

---

## Events

### `GET /api/v1/events`

**Auth:** Required

List events with filtering and pagination.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |
| `event_type` | string | Filter by event type (e.g., `PROCESS_EXEC`) |
| `agent_id` | string | Filter by agent ID |
| `severity` | int | Filter by minimum severity (0-4) |
| `search` | string | Full-text search in event payload |
| `since` | string | Start time (RFC3339) |
| `until` | string | End time (RFC3339) |

**Response:**
```json
{
  "events": [
    {
      "id": "evt-xxx",
      "agent_id": "agent-xxx",
      "hostname": "web-01",
      "event_type": "PROCESS_EXEC",
      "timestamp": "2025-01-15T12:00:00Z",
      "severity": 0,
      "payload": { ... }
    }
  ],
  "total": 1000
}
```

### `GET /api/v1/events/:id`

**Auth:** Required

Get a single event by ID.

### `POST /api/v1/events/inject`

**Auth:** Required

Inject a synthetic event for testing.

**Request:**
```json
{
  "agent_id": "agent-xxx",
  "event_type": "PROCESS_EXEC",
  "payload": { ... }
}
```

### `GET /api/v1/events/stream`

**Auth:** Required

SSE (Server-Sent Events) stream of live events. Connect with an `EventSource` or SSE-compatible client.

**Response:** A continuous stream of `text/event-stream` data:

```
data: {"id":"evt-xxx","event_type":"PROCESS_EXEC","timestamp":"...","payload":{...}}

data: {"id":"evt-yyy","event_type":"NET_CONNECT","timestamp":"...","payload":{...}}
```

---

## Process Tree

### `GET /api/v1/processes/:pid/tree`

**Auth:** Required

Get the process tree (parent-child relationships) for a specific process.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `agent_id` | string | Agent to query (required) |

---

## Alerts

### `GET /api/v1/alerts`

**Auth:** Required

List alerts with filtering and pagination.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |
| `status` | string | Filter by status: `OPEN`, `IN_PROGRESS`, `CLOSED`, `FALSE_POSITIVE` |
| `severity` | int | Filter by minimum severity (0-4) |
| `agent_id` | string | Filter by agent ID |
| `search` | string | Search in alert title and description |
| `since` | string | Start time (RFC3339) |
| `until` | string | End time (RFC3339) |

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert-xxx",
      "title": "Web Server Spawning Shell",
      "description": "...",
      "severity": 3,
      "status": "OPEN",
      "rule_id": "rule-suspicious-shell",
      "rule_name": "Web Server Spawning Shell",
      "mitre_ids": ["T1059.004", "T1190"],
      "event_ids": ["evt-xxx"],
      "agent_id": "agent-xxx",
      "hostname": "web-01",
      "first_seen": "2025-01-15T12:00:00Z",
      "last_seen": "2025-01-15T12:00:00Z",
      "hit_count": 1,
      "assignee": "",
      "notes": ""
    }
  ],
  "total": 5
}
```

### `GET /api/v1/alerts/:id`

**Auth:** Required

Get a single alert by ID.

### `GET /api/v1/alerts/:id/events`

**Auth:** Required

Get all events associated with an alert.

### `GET /api/v1/alerts/:id/timeline`

**Auth:** Required

Get the timeline of events for an alert (ordered chronologically).

### `POST /api/v1/alerts/:id/explain`

**Auth:** Required

Generate an AI-powered explanation of the alert using the configured LLM provider.

**Response:**
```json
{
  "explanation": "This alert fired because nginx (PID 1234) spawned a bash shell, which is a common indicator of web shell exploitation..."
}
```

### `PATCH /api/v1/alerts/:id`

**Auth:** Required

Update alert status, assignee, or notes.

**Request:**
```json
{
  "status": "IN_PROGRESS",
  "assignee": "analyst@example.com",
  "notes": "Investigating this incident"
}
```

---

## Live Response

### `GET /api/v1/liveresponse/agents`

**Auth:** Required

List agents with active live response sessions.

**Response:**
```json
{
  "agents": ["agent-xxx", "agent-yyy"]
}
```

### `POST /api/v1/liveresponse/command`

**Auth:** Required

Send a command to an agent and wait for the result.

**Request:**
```json
{
  "agent_id": "agent-xxx",
  "action": "exec",
  "args": ["ps", "aux"],
  "timeout": 30
}
```

**Response:**
```json
{
  "command_id": "cmd-xxx",
  "agent_id": "agent-xxx",
  "status": "completed",
  "exit_code": 0,
  "stdout": "USER  PID ...",
  "stderr": "",
  "error": ""
}
```

---

## Incidents

### `GET /api/v1/incidents`

**Auth:** Required

List incidents with filtering.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |
| `status` | string | Filter by status |
| `severity` | int | Filter by minimum severity |

### `GET /api/v1/incidents/:id`

**Auth:** Required

Get a single incident by ID.

### `PATCH /api/v1/incidents/:id`

**Auth:** Required

Update incident status, assignee, or notes.

**Request:**
```json
{
  "status": "IN_PROGRESS",
  "assignee": "analyst@example.com",
  "notes": "Confirmed compromise"
}
```

### `GET /api/v1/incidents/:id/alerts`

**Auth:** Required

Get all alerts associated with an incident.

---

## Rules

### `GET /api/v1/rules`

**Auth:** Required

List all detection rules.

**Response:**
```json
{
  "rules": [
    {
      "id": "rule-suspicious-shell",
      "name": "Web Server Spawning Shell",
      "description": "...",
      "enabled": true,
      "severity": 3,
      "event_types": ["PROCESS_EXEC"],
      "conditions": [...],
      "mitre_ids": ["T1059.004", "T1190"],
      "rule_type": "match",
      "threshold_count": 0,
      "threshold_window_s": 0,
      "group_by": "",
      "author": "system",
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

### `GET /api/v1/rules/:id`

**Auth:** Required

Get a single rule by ID.

### `POST /api/v1/rules`

**Auth:** Required

Create a new detection rule.

**Request:**
```json
{
  "name": "Custom SSH Alert",
  "description": "Alert on SSH connections to non-standard ports",
  "severity": 2,
  "event_types": ["NET_CONNECT"],
  "conditions": [
    {"field": "dst_port", "op": "eq", "value": 2222},
    {"field": "direction", "op": "eq", "value": "OUTBOUND"}
  ],
  "mitre_ids": ["T1021.004"],
  "rule_type": "match"
}
```

### `PUT /api/v1/rules/:id`

**Auth:** Required

Update an existing rule (full replacement).

### `DELETE /api/v1/rules/:id`

**Auth:** Required

Delete a rule.

### `POST /api/v1/rules/reload`

**Auth:** Required

Force the detection engine to reload all rules and suppressions from the database.

### `POST /api/v1/rules/:id/backtest`

**Auth:** Required

Run a rule against historical events to see what would have matched.

---

## Suppressions

### `GET /api/v1/suppressions`

**Auth:** Required

List all suppression rules.

**Response:**
```json
{
  "suppressions": [
    {
      "id": "sup-xxx",
      "name": "Suppress cron healthchecks",
      "description": "...",
      "enabled": true,
      "event_types": ["PROCESS_EXEC"],
      "conditions": [...],
      "hit_count": 1523,
      "last_hit_at": "2025-01-15T12:00:00Z"
    }
  ]
}
```

### `POST /api/v1/suppressions`

**Auth:** Required

Create a new suppression rule.

**Request:**
```json
{
  "name": "Suppress cron healthchecks",
  "description": "Ignore process exec from crond running /usr/local/bin/healthcheck",
  "event_types": ["PROCESS_EXEC"],
  "conditions": [
    {"field": "process.comm", "op": "eq", "value": "crond"},
    {"field": "process.cmdline", "op": "contains", "value": "healthcheck"}
  ]
}
```

### `PUT /api/v1/suppressions/:id`

**Auth:** Required

Update an existing suppression rule.

### `DELETE /api/v1/suppressions/:id`

**Auth:** Required

Delete a suppression rule.

---

## Packages and Vulnerabilities

### `GET /api/v1/agents/:id/packages`

**Auth:** Required

List installed packages for an agent.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results |
| `offset` | int | Pagination offset |
| `search` | string | Filter by package name |

### `GET /api/v1/agents/:id/vulnerabilities`

**Auth:** Required

List known vulnerabilities for an agent's installed packages.

### `GET /api/v1/vulnerabilities`

**Auth:** Required

List all known vulnerabilities across all agents.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results |
| `offset` | int | Pagination offset |
| `severity` | string | Filter by CVE severity |
| `cve_id` | string | Filter by specific CVE ID |

---

## IOCs (Indicators of Compromise)

### `GET /api/v1/iocs`

**Auth:** Required

List IOCs with filtering.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results |
| `offset` | int | Pagination offset |
| `type` | string | Filter by IOC type (ip, domain, hash) |
| `source` | string | Filter by source |
| `search` | string | Search in IOC value or description |

**Response:**
```json
{
  "iocs": [
    {
      "id": "ioc-xxx",
      "type": "ip",
      "value": "198.51.100.1",
      "source": "abuse.ch",
      "severity": 3,
      "description": "Feodo Tracker C2",
      "tags": ["c2", "feodo"],
      "enabled": true,
      "expires_at": null,
      "created_at": "2025-01-01T00:00:00Z",
      "hit_count": 0,
      "last_hit_at": null
    }
  ],
  "total": 500
}
```

### `GET /api/v1/iocs/stats`

**Auth:** Required

Get IOC statistics (counts by type, source, etc.).

### `GET /api/v1/iocs/:id`

**Auth:** Required

Get a single IOC by ID.

### `POST /api/v1/iocs`

**Auth:** Required

Create a single IOC.

**Request:**
```json
{
  "type": "ip",
  "value": "198.51.100.1",
  "source": "manual",
  "severity": 3,
  "description": "Known C2 server",
  "tags": ["c2"]
}
```

### `POST /api/v1/iocs/bulk`

**Auth:** Required

Bulk import IOCs.

**Request:**
```json
{
  "iocs": [
    {"type": "ip", "value": "198.51.100.1", "source": "feed", "severity": 3},
    {"type": "domain", "value": "evil.example.com", "source": "feed", "severity": 4}
  ]
}
```

### `DELETE /api/v1/iocs/:id`

**Auth:** Required

Delete a single IOC.

### `DELETE /api/v1/iocs/source/:source`

**Auth:** Required

Delete all IOCs from a specific source (e.g., to purge and re-sync a feed).

### `GET /api/v1/iocs/feeds`

**Auth:** Required

List configured threat intelligence feeds and their sync status.

### `POST /api/v1/iocs/feeds/sync`

**Auth:** Required

Trigger an immediate sync of all IOC feeds.

### `GET /api/v1/iocs/sources`

**Auth:** Required

Get IOC counts grouped by source.

---

## Threat Hunting

### `POST /api/v1/hunt`

**Auth:** Required

Run a threat hunting query across stored events.

**Request:**
```json
{
  "query": "process.comm = 'curl' AND dst_port = 443",
  "since": "2025-01-01T00:00:00Z",
  "until": "2025-01-15T00:00:00Z",
  "limit": 100
}
```

**Response:**
```json
{
  "results": [...],
  "total": 42
}
```

---

## Settings

### `GET /api/v1/settings/retention`

**Auth:** Required

Get current data retention settings.

**Response:**
```json
{
  "retention_events_days": 30,
  "retention_alerts_days": 90
}
```

### `POST /api/v1/settings/retention`

**Auth:** Required

Update data retention settings.

**Request:**
```json
{
  "retention_events_days": 60,
  "retention_alerts_days": 180
}
```

### `GET /api/v1/settings/llm`

**Auth:** Required

Get current LLM provider configuration.

**Response:**
```json
{
  "provider": "ollama",
  "model": "llama3.2",
  "base_url": "http://localhost:11434",
  "enabled": true
}
```

### `POST /api/v1/settings/llm`

**Auth:** Required

Configure the LLM provider. Supported providers: `ollama`, `openai`, `anthropic`, `gemini`.

**Request:**
```json
{
  "provider": "openai",
  "model": "gpt-4",
  "api_key": "sk-...",
  "enabled": true
}
```

### `POST /api/v1/settings/llm/test`

**Auth:** Required

Test the LLM connection with the current or provided configuration.

---

## Migration

### `POST /api/v1/migrate/export`

**Auth:** Required

Export all data (rules, suppressions, IOCs, settings) as a JSON archive.

### `POST /api/v1/migrate/import`

**Auth:** Required

Import data from a previously exported JSON archive.

---

## API Keys (Admin)

Available under both `/api/v1/keys` (authenticated) and `/api/v1/admin/keys` (admin-only).

### `GET /api/v1/keys`

**Auth:** Required (Admin)

List all API keys (prefix and metadata only, not the full key).

**Response:**
```json
{
  "keys": [
    {
      "id": "key-xxx",
      "name": "CI Pipeline",
      "prefix": "edr_xxxxx",
      "created_at": "2025-01-01T00:00:00Z",
      "expires_at": "2026-01-01T00:00:00Z",
      "last_used_at": "2025-01-15T12:00:00Z",
      "created_by": "admin",
      "enabled": true
    }
  ]
}
```

### `POST /api/v1/keys`

**Auth:** Required (Admin)

Create a new API key. The full key is returned only once.

**Request:**
```json
{
  "name": "CI Pipeline",
  "expires_at": "2026-01-01T00:00:00Z"
}
```

**Response:**
```json
{
  "id": "key-xxx",
  "name": "CI Pipeline",
  "key": "edr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "prefix": "edr_xxxxx"
}
```

### `POST /api/v1/keys/:id/revoke`

**Auth:** Required (Admin)

Revoke an API key (disables it without deleting).

### `DELETE /api/v1/keys/:id`

**Auth:** Required (Admin)

Permanently delete an API key.

---

## Admin

All admin endpoints require the `admin` role.

### `GET /api/v1/admin/users`

**Auth:** Required (Admin)

List all users.

### `POST /api/v1/admin/users`

**Auth:** Required (Admin)

Create a new user.

**Request:**
```json
{
  "username": "analyst1",
  "password": "securepassword",
  "email": "analyst@example.com",
  "role": "analyst"
}
```

### `GET /api/v1/admin/users/:id`

**Auth:** Required (Admin)

Get a single user by ID.

### `PATCH /api/v1/admin/users/:id`

**Auth:** Required (Admin)

Update a user's role, email, or enabled status.

**Request:**
```json
{
  "role": "admin",
  "enabled": true
}
```

### `DELETE /api/v1/admin/users/:id`

**Auth:** Required (Admin)

Delete a user.

### `POST /api/v1/admin/users/:id/reset-password`

**Auth:** Required (Admin)

Reset a user's password.

**Request:**
```json
{
  "password": "newpassword"
}
```

### `DELETE /api/v1/admin/reset-all-users`

**Auth:** Required (Admin)

Delete all users and reset to setup state.

### `GET /api/v1/admin/audit`

**Auth:** Required (Admin)

Get the audit log of administrative actions.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Max results (default 50) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "entries": [
    {
      "id": 1,
      "timestamp": "2025-01-15T12:00:00Z",
      "actor_id": "usr-xxx",
      "actor_name": "admin",
      "action": "user.create",
      "target_type": "user",
      "target_id": "usr-yyy",
      "target_name": "analyst1",
      "ip": "10.0.1.1",
      "details": ""
    }
  ],
  "total": 1
}
```

---

## Error Responses

All endpoints return errors in a consistent format:

```json
{
  "error": "description of what went wrong"
}
```

Common HTTP status codes:

| Code | Meaning |
|---|---|
| 400 | Bad request (invalid parameters or body) |
| 401 | Unauthorized (missing or invalid token) |
| 403 | Forbidden (insufficient role) |
| 404 | Resource not found |
| 429 | Rate limited |
| 500 | Internal server error |
