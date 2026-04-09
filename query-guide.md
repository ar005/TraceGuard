# OEDR Threat Hunting Query Guide

The Hunt tab lets analysts write SQL-like queries directly against the raw events table. This is the most powerful investigation tool in OEDR — you can search across all telemetry collected from every endpoint.

---

## Quick Start

Open the **Hunt** tab in the UI, type a query, and click **Run Query**. Results appear in a table below.

```sql
-- Find all bash executions in the last hour
event_type = 'PROCESS_EXEC' AND payload->>'exe_path' LIKE '%bash%'
  AND timestamp > NOW() - INTERVAL '1 hour'

-- Find failed SSH logins from external IPs
event_type = 'LOGIN_FAILED' AND payload->>'service' = 'sshd'

-- Find files written to /etc/
event_type = 'FILE_WRITE' AND payload->>'path' LIKE '/etc/%'
```

---

## How It Works

Your query becomes the `WHERE` clause in:

```sql
SELECT * FROM events WHERE ( <your query> ) ORDER BY timestamp DESC LIMIT <limit>
```

You write standard PostgreSQL predicates. The system validates your input, rejects anything dangerous, and returns matching events.

**API endpoint:** `POST /api/v1/hunt`

```json
{
  "query": "event_type = 'PROCESS_EXEC' AND hostname = 'web01'",
  "limit": 100
}
```

Response:

```json
{
  "events": [ ... ],
  "total": 1234,
  "query": "event_type = 'PROCESS_EXEC' AND hostname = 'web01'"
}
```

---

## Events Table Columns

These are the top-level columns you can query directly:

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `id` | TEXT | Event UUID | `id = 'abc-123'` |
| `agent_id` | TEXT | Agent that generated the event | `agent_id = 'agent-xyz'` |
| `hostname` | TEXT | Endpoint hostname | `hostname = 'web-prod-01'` |
| `event_type` | TEXT | Event type (see list below) | `event_type = 'PROCESS_EXEC'` |
| `timestamp` | TIMESTAMPTZ | When the event occurred | `timestamp > NOW() - INTERVAL '24 hours'` |
| `payload` | JSONB | Full event data (nested JSON) | `payload->>'path' LIKE '/tmp/%'` |
| `received_at` | TIMESTAMPTZ | When the backend received it | `received_at > '2026-03-19'` |
| `severity` | SMALLINT | 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL | `severity >= 3` |
| `rule_id` | TEXT | Detection rule that matched (if any) | `rule_id != ''` |
| `alert_id` | TEXT | Alert ID (if alert was fired) | `alert_id != ''` |

---

## Accessing Payload Fields (JSONB)

Event-specific data lives in the `payload` column as JSON. Access nested fields with PostgreSQL's `->>'field'` operator:

```sql
-- Text extraction (returns TEXT, use for string comparisons)
payload->>'path'                         -- top-level field
payload->'process'->>'exe_path'          -- nested field
payload->'process'->>'pid'               -- nested field (returns text)

-- Numeric extraction (cast for numeric comparisons)
(payload->'process'->>'pid')::int        -- cast to integer
(payload->>'dst_port')::int              -- cast to integer
(payload->>'bytes_sent')::bigint         -- cast to bigint

-- Boolean extraction
(payload->>'is_memfd')::boolean          -- cast to boolean
(payload->>'is_private')::boolean

-- Array contains (check if a JSON array contains a value)
payload->'tags' ? 'revshell'             -- tags array contains 'revshell'

-- Full-text search across entire payload
payload::text ILIKE '%suspicious_string%'
```

---

## Event Types

### Process Events

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `PROCESS_EXEC` | Process executed | `process.pid`, `process.ppid`, `process.exe_path`, `process.cmdline`, `process.username`, `process.cwd`, `exe_hash`, `is_memfd`, `parent_process.*` |
| `PROCESS_EXIT` | Process terminated | `process.pid`, `exit_code`, `signal`, `duration` |
| `PROCESS_FORK` | Process forked | `process.pid`, `child_pid`, `clone_flags`, `is_thread` |
| `PROCESS_PTRACE` | ptrace operation | `process.pid`, `target_pid`, `target_comm`, `ptrace_request` |

### Network Events

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `NET_CONNECT` | Outbound TCP/UDP connection | `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `direction`, `is_private`, `process.*` |
| `NET_ACCEPT` | Inbound connection accepted | `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `direction`, `process.*` |
| `NET_DNS` | DNS resolution | `dns_query`, `resolved_ips`, `process.*` |
| `NET_CLOSE` | Connection closed | `src_ip`, `dst_ip`, `dst_port`, `bytes_sent`, `bytes_recv`, `duration` |

### File Events

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `FILE_CREATE` | File created | `path`, `hash_after`, `mode`, `size_bytes`, `process.*` |
| `FILE_WRITE` | File written | `path`, `hash_after`, `size_bytes`, `process.*` |
| `FILE_DELETE` | File deleted | `path`, `process.*` |
| `FILE_RENAME` | File renamed | `path`, `old_path`, `process.*` |
| `FILE_CHMOD` | Permissions changed | `path`, `mode`, `process.*` |

### Authentication Events

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `LOGIN_SUCCESS` | Successful login | `username`, `source_ip`, `service`, `method` |
| `LOGIN_FAILED` | Failed login attempt | `username`, `source_ip`, `service`, `method` |
| `SUDO_EXEC` | Sudo command executed | `username`, `target_user`, `command`, `tty` |

### Command Events

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `CMD_EXEC` | Command executed (proc scan) | `cmdline`, `tags`, `process.*` |
| `CMD_HISTORY` | Shell history entry | `cmdline`, `tags`, `shell`, `history_file` |

### Config/Registry Events

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `REG_SET` | Config file modified | `path`, `key`, `old_value`, `new_value`, `category` |
| `REG_DELETE` | Config entry removed | `path`, `key`, `category` |

### Agent Lifecycle

| Type | Description |
|------|-------------|
| `AGENT_START` | Agent started (includes version info) |
| `AGENT_STOP` | Agent stopped |
| `AGENT_TAMPER` | Tamper attempt detected |
| `AGENT_HEARTBEAT` | Periodic heartbeat |
| `PKG_INVENTORY` | Package inventory snapshot |

---

## Process Context Fields

Every event includes a `process` object with full attribution. Access via `payload->'process'->>'field'`:

| Field | Type | Description |
|-------|------|-------------|
| `pid` | int | Process ID |
| `ppid` | int | Parent process ID |
| `uid` | int | User ID |
| `gid` | int | Group ID |
| `euid` | int | Effective UID (detects setuid escalation) |
| `username` | string | Resolved username |
| `comm` | string | Short process name (max 16 chars) |
| `exe_path` | string | Full path to executable |
| `cmdline` | string | Full command line |
| `cwd` | string | Working directory |
| `container_id` | string | Container ID (if containerized) |
| `runtime` | string | Container runtime: docker, containerd, podman, cri-o |
| `image_name` | string | Container image name |
| `pod_name` | string | Kubernetes pod name |
| `namespace` | string | Kubernetes namespace |

---

## SQL Operators Reference

| Operator | Example | Description |
|----------|---------|-------------|
| `=` | `event_type = 'NET_CONNECT'` | Exact match |
| `!=` / `<>` | `hostname != 'test-box'` | Not equal |
| `>`, `<`, `>=`, `<=` | `severity >= 3` | Numeric/date comparison |
| `LIKE` | `payload->>'path' LIKE '/etc/%'` | Pattern match (% = wildcard) |
| `ILIKE` | `payload->>'cmdline' ILIKE '%password%'` | Case-insensitive LIKE |
| `IN` | `event_type IN ('FILE_WRITE','FILE_CREATE')` | Match any in list |
| `NOT IN` | `hostname NOT IN ('test1','test2')` | Exclude list |
| `IS NULL` | `alert_id IS NULL` | Null check |
| `IS NOT NULL` | `rule_id IS NOT NULL` | Not null |
| `AND` | `severity >= 3 AND hostname = 'prod'` | Both conditions |
| `OR` | `event_type = 'FILE_WRITE' OR event_type = 'FILE_CREATE'` | Either condition |
| `NOT` | `NOT payload->>'is_private' = 'true'` | Negate |
| `BETWEEN` | `timestamp BETWEEN '2026-03-18' AND '2026-03-19'` | Range |
| `~` | `payload->>'cmdline' ~ 'nc.*-e'` | Regex match |
| `~*` | `payload->>'cmdline' ~* 'NC.*-E'` | Case-insensitive regex |
| `?` | `payload->'tags' ? 'revshell'` | JSONB array contains key |
| `@>` | `payload @> '{"is_memfd": true}'` | JSONB contains |
| `::int` | `(payload->>'dst_port')::int > 49151` | Type cast for comparison |
| `::boolean` | `(payload->>'is_memfd')::boolean = true` | Boolean cast |

---

## Example Queries

### Process Hunting

```sql
-- All processes run by root
event_type = 'PROCESS_EXEC' AND payload->'process'->>'uid' = '0'

-- Processes with suspicious names
event_type = 'PROCESS_EXEC'
  AND payload->'process'->>'exe_path' ILIKE '%/tmp/%'

-- Fileless execution (memfd)
event_type = 'PROCESS_EXEC' AND (payload->>'is_memfd')::boolean = true

-- Python or perl spawned by a web server
event_type = 'PROCESS_EXEC'
  AND payload->'process'->>'comm' IN ('python','python3','perl')
  AND payload->'parent_process'->>'comm' IN ('nginx','apache2','httpd')

-- Processes in containers
event_type = 'PROCESS_EXEC'
  AND payload->'process'->>'container_id' != ''

-- Processes in a specific Kubernetes namespace
event_type = 'PROCESS_EXEC'
  AND payload->'process'->>'namespace' = 'production'
```

### Network Hunting

```sql
-- All external outbound connections
event_type = 'NET_CONNECT'
  AND payload->>'direction' = 'OUTBOUND'
  AND (payload->>'is_private')::boolean = false

-- Connections to a specific IP
event_type = 'NET_CONNECT' AND payload->>'dst_ip' = '203.0.113.50'

-- High-port connections (potential C2)
event_type = 'NET_CONNECT'
  AND (payload->>'dst_port')::int > 49151
  AND payload->>'direction' = 'OUTBOUND'

-- DNS queries for suspicious domains
event_type = 'NET_DNS'
  AND payload->>'dns_query' ILIKE '%.xyz'

-- Large data transfers (> 100MB sent)
event_type = 'NET_CLOSE'
  AND (payload->>'bytes_sent')::bigint > 104857600
```

### File Hunting

```sql
-- Files written to sensitive directories
event_type IN ('FILE_WRITE','FILE_CREATE')
  AND (payload->>'path' LIKE '/etc/%'
    OR payload->>'path' LIKE '/root/.ssh/%'
    OR payload->>'path' LIKE '/var/spool/cron/%')

-- Executable files created in /tmp
event_type = 'FILE_CREATE'
  AND payload->>'path' LIKE '/tmp/%'
  AND (payload->>'mode')::int & 73 > 0

-- File renames (potential staging)
event_type = 'FILE_RENAME'
  AND payload->>'old_path' LIKE '/tmp/%'
  AND payload->>'path' LIKE '/usr/%'

-- Files written by a specific process
event_type = 'FILE_WRITE'
  AND payload->'process'->>'comm' = 'curl'
```

### Authentication Hunting

```sql
-- All failed logins
event_type = 'LOGIN_FAILED'

-- Failed SSH logins from a specific IP
event_type = 'LOGIN_FAILED'
  AND payload->>'service' = 'sshd'
  AND payload->>'source_ip' = '10.0.0.50'

-- Sudo to root
event_type = 'SUDO_EXEC'
  AND payload->>'target_user' = 'root'

-- Sudo commands containing suspicious patterns
event_type = 'SUDO_EXEC'
  AND payload->>'command' ~* '(chmod.*777|chown.*root|bash|sh$)'

-- Successful logins from unusual IPs (not in known range)
event_type = 'LOGIN_SUCCESS'
  AND payload->>'source_ip' NOT LIKE '10.0.%'
  AND payload->>'source_ip' NOT LIKE '192.168.%'
  AND payload->>'source_ip' IS NOT NULL
```

### Command Hunting

```sql
-- Commands tagged as reverse shells
event_type IN ('CMD_EXEC','CMD_HISTORY')
  AND payload::text ILIKE '%revshell%'

-- Curl piped to shell
event_type IN ('CMD_EXEC','CMD_HISTORY')
  AND payload->>'cmdline' ~* 'curl.*\|.*(sh|bash)'

-- Base64 decoding commands
event_type IN ('CMD_EXEC','CMD_HISTORY')
  AND payload->>'cmdline' ILIKE '%base64%decode%'

-- History evasion attempts
event_type IN ('CMD_EXEC','CMD_HISTORY')
  AND payload::text ILIKE '%history-evasion%'
```

### Cross-Type Hunting

```sql
-- All high/critical severity events in the last hour
severity >= 3 AND timestamp > NOW() - INTERVAL '1 hour'

-- Everything from a specific host in the last 24h
hostname = 'compromised-host'
  AND timestamp > NOW() - INTERVAL '24 hours'

-- All events that triggered alerts
alert_id != ''

-- Events from a specific agent with any detection rule match
agent_id = 'agent-abc-123' AND rule_id != ''

-- Full-text search across all payloads
payload::text ILIKE '%mimikatz%'

-- Container-related events
payload::text ILIKE '%container_id%'
  AND payload->'process'->>'container_id' != ''
```

### Time-Based Queries

```sql
-- Events from a specific date range
timestamp BETWEEN '2026-03-18T00:00:00Z' AND '2026-03-19T00:00:00Z'

-- Events in the last N minutes
timestamp > NOW() - INTERVAL '30 minutes'

-- Off-hours events (between midnight and 5 AM UTC)
EXTRACT(HOUR FROM timestamp) BETWEEN 0 AND 5
```

---

## Blocked Keywords

For security, the following SQL keywords are **rejected** (case-insensitive):

`DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `TRUNCATE`, `CREATE`, `GRANT`, `EXEC`, `UNION`

Semicolons (`;`) are also blocked. These restrictions prevent modification of data — hunt queries are strictly read-only.

---

## Limits

| Parameter | Default | Maximum |
|-----------|---------|---------|
| Result limit | 100 | 1000 |
| Query timeout | Database default | — |
| Payload search | Full GIN index | — |

The response includes a `total` count of all matching events (not just the returned page), so you know if there are more results than the limit.

---

## Tips

1. **Start broad, then narrow.** Begin with `event_type = 'PROCESS_EXEC'` and add conditions.
2. **Use `payload::text ILIKE`** for fast full-text search when you're not sure which field contains the data.
3. **Use `EXPLAIN` prefix?** No — but the events table has indexes on `agent_id`, `event_type`, `timestamp DESC`, and a GIN index on `payload`. Queries filtering on these columns will be fast.
4. **Combine with timestamp filters** to keep queries performant on large datasets.
5. **Check container context** by adding `AND payload->'process'->>'container_id' != ''` to scope to containerized processes.
6. **Use regex (`~` or `~*`)** for complex pattern matching instead of multiple LIKE clauses.
