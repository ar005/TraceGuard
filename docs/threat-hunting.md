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
