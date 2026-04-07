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

### Incidents
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/incidents` | Query incidents (filters: status, min_severity, agent_id) |
| GET | `/api/v1/incidents/:id` | Single incident |
| PATCH | `/api/v1/incidents/:id` | Update status/assignee/notes |
| GET | `/api/v1/incidents/:id/alerts` | All alerts in the incident |

### Threat Hunting
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/hunt` | Execute hunting query (body: `{"query": "...", "limit": 100}`) |

### Live Response
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/liveresponse/agents` | List agents with active live response sessions |
| POST | `/api/v1/liveresponse/command` | Send command to agent (body: `{"agent_id", "action", "args", "timeout"}`) |

### Vulnerabilities
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/vulnerabilities` | Query all vulnerabilities (filters: agent_id, severity) |
| GET | `/api/v1/agents/:id/packages` | List installed packages for an agent |
| GET | `/api/v1/agents/:id/vulnerabilities` | Vulnerabilities + stats for an agent |

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
