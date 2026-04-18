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
