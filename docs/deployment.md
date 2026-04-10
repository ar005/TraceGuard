# Deployment Guide

This guide covers deploying the full TraceGuard platform: backend, dashboard, agents, and browser extensions.

## System Requirements

### Backend Server

| Requirement | Minimum |
|---|---|
| OS | Linux (any distribution) |
| Go | 1.21+ (1.22+ recommended) |
| PostgreSQL | 14+ (16 recommended) |
| RAM | 2 GB |
| Docker (optional) | 20.10+ with Compose v2 |

### Agent Endpoints

| Requirement | Minimum |
|---|---|
| OS | Linux |
| Kernel | 5.8+ (for eBPF support) |
| Go | 1.21+ (for building from source) |
| clang | 14+ (for eBPF compilation) |
| libbpf-dev | Required for eBPF |

### Dashboard

| Requirement | Minimum |
|---|---|
| Node.js | 18+ |
| npm | 9+ |

## Network Ports

| Port | Protocol | Component | Purpose |
|---|---|---|---|
| **8080** | TCP (HTTP) | edr-backend | REST API for dashboard and admin UIs |
| **50051** | TCP (gRPC) | edr-backend | Agent event streaming and heartbeats |
| **5000** | TCP (HTTP) | edr-ui (legacy) | Legacy Flask analyst UI |
| **5001** | TCP (HTTP) | edr-admin (legacy) | Legacy Flask admin portal |
| **5002** | TCP (HTTP) | edr-ui3 | Next.js dashboard |
| **5432** | TCP | PostgreSQL | Database (backend only, not exposed externally) |
| **9999** | TCP (HTTP) | edr-agent | Browser extension event receiver (localhost only) |

## Deployment Order

### Step 1: PostgreSQL Setup

#### Option A: Docker

```bash
docker run -d \
  --name edr-postgres \
  -e POSTGRES_DB=edr \
  -e POSTGRES_USER=edr \
  -e POSTGRES_PASSWORD=<strong-password> \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine
```

#### Option B: System PostgreSQL

```bash
sudo apt install postgresql-16
sudo -u postgres createuser edr
sudo -u postgres createdb -O edr edr
sudo -u postgres psql -c "ALTER USER edr PASSWORD '<strong-password>';"
```

Schema migrations run automatically when the backend starts. No manual SQL needed.

### Step 2: Backend

#### Option A: Build from Source

```bash
cd edr-backend
make build

# Configure via environment or config/server.yaml
export EDR_DATABASE_HOST=localhost
export EDR_DATABASE_PORT=5432
export EDR_DATABASE_NAME=edr
export EDR_DATABASE_USER=edr
export EDR_DATABASE_PASSWORD=<strong-password>
export EDR_DATABASE_SSL_MODE=disable
export EDR_JWT_SECRET=<long-random-secret>

./edr-backend
```

The backend starts the REST API on `:8080` and gRPC server on `:50051`.

#### Option B: Docker Compose

```bash
cd edr-backend/deploy

# Edit docker-compose.yml to set strong passwords
# Then:
docker compose up -d
```

The provided `docker-compose.yml` starts both PostgreSQL and the backend. Services defined:

- **postgres**: PostgreSQL 16 Alpine with health check, persistent volume `postgres_data`.
- **backend**: TraceGuard backend built from `deploy/Dockerfile`, depends on healthy Postgres. Exposes ports 8080 and 50051.

#### TLS Certificates

For production, generate TLS certificates:

```bash
cd edr-backend
make gen-certs
# Creates self-signed certs in deploy/certs/
```

Mount the certs directory into the container at `/etc/edr/tls` (already configured in docker-compose.yml).

### Step 3: Initial Setup (First User Creation)

Before logging in, create the first admin user:

```bash
curl -X POST http://localhost:8080/api/v1/setup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-secure-password",
    "email": "admin@example.com"
  }'
```

This endpoint only works when no users exist in the database. It creates an admin-role user and returns a JWT token.

### Step 4: Dashboard (edr-ui3)

```bash
cd edr-ui3
npm install
npm run build

# Set the backend URL if not localhost:8080
export NEXT_PUBLIC_BACKEND_URL=http://your-backend-host:8080

npm start -- -p 5002
```

The dashboard is accessible at `http://your-server:5002`.

### Step 5: Agent Deployment

Build the agent on a machine with the required kernel and toolchain:

```bash
cd edr-agent
make all    # check-deps -> vmlinux -> ebpf -> generate -> build
```

This produces the `edr-agent` binary. Deploy it to endpoint machines:

```bash
# Copy to endpoint
scp edr-agent user@endpoint:/opt/edr/
scp config/agent.yaml user@endpoint:/opt/edr/config/

# On the endpoint, edit config/agent.yaml:
# Set backend_addr to your backend's gRPC address (e.g., "your-backend:50051")

# Run (requires root for eBPF)
sudo /opt/edr/edr-agent
```

### Step 6: Browser Extension

Deploy to analyst workstations. See [browser-extension.md](browser-extension.md) for detailed installation instructions.

- **Chrome**: Load unpacked from `extensions/chrome/`.
- **Firefox**: Load temporary add-on from `extensions/firefox/manifest.json`.

Ensure the agent is running on each analyst machine (the extension sends to `127.0.0.1:9999`).

## Production Considerations

### JWT Secret

Always set `EDR_JWT_SECRET` to a strong random value in production:

```bash
export EDR_JWT_SECRET=$(openssl rand -base64 48)
```

If unset, the backend generates a random ephemeral secret on each restart, which invalidates all existing sessions.

### Reverse Proxy (nginx)

Place nginx in front of the backend and dashboard:

```nginx
# /etc/nginx/sites-available/edr

# Dashboard
server {
    listen 443 ssl;
    server_name edr.example.com;

    ssl_certificate     /etc/letsencrypt/live/edr.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/edr.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Backend API
server {
    listen 443 ssl;
    server_name api.edr.example.com;

    ssl_certificate     /etc/letsencrypt/live/edr.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/edr.example.com/privkey.pem;

    # SSE requires long-lived connections
    proxy_read_timeout 86400;
    proxy_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Important: Disable proxy buffering for SSE endpoints (`/api/v1/events/stream`).

### systemd Service Files

#### Backend

```ini
# /etc/systemd/system/edr-backend.service
[Unit]
Description=TraceGuard Backend
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=edr
Group=edr
WorkingDirectory=/opt/edr/backend
ExecStart=/opt/edr/backend/edr-backend
EnvironmentFile=/opt/edr/backend/.env
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### Dashboard

```ini
# /etc/systemd/system/edr-dashboard.service
[Unit]
Description=TraceGuard Dashboard (Next.js)
After=network.target edr-backend.service

[Service]
Type=simple
User=edr
Group=edr
WorkingDirectory=/opt/edr/dashboard
ExecStart=/usr/bin/npm start -- -p 5002
Environment=NEXT_PUBLIC_BACKEND_URL=http://localhost:8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### Agent

```ini
# /etc/systemd/system/edr-agent.service
[Unit]
Description=TraceGuard Agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/edr/edr-agent
WorkingDirectory=/opt/edr
Restart=always
RestartSec=5
# Agent needs root for eBPF
User=root

[Install]
WantedBy=multi-user.target
```

## Environment Variables Reference

### Backend (edr-backend)

| Variable | Default | Description |
|---|---|---|
| `EDR_DATABASE_HOST` | `localhost` | PostgreSQL host |
| `EDR_DATABASE_PORT` | `5432` | PostgreSQL port |
| `EDR_DATABASE_NAME` | `edr` | Database name |
| `EDR_DATABASE_USER` | `edr` | Database user |
| `EDR_DATABASE_PASSWORD` | — | Database password |
| `EDR_DATABASE_SSL_MODE` | `disable` | PostgreSQL SSL mode |
| `EDR_SERVER_HTTP_ADDR` | `:8080` | REST API listen address |
| `EDR_SERVER_GRPC_ADDR` | `:50051` | gRPC listen address |
| `EDR_JWT_SECRET` | (random) | JWT signing key |
| `EDR_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `EDR_LOG_FORMAT` | `text` | Log format: text or json |
| `OLLAMA_ENABLED` | `false` | Enable LLM alert explanation |
| `OLLAMA_MODEL` | — | Ollama model name for explanations |

### Dashboard (edr-ui3)

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_BACKEND_URL` | `http://localhost:8080` | Backend API URL |

### UIs (Legacy Flask)

| Variable | Default | Description |
|---|---|---|
| `EDR_BACKEND` | `http://localhost:8080` | Backend URL for edr-ui and edr-admin |

## Docker Deployment

The `edr-backend/deploy/docker-compose.yml` provides a ready-to-use deployment:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: edr
      POSTGRES_USER: edr
      POSTGRES_PASSWORD: edr      # Change in production
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  backend:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      EDR_DATABASE_HOST: postgres
      EDR_DATABASE_PORT: 5432
      EDR_DATABASE_NAME: edr
      EDR_DATABASE_USER: edr
      EDR_DATABASE_PASSWORD: edr  # Match postgres service
      EDR_JWT_SECRET: change-this-to-a-long-random-secret-in-production
    ports:
      - "50051:50051"
      - "8080:8080"
    volumes:
      - ./config:/app/config:ro
      - ./certs:/etc/edr/tls:ro

volumes:
  postgres_data:
```

To start:

```bash
cd edr-backend/deploy
docker compose up -d
```

To stop:

```bash
docker compose down
```

To rebuild after code changes:

```bash
docker compose up -d --build
```

## Monitoring the Deployment

### Health Endpoint

The backend exposes a health check:

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### Agent Heartbeats

Agents send periodic heartbeats via gRPC. The backend marks agents as online/offline based on heartbeat recency. Monitor agent status via:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/agents
```

Each agent includes `is_online` and `last_seen` fields.

### Dashboard Indicators

The dashboard home page shows:
- **Online Agents** count with live ping animations
- **Open Alerts** count
- **Total Events** in the selected time range

## Backup

### PostgreSQL Dumps

Regular database backups are essential:

```bash
# Full dump
pg_dump -U edr -h localhost edr > edr_backup_$(date +%Y%m%d).sql

# Compressed
pg_dump -U edr -h localhost -Fc edr > edr_backup_$(date +%Y%m%d).dump

# Restore
pg_restore -U edr -h localhost -d edr edr_backup.dump
```

### Automated Backup (cron)

```bash
# /etc/cron.d/edr-backup
0 2 * * * edr pg_dump -U edr -h localhost -Fc edr > /opt/edr/backups/edr_$(date +\%Y\%m\%d).dump
# Retain 30 days
0 3 * * * edr find /opt/edr/backups -name "edr_*.dump" -mtime +30 -delete
```

### Data Retention

The backend supports configurable data retention (set in the `settings` table):
- **Events**: Default 30 days
- **Alerts**: Default 90 days

These can be adjusted via the Settings page in the dashboard.
