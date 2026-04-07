## Project Overview

This is an AI generated overview of the project.

TraceGuard is a self-hosted, open-source Endpoint Detection & Response (EDR) system for Linux. It has four components:

- **edr-agent** (Go) — eBPF-based endpoint monitor that streams events via gRPC
- **edr-backend** (Go) — gRPC ingest + REST API server backed by PostgreSQL
- **edr-ui** (Python/Flask) — Web dashboard that proxies to backend API
- **edr-admin** (Python/Flask) — Standalone admin portal for user management

## Build & Run Commands

### Agent (`edr-agent/`)
```bash
make check-deps    # Verify clang, Go 1.21+, libbpf, bpftool
make all           # Full build: vmlinux → ebpf → generate → build
make build         # Go build only (after eBPF is generated)
make run           # Build + run with sudo
make test          # Run Go tests
make lint          # Run linter
make clean         # Remove build artifacts
```
Build chain: generate `vmlinux.h` from kernel BTF → compile `.bpf.c` with clang → run `bpf2go` → build Go binary with CGO_ENABLED=1.

### Backend (`edr-backend/`)
```bash
make build         # Compile backend binary (CGO_ENABLED=0)
make run           # Build + run locally
make test          # Run Go tests
make docker-up     # Start postgres + backend via Docker Compose
make docker-down   # Stop Docker Compose
make docker-logs   # Tail backend container logs
make db-start      # Start local PostgreSQL only
make gen-certs     # Generate self-signed TLS certs
```

### UI (`edr-ui/`)
```bash
pip install flask requests
python app.py      # Serves on :5000, proxies to backend at :8080
```

### Admin (`edr-admin/`)
```bash
pip install -r requirements.txt
python app.py                  # Serves on :5001
python app.py --force-setup    # Reset all users via direct DB access
```

## Architecture

### Event Flow
```
eBPF probes (kernel) → Agent Event Bus → Local SQLite Buffer → gRPC Stream (50051)
→ Backend Ingest → PostgreSQL → Detection Engine → Alerts → REST API (8080) → Flask UI (5000)
```

The agent buffers events in SQLite when the backend is unreachable and replays them on reconnection.

### Agent Internals (`edr-agent/internal/`)
- `monitor/process|network|file|cmd|registry` — Each monitor type runs independently, publishing to the event bus
- `buffer/` — SQLite-backed offline event queue with flush interval
- `transport/` — gRPC client that streams `EventEnvelope` messages to backend
- `selfprotect/` — Watchdog and binary integrity checks
- `config/` — Viper-based YAML config with hot-reload support
- `ebpf/` — C eBPF programs hooked to execve, socket, and VFS syscalls; compiled via clang then wrapped by cilium/ebpf's bpf2go

### Backend Internals (`edr-backend/internal/`)
- `ingest/` — gRPC server implementing `EventService` (Register, StreamEvents, Heartbeat)
- `api/` — Gin HTTP router, all routes under `/api/v1/`
- `detection/` — Rule engine evaluating conditions (AND logic, operators: eq/ne/contains/startswith/regex/gt/lt/in)
- `store/` — PostgreSQL data access layer (sqlx + lib/pq)
- `users/` — JWT authentication (golang-jwt)
- `llm/` — Optional Ollama integration for AI alert explanations
- `models/` — Shared types: Agent, Event, Alert, Rule, User
- `migrate/` — Auto-applied schema migrations on startup

### Proto Definition
`edr-backend/proto/edr.proto` defines `EventService` with RPCs: `Register`, `StreamEvents`, `Heartbeat`. The agent and backend each have generated code in their respective `internal/proto/` directories.

### Detection Rules
Rules have conditions evaluated as AND with fields like `cmdline`, `username`, `tags`, `process.exe_path`, `path`, `dst_port`. Severities: 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL. Rules support threshold-based alerting and backtesting.

## Key Configuration Files
- `edr-agent/config/agent.yaml` — Agent monitors, backend URL, TLS, buffer settings
- `edr-backend/config/server.yaml` — Server ports, DB connection, TLS, retention policy
- `edr-backend/deploy/docker-compose.yml` — PostgreSQL 16 + backend orchestration
- `edr-backend/deploy/Dockerfile` — Multi-stage build (golang:1.22-alpine → alpine:3.19)

## Runtime Requirements
- **Agent:** Linux kernel 5.8+, root or CAP_BPF privileges, clang, libbpf headers
- **Backend:** PostgreSQL 16 (or Docker)
- **UI/Admin:** Python 3.9+

## Ports
| Service | Port |
|---------|------|
| gRPC (agent↔backend) | 50051 |
| REST API (backend) | 8080 |
| Web UI | 5000 |
| Admin portal | 5001 |
| PostgreSQL | 5432 |
