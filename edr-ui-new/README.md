# TraceGuard — Open Endpoint Detection & Response

A full-stack EDR (Endpoint Detection & Response) platform for Linux, built as a monorepo with five components.

## Architecture

```
Endpoint                          Server                         Analyst
────────                          ──────                         ───────
edr-agent (Go + eBPF)  ──gRPC──> edr-backend (Go)  ──REST──>  edr-ui3 (Next.js)
  - Process monitor                - Event ingest               - Dashboard
  - Network monitor                - Detection engine            - Events + live SSE
  - File monitor                   - Alert correlation           - Alerts + AI explain
  - Auth/login monitor             - IOC matching                - Search + Hunt
  - Command monitor                - SSE live push               - Rules + Suppressions
  - Browser monitor ◄──HTTP──     - REST API (:8080)            - IOCs + Vulns
       ▲                           - gRPC (:50051)               - Live Response
       │                           - PostgreSQL                  - Settings + Themes
  Browser Extension
  (Chrome / Firefox)
```

## Components

| Component | Language | Port(s) | Purpose |
|-----------|----------|---------|---------|
| **edr-agent** | Go + eBPF | :9999 (browser) | Endpoint agent: eBPF probes for process/network/file/auth events, browser extension receiver |
| **edr-backend** | Go | :8080 (REST), :50051 (gRPC) | Ingests events, stores in PostgreSQL, runs detection rules, exposes REST API |
| **edr-ui3** | Next.js 16 / React 19 | :5002 | Analyst dashboard (primary) — Impeccable design, 16 pages, 7 themes |
| **edr-ui** | Python/Flask | :5000 | Legacy analyst UI |
| **edr-admin** | Python/Flask | :5001 | Admin portal for user/key management |
| **extensions** | JavaScript | — | Chrome (Manifest V3) + Firefox (WebExtensions) browser monitoring |

## Quick Start

### Prerequisites
- Linux with kernel >= 5.8 (for eBPF)
- Go 1.21+
- Node.js 18+
- PostgreSQL 14+
- Docker (optional, for backend + postgres)

### 1. Start Backend + Database
```bash
cd edr-backend
make docker-up          # starts backend + postgres via docker-compose
# OR manually:
make build && make run  # requires local postgres
```

### 2. Start the Dashboard (edr-ui3)
```bash
cd edr-ui3
npm install
npm run build           # production build
npm start -- -p 5002 -H 0.0.0.0

# or for development:
npm run dev             # http://localhost:5002
```

Create a `.env.local` file if accessing from a remote machine:
```
NEXT_PUBLIC_BACKEND_URL=http://YOUR_SERVER_IP:8080
```

### 3. Start the Agent
```bash
cd edr-agent
make all                # check-deps → vmlinux → ebpf → generate → build
sudo ./edr-agent --config config/agent.yaml
```

### 4. Install Browser Extension (optional)
**Chrome**: `chrome://extensions/` → Developer mode → Load unpacked → select `extensions/chrome/`

**Firefox**: `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → select `extensions/firefox/manifest.json`

## What's Been Built

### Agent Features
- **eBPF process monitoring** — exec, fork, exit, ptrace injection detection
- **eBPF network monitoring** — TCP/UDP connections, DNS snooping with DGA detection
- **eBPF file monitoring** — create/write/delete/rename with SHA-256 hashing
- **Auth/login monitoring** — SSH login success/failure, sudo, brute force detection
- **Command monitoring** — shell command history, reverse shell detection
- **Registry monitoring** — /etc config file changes (sudoers, cron, ssh, ld)
- **Vulnerability detection** — package inventory (dpkg/rpm), CVE matching
- **Browser monitoring** — receives BROWSER_REQUEST events from Chrome/Firefox extension via localhost HTTP receiver (`:9999`)
- **Local SQLite buffer** — survives network outages, replays on reconnect
- **Self-protection** — watchdog process, binary immutability

### Backend Features
- **gRPC ingest** — streaming events from agents with heartbeat/registration
- **Detection engine** — match + threshold rules, regex caching, IOC matching
- **30+ seeded detection rules** — webshell, ptrace injection, memfd exec, brute force, C2 beaconing, DGA domains, browser phishing rules
- **Alert correlation** — automatic incident grouping by agent + time window
- **IOC management** — CRUD + bulk import, threat feed sync, in-memory cache
- **SSE broker** — real-time event push to browser clients
- **LLM integration** — Ollama/OpenAI/Anthropic/Gemini for alert explanation
- **Live response** — remote command execution on agents
- **JWT auth** — login, API keys, role-based access
- **Auto-migrations** — schema applied at startup

### Dashboard (edr-ui3) — 16 Pages
| Page | Features |
|------|----------|
| **Dashboard** | KPI stat cards, severity bar chart, recent alerts, online agents |
| **Alerts** | Status/severity filters, detail panel with MITRE ATT&CK, AI explain, related events |
| **Events** | Type filters (Process, CMD, Network, File, Browser, DNS), live SSE toggle, detail drawer |
| **Search** | Full-text search, quick filter chips, advanced filters (agent, hostname, time range) |
| **Commands** | CMD_EXEC event list with filter |
| **Agents** | Table with online status, hostname, IP, OS, version, last seen |
| **Incidents** | Status filters, detail drawer with status update, notes, related alerts |
| **Hunt** | SQL-like query textarea with examples, Ctrl+Enter to run |
| **Rules** | Toggle enabled, delete, reload engine, expand for conditions/threshold |
| **Suppressions** | Toggle, delete, create with event type chips + conditions JSON |
| **IOCs** | Stats bar, type filters, add/bulk-import/sync-feeds with spinner, delete |
| **Vulnerabilities** | Severity filters, CVE table with NVD links, search |
| **Live Response** | Agent selector, terminal UI with command history (up/down arrows) |
| **Settings** | 7 color themes, data retention, LLM provider config + test connection |
| **Login** | Centered form with JWT authentication |

### Browser Extension
- **Chrome** (Manifest V3) + **Firefox** (WebExtensions)
- Captures: full URL, status code, method, redirect chains, referrer, server IP, response headers
- Filters noise (static assets, CDN, browser-internal domains)
- Batches events and POSTs to agent's localhost endpoint
- Popup UI with capture/send/error stats, pause/resume, agent URL config
- 5 seeded phishing detection rules in backend

### Design
- Built following [Impeccable](https://github.com/pbakaus/impeccable) frontend design skills
- OKLCH-based color system with blue-tinted neutrals
- Typography: DM Sans (body), Space Grotesk (headings), JetBrains Mono (data)
- 7 themes: Light, Dark, Midnight, Ember, Arctic, Verdant, Rose
- Collapsible sidebar with tooltips, active indicator, localStorage persistence
- No glassmorphism, no gradient text, no cyan-on-dark AI aesthetics

## Project Structure

```
edr/
├── edr-agent/              # Go + eBPF endpoint agent
│   ├── cmd/agent/          # Entry point
│   ├── ebpf/               # eBPF C source (process, network, file)
│   ├── internal/
│   │   ├── agent/          # Core lifecycle
│   │   ├── monitor/        # process, network, file, auth, cmd, registry, vuln, browser
│   │   ├── events/         # Event bus
│   │   ├── transport/      # gRPC client
│   │   ├── buffer/         # SQLite offline buffer
│   │   └── config/         # Viper YAML config
│   └── pkg/types/          # Canonical event types (shared)
├── edr-backend/            # Go REST + gRPC backend
│   ├── cmd/server/         # Entry point
│   ├── internal/
│   │   ├── api/            # Gin REST API (50+ endpoints)
│   │   ├── ingest/         # gRPC event ingestion
│   │   ├── detection/      # Rule engine (match + threshold)
│   │   ├── store/          # PostgreSQL data layer
│   │   ├── sse/            # Server-sent events broker
│   │   ├── llm/            # LLM integration
│   │   └── iocfeed/        # Threat feed syncer
│   └── proto/              # gRPC proto definitions
├── edr-ui3/                # Next.js 16 analyst dashboard (primary)
│   └── src/
│       ├── app/            # 16 page routes
│       ├── components/     # Layout + shared components
│       ├── hooks/          # useApi, useSSE
│       ├── lib/            # API client, auth, utils
│       └── types/          # TypeScript interfaces
├── edr-ui/                 # Legacy Flask analyst UI
├── edr-admin/              # Flask admin portal
├── extensions/             # Browser extensions
│   ├── chrome/             # Manifest V3
│   └── firefox/            # WebExtensions
├── COMMIT_LOG.md           # Per-commit changelog
└── TODO.md                 # Roadmap + completed items
```

## Environment Variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `NEXT_PUBLIC_BACKEND_URL` | edr-ui3 | Backend API URL (default: `http://localhost:8080`) |
| `EDR_BACKEND` | edr-ui, edr-admin | Backend URL for Flask UIs |
| `EDR_JWT_SECRET` | edr-backend | JWT signing key |
| `EDR_DATABASE_*` | edr-backend | PostgreSQL connection |
| `OLLAMA_ENABLED` | edr-backend | Enable LLM alert explanation |

## Ports

| Port | Service |
|------|---------|
| 5002 | edr-ui3 (Next.js dashboard) |
| 5000 | edr-ui (Flask legacy) |
| 5001 | edr-admin (Flask admin) |
| 8080 | edr-backend REST API |
| 50051 | edr-backend gRPC |
| 9999 | edr-agent browser monitor (localhost only) |
