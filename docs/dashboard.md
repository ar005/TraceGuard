# Dashboard (edr-ui-new) Documentation

The TraceGuard dashboard is a Next.js 16 analyst-facing web application. It provides a command-center interface for monitoring endpoints, investigating alerts, hunting threats, operating SOAR playbooks, managing canary tokens, detecting data exfiltration, and running scheduled tasks on remote agents.

> **Important:** This application uses Next.js 16 with React 19. APIs and conventions may differ from Next.js 13/14 training data. Read `node_modules/next/dist/docs/` before writing code here. See `edr-ui-new/AGENTS.md`.

## Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| **Next.js** | 16.x | React framework with App Router |
| **React** | 19.x | UI library |
| **Tailwind CSS** | v4 | Utility-first CSS framework (with `@tailwindcss/postcss`) |
| **Recharts** | 3.x | Charting library for dashboard visualizations |
| **Lucide React** | 0.577+ | Icon library |
| **next-themes** | 0.4.x | Theme management (light/dark/custom) |
| **clsx + tailwind-merge** | — | Conditional class name utilities |
| **TypeScript** | 5.x | Type-safe development |

## Setup and Running

### Prerequisites

- Node.js 18+
- A running TraceGuard backend instance on port 8080

### Install and Build

```bash
cd edr-ui-new
npm install
npm run build
```

### Development Mode

```bash
npm run dev
# Starts on http://localhost:5002
```

### Production Mode

```bash
npm run build
npm start -- -p 5002 -H 0.0.0.0
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_BACKEND_URL` | _(empty — proxy mode)_ | Backend REST API URL. **Proxy mode (recommended):** leave unset; `next.config.ts`'s `rewrites()` proxies `/api/*` to the backend on the same origin. **Direct mode:** set to `https://your-backend-host` and the browser will talk to the backend directly (requires backend-side CORS). |
| `NEXT_PUBLIC_ENVIRONMENT` | _(unset)_ | Operator-controlled flag. When set to `prod`, the dashboard logs a console warning if `NEXT_PUBLIC_BACKEND_URL` is also unset (catches a broken-production-deploy case). Anything else (or unset) is treated as dev/staging — no warning. Not tied to `NODE_ENV`, which `npm run build && npm start` always sets to `production` even on a developer's laptop. |

> **Inlining**: `NEXT_PUBLIC_*` env vars are baked into the JS bundle at `npm run build` time. Setting them in your shell **after** `npm run build` has no effect — set them before the build or use `.env.local`.

## Authentication Flow

1. Users navigate to `/login` and enter username/password.
2. The login page calls `POST /api/v1/auth/login` on the backend (via the proxy when `NEXT_PUBLIC_BACKEND_URL` is unset, or directly when it's set).
3. On success the backend sets an `httpOnly` session cookie. The client stores no JWT itself; `AuthProvider` hydrates by calling `GET /api/v1/me` to read the current user.
4. All subsequent API requests are made through `src/lib/api-client.ts`, which sends the cookie automatically (`credentials: "include"`).
5. On HTTP 401, `api-client` triggers a single navigation to `/login` (deduped via a module-level `redirecting` flag, using `window.location.replace` so the failed page doesn't sit on the back stack). The `/api/v1/me` probe is exempt — that 401 is expected during hydration and `AuthGuard` handles the redirect via `router.replace`, avoiding a fight between the two paths.

### Deployment modes

The api-client and `next.config.ts` support two deployment shapes:

- **Proxy mode (recommended)**: `NEXT_PUBLIC_BACKEND_URL` unset → `BASE = ""`. All requests become same-origin relative URLs (`/api/v1/...`) and `next.config.ts`'s `rewrites()` block proxies them to the backend. httpOnly cookies and CSP `connect-src 'self'` work cleanly. SSO redirects from the login page also resolve relative, so SSO works for end users on any host.
- **Direct mode**: `NEXT_PUBLIC_BACKEND_URL=https://backend.example.com` → `BASE` is absolute. The browser talks to the backend directly. Requires CORS configured on the backend and a CSP that allowlists the backend host. Only choose this when the Next.js proxy isn't viable.

## Pages

The dashboard has 50+ authenticated pages organized into five sidebar sections plus a login page. The sidebar is collapsible (240px expanded, 56px collapsed). Collapse state is saved in `localStorage` under `sidebar-collapsed`. When collapsed on phones, it auto-collapses on navigation.

### Core

| Page | Route | Description |
|---|---|---|
| **Dashboard** | `/` | Overview with stat cards, alert severity chart, recent alerts, online agents. Supports time range selection: 1h, 6h, 24h, 7d. |
| **Alerts** | `/alerts` | Paginated alert list. Status filters (All/Open/Investigating/Closed) and severity filters. Slide-out detail drawer with timeline, process tree, AI explanation, triage. |
| **Incidents** | `/incidents` | Correlated alert groups. Shows severity, alert count, hostnames, MITRE IDs. Detail drawer with status management, notes, related alerts. |
| **Cases** | `/cases` | Analyst investigation cases. Supports create/update/close, linking alerts, case notes, and AI summarisation via `POST /cases/:id/summarise`. |
| **Agents** | `/agents` | Registered agents with online/offline status, hostname, IP, OS, version, last-seen. Click to open agent detail page. |
| **Agent Detail** | `/agents/[id]` | Tabs: Overview (metadata, tags), Events (filtered stream), Alerts, Packages, Scheduled Tasks. |

### Investigate

| Page | Route | Description |
|---|---|---|
| **Events** | `/events` | Event stream with type filters and live SSE mode. Clicking an event opens a detail drawer with full JSON payload and optional process tree viewer. |
| **Commands** | `/commands` | Filtered view of CMD_EXEC events. |
| **Browser Activity** | `/browser` | BROWSER_REQUEST events from the browser extension. Filters: agent, domain, status code, resource type. |
| **USB Devices** | `/usb` | USB device inventory and connect/disconnect history. |
| **Email Threats** | `/email-threats` | Events from email client monitors (email client spawning shells, suspicious downloads). |
| **Hunt** | `/hunt` | SQL-like threat hunting query editor. 37+ example queries. Ctrl+Enter to execute. |
| **Search** | `/search` | Full-featured event search with date range, agent, hostname filters. |

### Detect

| Page | Route | Description |
|---|---|---|
| **Rules** | `/rules` | Detection rule management. Toggle enable/disable, view conditions, threshold settings, MITRE links. Includes a visual rule builder. |
| **YARA Rules** | `/yara` | YARA rule management. List, create, edit, delete YARA rules with rule text editor. |
| **Suppressions** | `/suppressions` | Suppression rule management. Creates rules to filter noise from detection. |
| **IOCs** | `/iocs` | Indicators of Compromise. Supports type filters, bulk import, feed sync. |
| **IOC Feeds** | `/ioc-feeds` | Custom IOC feed management (URL-based feeds). |
| **DNS Intelligence** | `/dns` | DNS query analytics. Shows DNS events from all agents and top queried domains chart. Queries `GET /api/v1/dns/events` and `GET /api/v1/dns/stats`. |
| **Vulnerabilities** | `/vulnerabilities` | CVEs detected on agent endpoints with severity, package, and fixed-version details. |
| **MITRE Heatmap** | `/mitre-heatmap` | Visual heatmap of MITRE ATT&CK techniques covered by enabled detection rules. |

### XDR

| Page | Route | Description |
|---|---|---|
| **Sources** | `/sources` | XDR data source connector management. Create/update/delete connectors. |
| **Network Events** | `/network-events` | Network flow events from XDR network sources. |
| **Cloud Events** | `/cloud-events` | Cloud API call events (AWS CloudTrail, etc.). |
| **Identity Events** | `/identity-events` | Authentication and identity events from IdP sources. |
| **User Risk** | `/user-risk` | Identity graph with user risk scores and top risky users. |
| **Host Risk** | `/host-risk` | Agent risk scores and top risky endpoints. |
| **UEBA Timeline** | `/ueba` | User/Entity Behavior Analytics timeline for a selected user. |
| **Asset Inventory** | `/asset-inventory` | Unified endpoint + cloud + network device registry. |
| **Containers** | `/containers` | Container inventory with runtime, image, pod, namespace. |
| **Data Exfiltration** | `/data-exfil` | DLP/exfil signals dashboard. Shows USB bulk transfers > 50 MB, outbound transfers > 100 MB, and cloud uploads > 25 MB. Queries `GET /api/v1/dlp/events` and `GET /api/v1/dlp/stats`. |

### Operate

| Page | Route | Description |
|---|---|---|
| **Live Response** | `/live-response` | Remote command execution terminal. Select an online agent, run commands, view streamed output. Supports command history. |
| **Playbooks** | `/playbooks` | SOAR playbook management. Create/edit playbooks with trigger filters and actions (Slack, PagerDuty, email, isolate, block IP, disable identity). |
| **Playbook Runs** | `/playbooks/runs` | Execution history for all playbook runs with status and actions log. |
| **Auto-Remediation** | `/auto-remediation` | Automatic remediation rules that trigger on rule/severity match. |
| **Compliance** | `/compliance` | Compliance framework coverage (MITRE ATT&CK technique coverage by detection rules). |
| **Canary Tokens** | `/canary` | Deception token management. Create tokens of type credential, file, url, or dns. Shows trigger history. Each triggered canary fires a severity-5 alert via the unauthenticated webhook `POST /api/canary/trigger/:token`. |
| **Scheduled Tasks** | `/scheduled-tasks` | Global scheduled task view across all agents. Create, edit, trigger, and view execution history. Tasks are delivered via the heartbeat mechanism. |
| **Auto-Case Policies** | `/autocase` | Policies that automatically create investigation cases when alert criteria match. |
| **Response Actions** | `/response-actions` | Audit trail for all response actions (isolate, block IP, disable identity). |
| **Export / SIEM** | `/export` | Configure SIEM/notification export destinations (Slack, PagerDuty, webhook, syslog/CEF, email). |
| **Reports** | `/reports` | Generate and download CSV/JSON reports for alerts, events, and agents. |
| **Metrics** | `/metrics` | Prometheus metrics visualization: event ingest rates, alert counts, agent connectivity, API latency, detection timing. |
| **Settings** | `/settings` | Theme selection, LLM provider settings (Ollama, OpenAI, Anthropic, Gemini), data retention policies. |

---

## Visual Rule Builder

The Rules page includes a visual rule builder accessible via the "New Rule" button:

- **Metadata**: Name, description, severity, author, MITRE technique IDs
- **Event type selection**: Multi-select for target event types
- **Condition builder**: Add/remove conditions with field, operator, and value
- **Rule type**: Match or threshold toggle
- **Threshold settings**: Count, window (seconds), group-by field
- **Preview**: Resulting rule JSON before submission
- **Validation**: Client-side validation of required fields

---

## Design System

### Color Architecture

Uses **OKLCH color space** for perceptually uniform colors. All colors are defined as CSS custom properties in `globals.css`.

**Semantic color tokens:**

| Token | Purpose |
|---|---|
| `--primary` | Brand accent (warm amber `#e8a83e` in default theme) |
| `--destructive` | Error/danger states |
| `--success` | Success indicators |
| `--warning` | Warning states |
| `--info` | Informational elements |

**Severity palette:**

| Token | Severity |
|---|---|
| `--severity-critical` | Red (OKLCH 0.55 0.22 25) |
| `--severity-high` | Orange (OKLCH 0.60 0.18 40) |
| `--severity-medium` | Amber (OKLCH 0.70 0.15 75) |
| `--severity-low` | Blue (OKLCH 0.55 0.15 240) |
| `--severity-info` | Gray (OKLCH 0.52 0.01 240) |

### Typography

| Font | CSS Variable | Usage |
|---|---|---|
| **DM Sans** | `--font-dm-sans` | Body text, UI labels |
| **Space Grotesk** | `--font-space-grotesk` | Headings, page titles |
| **JetBrains Mono** | `--font-jetbrains-mono` | Code, timestamps, IDs |

### Themes

7 themes selectable from the Settings page:

| Theme | Base | Primary Color |
|---|---|---|
| **Light** | Light | Warm amber `#e8a83e` |
| **Dark** | Dark | Warm amber `#e8a83e` |
| **Midnight** | Dark | Steel blue `#4d8fef` |
| **Ember** | Dark | Burnt orange `#f37216` |
| **Arctic** | Light | Cool blue `#2e8bc0` |
| **Verdant** | Dark | Forest green `#2dbd6e` |
| **Rose** | Dark | Hot pink `#e3499a` |

### Animations

- `animate-fade-in` — Fade in with slight upward slide (0.2s)
- `animate-shimmer` — Gradient sweep for loading skeletons
- `animate-pulse-ring` — Pulsing green ring for live status indicators
- `animate-spin-slow` — Slow rotation (3s) for loading spinners

---

## Live Events via SSE

The Events page supports real-time event streaming through Server-Sent Events. The `useSSE` hook manages the connection. SSE tickets are obtained via `POST /api/v1/auth/sse-ticket`, then the `EventSource` connects to `GET /api/v1/events/stream?token=<ticket>`. Incoming events are prepended to the event list, capped at 200 events.

---

## Process Tree Viewer

Available in Alert and Event detail drawers for PROCESS_EXEC, PROCESS_FORK, and CMD_EXEC events.

- Fetches from `GET /api/v1/processes/{pid}/tree?agent_id={id}&depth=5`
- Renders a hierarchical tree with indentation
- Root process highlighted in primary color

---

## AI Alert Explanation

Available in the Alert detail drawer via `POST /api/v1/alerts/:id/explain`. Uses the configured LLM provider (Ollama, OpenAI, Anthropic, or Gemini).
