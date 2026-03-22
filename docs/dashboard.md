# Dashboard (edr-ui3) Documentation

The TraceGuard dashboard is a modern, analyst-facing web application codenamed **TRACEGUARD**. It provides a command-center interface for monitoring endpoints, investigating alerts, hunting for threats, and managing detection rules.

## Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| **Next.js** | 16.2.1 | React framework with App Router |
| **React** | 19.2.4 | UI library |
| **Tailwind CSS** | v4 | Utility-first CSS framework (with `@tailwindcss/postcss`) |
| **Recharts** | 3.8.0 | Charting library for dashboard visualizations |
| **Lucide React** | 0.577.0 | Icon library |
| **next-themes** | 0.4.6 | Theme management (light/dark/custom) |
| **clsx + tailwind-merge** | — | Conditional class name utilities |
| **TypeScript** | 5.x | Type-safe development |

## Setup and Running

### Prerequisites

- Node.js 18+
- A running TraceGuard backend instance on port 8080

### Install and Build

```bash
cd edr-ui3
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
npm start -- -p 5002
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_BACKEND_URL` | `http://localhost:8080` | Backend REST API URL. Set this when the backend runs on a different host or port. |

The API client (`src/lib/api-client.ts`) reads this variable at runtime on the client side.

## Authentication Flow

1. Users navigate to `/login` and enter username/password.
2. The login page calls `POST /api/v1/login` on the backend.
3. On success, the JWT token is stored in `localStorage` under the key `edr_token`, and the user object under `edr_user`.
4. All subsequent API requests include the token as a `Bearer` token in the `Authorization` header.
5. If any API call returns HTTP 401, the client clears the stored token/user and redirects to `/login`.
6. The login page branded as "TRACEGUARD" with the BookOpen icon and "Sign in to the command center" prompt.

## Pages

The dashboard includes 14 authenticated pages plus a login page. The sidebar organizes them into four navigation sections.

### Main

| Page | Route | Description |
|---|---|---|
| **Dashboard** | `/` | Overview page with stat cards (Total Events, Open Alerts, Online Agents, Active Rules), an "Alerts by Severity" horizontal bar chart (Recharts), a recent alerts list, and an online agents panel with live ping indicators. Supports time range selection: 1h, 6h, 24h, 7d. |
| **Alerts** | `/alerts` | Paginated alert list with status filters (All, Open, Investigating, Closed) and severity filters (Critical, High, Medium, Low, Info). Each alert row shows severity dot, title, rule name, hostname, hit count, MITRE ATT&CK IDs, status badge, and first-seen time. Clicking an alert opens a slide-out detail drawer. |
| **Events** | `/events` | Event stream with type filters (All, Process, Command, Network, File, Browser, DNS). Supports a live mode toggle that connects to SSE for real-time event streaming. Includes text search. Clicking an event opens a detail drawer showing full JSON payload and an optional process tree viewer. |
| **Commands** | `/commands` | Filtered view of CMD_EXEC events. Lists commands with timestamp, hostname, and the command line. Includes a text filter for searching specific commands. |
| **Agents** | `/agents` | Table of registered agents showing online/offline status (color-coded dot), hostname, IP address, OS and version, agent version, and last-seen time. |

### Investigation

| Page | Route | Description |
|---|---|---|
| **Search** | `/search` | Full-featured event search with a search bar, quick filter chips (Recent Alerts, Process Events, Network Events, File Events, Browser Events, Commands), and advanced filters (Agent ID, Hostname, Since, Until date range). Results displayed in a paginated table. |
| **Incidents** | `/incidents` | Incident management page. Incidents are auto-correlated groups of related alerts. Shows severity, title, status, alert count, hostnames, MITRE ATT&CK IDs, and last-seen time. Detail drawer includes status management, investigation notes (with save), and a list of related alerts. |
| **Hunt** | `/hunt` | Threat hunting interface with a SQL-like query editor. Includes example queries (e.g., "Process executions of curl", "External network connections", "Browser form submissions"). Supports Ctrl+Enter to execute. Results displayed in a table with event type, time, host, and summary. |

### Detection

| Page | Route | Description |
|---|---|---|
| **Rules** | `/rules` | Detection rule management. Lists all rules with toggle switches for enable/disable, name, description, severity, event types, rule type (match/threshold), MITRE IDs, and author. Expandable rows show full conditions JSON, threshold settings (count, window, group-by), and MITRE ATT&CK links. Includes a "Reload Rules" button and per-rule delete. |
| **Suppressions** | `/suppressions` | Suppression rule management for filtering noise. Lists suppression rules with enable/disable toggles, name, conditions, event types, hit count, and last hit time. Supports creating new suppression rules with event type selection. |
| **IOCs** | `/iocs` | Indicators of Compromise management. Supports type filters (IP, Domain, Hash). Lists IOCs with type badge, value, source, severity, hit count, tags, and expiry. Supports adding new IOCs (IP, domain, hash_sha256, hash_md5) and syncing feeds. |
| **Vulnerabilities** | `/vulnerabilities` | Vulnerability scanner results. Lists CVEs detected on agent endpoints with severity badges (Critical, High, Medium, Low, Unknown), CVE ID, package name, installed version, fixed version, and host. |

### Operations

| Page | Route | Description |
|---|---|---|
| **Live Response** | `/live-response` | Remote command execution terminal. Select an online agent from a dropdown, then type commands in a terminal-style interface. Commands are sent to the agent and responses displayed in a scrollable output area. Supports command history (up/down arrows). |
| **Settings** | `/settings` | Application configuration including theme selection, LLM provider settings (Ollama, OpenAI, Anthropic, Gemini), and data retention policies. |

## Design System

### Color Architecture

The design system uses **OKLCH color space** for perceptually uniform colors. All colors are defined as CSS custom properties in `globals.css`.

The base palette consists of **tinted neutrals** with a blue hue (240) and low chroma (0.01), giving a subtle blue-gray tint to all neutral surfaces.

**Semantic color tokens:**

| Token | Purpose |
|---|---|
| `--primary` | Brand accent (warm amber `#e8a83e` in default theme) |
| `--destructive` | Error/danger states |
| `--success` | Success indicators |
| `--warning` | Warning states |
| `--info` | Informational elements |

**Severity palette** for alerts and rules:

| Token | Severity |
|---|---|
| `--severity-critical` | Red (OKLCH 0.55 0.22 25) |
| `--severity-high` | Orange (OKLCH 0.60 0.18 40) |
| `--severity-medium` | Amber (OKLCH 0.70 0.15 75) |
| `--severity-low` | Blue (OKLCH 0.55 0.15 240) |
| `--severity-info` | Gray (OKLCH 0.52 0.01 240) |

**Surface layers** (light mode): `--surface-0` (card), `--surface-1` (raised), `--surface-2` (elevated).

### Typography

| Font | CSS Variable | Usage |
|---|---|---|
| **DM Sans** | `--font-dm-sans` | Body text, UI labels |
| **Space Grotesk** | `--font-space-grotesk` | Headings, page titles, section headers |
| **JetBrains Mono** | `--font-jetbrains-mono` | Code, timestamps, IDs, monospace data |

### Themes

The dashboard ships with 7 themes, selectable from the Settings page. Themes are applied via `next-themes` using a combination of the `class` attribute (light/dark) and the `data-theme` attribute (for named themes).

| Theme | Base | Primary Color | Description |
|---|---|---|---|
| **Light** | Light | Warm amber `#e8a83e` | Default light theme with blue-tinted gray neutrals. Clean, professional look with high contrast. |
| **Dark** | Dark | Warm amber `#e8a83e` | Default dark theme. Deep blue-gray backgrounds (`oklch(0.14 0.015 240)`) with amber accents. |
| **Midnight** | Dark | Steel blue `#4d8fef` | Cyber-themed dark mode. Near-black backgrounds (`#0d1117`) with blue steel accents. Feels like a hacker terminal. |
| **Ember** | Dark | Burnt orange `#f37216` | Warm, fire-themed dark mode. Dark brown-tinted backgrounds (`#161110`) with vivid orange accents. |
| **Arctic** | Light | Cool blue `#2e8bc0` | Cold, clinical light theme. Pale blue-gray backgrounds (`#ebeff5`) with ice-blue primary. Feels like a medical or scientific interface. |
| **Verdant** | Dark | Forest green `#2dbd6e` | Nature-inspired dark theme. Deep green-tinted backgrounds (`#0d1510`) with emerald accents. |
| **Rose** | Dark | Hot pink `#e3499a` | Vibrant dark theme. Dark plum-tinted backgrounds (`#151013`) with rose-pink accents. |

### Animations

The CSS includes four animation utilities:

- `animate-fade-in` -- Fade in with slight upward slide (0.2s). Used on page transitions.
- `animate-shimmer` -- Gradient sweep for loading skeletons.
- `animate-pulse-ring` -- Pulsing green ring for live status indicators.
- `animate-spin-slow` -- Slow rotation (3s) for loading spinners.

### Other Design Elements

- **Dot-grid background** (`.bg-dot-grid`): Subtle dot pattern for main content areas.
- **Custom scrollbars**: 6px thin scrollbars with theme-aware colors.
- **Focus ring**: 2px solid primary color outline with 2px offset.
- **Selection**: Amber-tinted selection highlight.

## Live Events via SSE

The Events page supports real-time event streaming through Server-Sent Events (SSE).

The `useSSE` hook (`src/hooks/use-sse.ts`) manages the connection:

1. When live mode is toggled on, an `EventSource` connects to `{BACKEND_URL}/api/v1/events/stream`.
2. The JWT token is passed as a query parameter (`?token=...`).
3. Incoming events are parsed from JSON and prepended to the event list.
4. The buffer is capped at 200 events (configurable via `maxEvents`).
5. A green pulsing dot indicates active connection; gray indicates disconnected.
6. Client-side filtering by event type and search term is applied to live events.

## Process Tree Viewer

Available in both the Alerts detail drawer and the Events detail drawer for PROCESS_EXEC, PROCESS_FORK, and CMD_EXEC events.

- Loads on demand via a "View Process Tree (PID X)" button.
- Fetches from `GET /api/v1/processes/{pid}/tree?agent_id={id}&depth=5`.
- Renders a hierarchical tree with indentation using `ProcessTreeNode` components.
- Each node displays: command name, PID, username, and truncated command line.
- Root process highlighted in primary color; children in foreground color.
- Tree connector characters (`--`) shown for child processes.

## AI Alert Explanation

Available in the Alert detail drawer:

1. Click "Explain with AI" button.
2. Sends `POST /api/v1/alerts/{id}/explain` to the backend.
3. Backend uses the configured LLM provider (Ollama, OpenAI, Anthropic, or Gemini) to analyze the alert.
4. Explanation is displayed in a bordered panel with monospace formatting.
5. "Re-analyze" button available after initial explanation.
6. Requires `OLLAMA_ENABLED=true` (or equivalent LLM configuration) on the backend.

## Sidebar Navigation

The sidebar is a collapsible left panel (240px expanded, 56px collapsed):

- **Toggle**: The BookOpen icon in the header doubles as the collapse/expand toggle.
- **Brand**: "TRACEGUARD" text appears when expanded.
- **Sections**: Main, Investigation, Detection, Operations -- each with a section header visible only when expanded.
- **Active indicator**: A 3px rounded primary-colored bar on the left side of the active link.
- **Tooltips**: When collapsed, hovering over an icon shows a tooltip with the page name.
- **Persistence**: Collapse state is saved in `localStorage` under `sidebar-collapsed`.
