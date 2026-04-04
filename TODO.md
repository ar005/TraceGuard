# TraceGuard Improvement Roadmap

## Completed

- [x] **1. Add tests** — Detection engine (53 test cases, engine_test.go)
- [x] **2. Rate limiting on API** — Per-IP token bucket middleware + config + 5 tests
- [x] **3. CSRF protection on Flask UIs** — Flask-WTF CSRFProtect on both apps + all forms/AJAX
- [x] **6. Process exit events** — /proc polling watcher goroutine synthesizes PROCESS_EXIT events for tracked PIDs
- [x] **7. DNS monitoring** — Raw socket DNS snooper in network monitor emits NET_DNS events + DGA/rare-TLD detection rules (implemented in network monitor, not eBPF)
- [x] **8. Alert correlation** — Incident grouping by agent+time window (30min), auto-correlation, REST API + UI proxy
- [x] **9. Threat intel feed integration** — IOC CRUD + bulk import, in-memory cache, real-time event matching (IP/domain/hash), REST API + UI proxy
- [x] **10. Process tree reconstruction** — API + store + UI tree visualization + test script
- [x] **11. Prometheus metrics** — /metrics/prometheus endpoint, 13 metric families (events, alerts, agents, gRPC, API latency, detection timing, SSE, DB)
- [x] **12. Agent policy push** — configver atomic counter, bumped on rule/suppression changes, agents detect version change in heartbeat response
- [x] **13. Database retention jobs** — Hourly sweep, DB-configurable, startup logging
- [x] **17. File hash enrichment** — SHA256 on file events (hash worker pool + HashAfter field)
- [x] **21. Live Response Shell** — gRPC bidi stream, remote command execution, safe allowlist, session manager
- [x] **22. Network Containment** — iptables-based isolation via live response, preserve backend comms only
- [x] **23. User/Login Monitoring** — auth.log tailing, LOGIN_SUCCESS/FAILED/SUDO_EXEC events, brute force detection rules
- [x] **24. Vulnerability Detection** — Package inventory (dpkg/rpm), CVE matching, REST API + UI proxy
- [x] **25. Container/K8s Awareness** — /proc/pid/cgroup parsing, container ID + runtime detection, process enrichment
- [x] **26. Advanced Hunting Query** — SQL-like query endpoint with safety validation, POST /api/v1/hunt
- [x] **Kernel module monitoring (kmod)** — Polls /proc/modules for module load/unload, signed/unsigned detection, KERNEL_MODULE_LOAD/UNLOAD events
- [x] **USB device monitoring** — Polls /sys/bus/usb/devices for connect/disconnect, vendor/product ID, USB_CONNECT/DISCONNECT events
- [x] **Memory injection detection (memmon)** — Polls /proc/*/maps for anonymous executable regions (shellcode indicators), MEMORY_INJECT events
- [x] **Cron parsing monitor (cronmon)** — Subscribes to file events on cron paths, parses crontab content, detects suspicious entries, CRON_MODIFY events
- [x] **Named pipe monitoring (pipemon)** — Polls watched directories for FIFO files (C2 indicators), PIPE_CREATE events
- [x] **Network share monitoring (sharemount)** — Polls /proc/mounts for CIFS/NFS/SMB mounts, SHARE_MOUNT/SHARE_UNMOUNT events
- [x] **TLS SNI extraction** — Raw AF_INET socket captures ClientHello, extracts SNI domain, dedup 30s TTL, NET_TLS_SNI events
- [x] **Browser extension + monitoring** — Chrome MV3 + Firefox WebExtensions, agent HTTP receiver, BROWSER_REQUEST events, 5 phishing detection rules
- [x] **Typosquat domain detection** — Levenshtein distance + homoglyph normalization against 32 brands, built into detection engine
- [x] **Auto-quarantine files on IOC hash match** — Files matching IOC hashes automatically quarantined
- [x] **Auto-block IPs on IOC match** — iptables-based IP blocking on IOC IP match
- [x] **Per-agent IP block/unblock UI** — Agent-level IP management in dashboard
- [x] **CVE cache with NVD lookup** — Backend fetches CVE data from NVD, stores locally in cve_cache table
- [x] **Package scan trigger (Scan Now)** — UI button triggers agent package scan, waits for result, stores packages in DB
- [x] **Visual rule builder** — Drag-and-drop rule builder on the Rules page
- [x] **Agent detail page** — /agents/[id] with 4 tabs (overview, events, alerts, packages)
- [x] **USB devices page** — /usb page with device inventory and history
- [x] **Browser activity page** — /browser page with agent/browser/domain/status filters, timeline, detail panel
- [x] **Metrics page** — /metrics page with Prometheus metrics visualization
- [x] **Hunt query templates** — 37 pre-built hunting queries across all event types
- [x] **CSV/JSON export** — Export functionality on 4 pages (events, alerts, agents, hunt results)
- [x] **7 color themes** — Light, Dark, Midnight, Ember, Arctic, Verdant, Rose themes
- [x] **Batch event inserts** — Bulk event insertion for improved ingest performance

### DNS Monitoring Roadmap

#### Phase 1 — DNS Snooping (Complete)
- [x] Raw socket DNS snooper captures every DNS query with process attribution (implemented in network monitor)
- [x] Emits NET_DNS events with PID, comm, resolved domain, and resolved IPs
- [x] Matches against IOC domain list in detection engine
- [x] Backend stores and displays DNS query events in UI
- [x] DGA domain detection rule (length, digit proportion, repeating patterns)
- [x] Rare/suspicious TLD detection rule

#### Phase 2 — TLS SNI Extraction (Complete)
- [x] Raw TCP socket captures outbound port 443 ClientHello messages
- [x] Parse TLS ClientHello to extract SNI (Server Name Indication) field
- [x] Emit NET_TLS_SNI events with domain + PID attribution (via /proc/net/tcp)
- [x] Deduplication with 30s TTL cache
- [x] Detection rules: rare TLD TLS connection, beaconing to same domain

#### Phase 3 — Browser Extension (Complete)
- [x] Chrome extension (Manifest V3) using chrome.webRequest API
- [x] Firefox extension (WebExtensions) — same logic, adapted for Firefox APIs
- [x] Agent HTTP receiver — localhost-only HTTP listener accepting extension events (5 tests)
- [x] BROWSER_REQUEST event type with full URL, domain, method, status, referrer, redirect chain
- [x] 5 phishing detection rules + typosquat/lookalike domain detection (32 brands)
- [x] UI: browser activity view with agent/browser/domain/status filters
- [ ] Domain age < 30 days + user interaction (newly registered phishing site)
- [ ] Backend API for browser monitoring allowlist/blocklist management

#### Phase 4 — Browser History Polling (Fallback)
- [ ] Poll Chrome/Firefox/Edge SQLite history databases for new entries
- [ ] Emit BROWSER_VISIT events with full URL + visit timestamp
- [ ] Fallback for when extension is not installed

- [x] **Browser navigation tree** — URL flow tree visualization (like process tree but for browser navigations), tab selector, time range, IOC domain highlighting, redirect chain expansion

## Later — Requires External Setup/Infrastructure

- [ ] **4. HTTPS on REST API** — Native TLS on Go server or nginx reverse proxy
- [ ] **5. Input validation on rule conditions** — Sanitize regex, prevent ReDoS
- [ ] **14. HA / horizontal scaling** — Stateless backend, read replicas
- [ ] **15. Export/SIEM integration** — Webhook (Slack, PagerDuty, Discord), syslog CEF (Splunk, ELK, QRadar), email SMTP for CRITICAL alerts, per-rule routing
- [ ] **16. Case management** — Group alerts into investigations with workflow
- [ ] **18. Container awareness (deeper)** — Container-specific dashboards and K8s integration
- [ ] **19. Structured logging** — JSON logs with correlation IDs
- [ ] **20. CI/CD pipeline** — GitHub Actions for build/test/lint
- [ ] **Dashboard widgets** — Event timeline chart, top alerting hosts, active monitors status
- [ ] **Notification system** — In-app notification bell, new alerts, agent offline events
