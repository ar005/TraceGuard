# TraceGuard Improvement Roadmap

## High Impact — Security & Reliability

- [x] **1. Add tests** — Detection engine (53 test cases, engine_test.go)
- [x] **2. Rate limiting on API** — Per-IP token bucket middleware + config + 5 tests
- [x] **3. CSRF protection on Flask UIs** — Flask-WTF CSRFProtect on both apps + all forms/AJAX
- [ ] **4. HTTPS on REST API** — Native TLS or document reverse-proxy requirement
- [ ] **5. Input validation on rule conditions** — Sanitize regex, prevent ReDoS

## High Impact — Detection Capabilities

- [x] **6. Process exit events** — /proc polling watcher goroutine synthesizes PROCESS_EXIT events for tracked PIDs
- [x] **7. DNS monitoring** — Snooper emits NET_DNS events + DGA/rare-TLD detection rules
- [x] **8. Alert correlation** — Incident grouping by agent+time window (30min), auto-correlation, REST API + UI proxy
- [x] **9. Threat intel feed integration** — IOC CRUD + bulk import, in-memory cache, real-time event matching (IP/domain/hash), REST API + UI proxy
- [x] **10. Process tree reconstruction** — API + store + UI tree visualization + test script

## Medium Impact — Operational Maturity

- [ ] **11. Prometheus metrics** — Events/sec, alerts, agent count, latency
- [ ] **12. Agent policy push** — gRPC server-streaming config updates
- [x] **13. Database retention jobs** — Hourly sweep, DB-configurable, startup logging
- [ ] **14. HA / horizontal scaling** — Stateless backend, read replicas
- [ ] **15. Export/SIEM integration** — Webhook/syslog output

## Nice to Have — Polish

- [ ] **16. Case management** — Group alerts into investigations
- [x] **17. File hash enrichment** — SHA256 on file events (already implemented: hash worker pool + HashAfter field)
- [ ] **18. Container awareness** — Cgroup namespace detection, container ID tagging
- [ ] **19. Structured logging** — JSON logs with correlation IDs
- [ ] **20. CI/CD pipeline** — GitHub Actions for build/test/lint

## New Features (Implemented)

- [x] **21. Live Response Shell** — gRPC bidi stream, remote command execution, safe allowlist, session manager
- [x] **22. Network Containment** — iptables-based isolation via live response, preserve backend comms only
- [x] **23. User/Login Monitoring** — auth.log tailing, LOGIN_SUCCESS/FAILED/SUDO_EXEC events, brute force detection rules
- [x] **24. Vulnerability Detection** — Package inventory (dpkg/rpm), CVE matching, REST API + UI proxy
- [x] **25. Container/K8s Awareness** — /proc/pid/cgroup parsing, container ID + runtime detection, process enrichment
- [x] **26. Advanced Hunting Query** — SQL-like query endpoint with safety validation, POST /api/v1/hunt

## Roadmap: URL & Domain Monitoring

### Phase 1 — eBPF DNS Snooping
- [ ] Hook `udp_sendmsg` on port 53 to capture every DNS query from any process
- [ ] Emit `NET_DNS_QUERY` events with full process attribution (PID, comm, exe)
- [ ] Enrich with resolved IPs
- [ ] Match against IOC domain list in detection engine
- [ ] Backend: store and display DNS query events in UI

### Phase 2 — eBPF TLS SNI Extraction
- [ ] Hook `tcp_sendmsg` / `security_socket_sendmsg` for outbound port 443
- [ ] Parse TLS ClientHello to extract SNI (Server Name Indication) field
- [ ] Emit `NET_TLS_SNI` events with domain + PID attribution
- [ ] Correlate with DNS events for full connection picture
- [ ] Detection rules: flag connections to known-bad or newly-registered domains

### Phase 3 — Browser Extension (Chrome + Firefox)
- [x] **Chrome extension** (Manifest V3) using `chrome.webRequest` API
  - [x] Capture: full URL, status code, method, headers, redirect chain, referrer, initiator
  - [x] Filter noise (static assets, CDN, etc.) via configurable allowlist
  - [x] POST events as JSON to agent's local HTTP endpoint (`127.0.0.1:9999`)
- [x] **Firefox extension** (WebExtensions) — same logic, adapted for Firefox APIs
- [x] **Agent: HTTP receiver** — localhost-only HTTP listener accepting extension events (5 tests)
- [x] **Agent: event type** — `BROWSER_REQUEST` event struct
  - Fields: url, domain, path, method, status_code, content_type, referrer, redirect_chain, tab_url, resource_type, server_ip, is_form_submit
- [x] **Backend: phishing detection rules** (5 seeded rules)
  - [x] Credential submission to non-allowlisted domain (form-submit + auth-page tag)
  - [x] Browser visited IOC-flagged domain
  - [x] Suspicious redirect chain (3+ hops)
  - [x] Form submission to rare TLD (.tk, .xyz, etc.)
  - [x] High-volume requests to same domain (threshold)
  - [ ] Typosquat/lookalike domain detection (Levenshtein distance from known brands)
  - [ ] Domain age < 30 days + user interaction (newly registered phishing site)
- [ ] **Backend: API** — browser monitoring allowlist/blocklist management
- [ ] **UI: browser activity view** — timeline of visited URLs with status codes

### Phase 4 — Browser History Polling (Fallback)
- [ ] Poll Chrome/Firefox/Edge SQLite history databases for new entries
  - Chrome: `~/.config/google-chrome/Default/History`
  - Firefox: `~/.mozilla/firefox/<profile>/places.sqlite`
  - Edge: `~/.config/microsoft-edge/Default/History`
- [ ] Emit `BROWSER_VISIT` events with full URL + visit timestamp
- [ ] Fallback for when extension is not installed
- [ ] Limitation: no status codes or POST data
