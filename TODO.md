# TraceGuard Improvement Roadmap

## High Impact — Security & Reliability

- [x] **1. Add tests** — Detection engine (53 test cases, engine_test.go)
- [x] **2. Rate limiting on API** — Per-IP token bucket middleware + config + 5 tests
- [ ] **3. CSRF protection on Flask UIs** — Add Flask-WTF or manual CSRF
- [ ] **4. HTTPS on REST API** — Native TLS or document reverse-proxy requirement
- [ ] **5. Input validation on rule conditions** — Sanitize regex, prevent ReDoS

## High Impact — Detection Capabilities

- [ ] **6. Process exit events** — Tracepoint or efficient /proc polling
- [x] **7. DNS monitoring** — Snooper emits NET_DNS events + DGA/rare-TLD detection rules
- [ ] **8. Alert correlation** — Cross-rule correlation with time windows
- [ ] **9. Threat intel feed integration** — IOC lists (IP, domain, hash)
- [x] **10. Process tree reconstruction** — API + store + UI tree visualization + test script

## Medium Impact — Operational Maturity

- [ ] **11. Prometheus metrics** — Events/sec, alerts, agent count, latency
- [ ] **12. Agent policy push** — gRPC server-streaming config updates
- [x] **13. Database retention jobs** — Hourly sweep, DB-configurable, startup logging
- [ ] **14. HA / horizontal scaling** — Stateless backend, read replicas
- [ ] **15. Export/SIEM integration** — Webhook/syslog output

## Nice to Have — Polish

- [ ] **16. Case management** — Group alerts into investigations
- [ ] **17. File hash enrichment** — SHA256 on file events, hash matching
- [ ] **18. Container awareness** — Cgroup namespace detection, container ID tagging
- [ ] **19. Structured logging** — JSON logs with correlation IDs
- [ ] **20. CI/CD pipeline** — GitHub Actions for build/test/lint
