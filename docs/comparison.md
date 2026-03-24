# TraceGuard vs Commercial EDR/XDR Platforms — Feature Comparison

This document provides an honest, comprehensive comparison of TraceGuard (Open EDR) against major commercial and open-source EDR/XDR products. Last updated: March 2026.

---

## 1. Feature Comparison Matrix

Legend: ✅ = Yes | ❌ = No | 🟡 = Partial/Limited | 🔧 = Planned/Roadmap

### Endpoint Monitoring

| Feature | TraceGuard | CrowdStrike Falcon | MS Defender | SentinelOne | Carbon Black | Sophos Intercept X | Elastic Security | Wazuh | OSSEC |
|---------|------|-------------------|-------------|-------------|--------------|-------------------|-----------------|-------|-------|
| Process monitoring (exec, fork, exit) | ✅ eBPF | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 Log-based |
| File integrity monitoring | ✅ eBPF + SHA-256 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network connection tracking | ✅ eBPF TCP/UDP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 Log-based | 🟡 Log-based |
| DNS monitoring | ✅ DNS snooping + DGA detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 Via Suricata | ❌ |
| Registry/config monitoring | ✅ /etc watchers | ✅ Windows Registry | ✅ Windows Registry | ✅ Windows Registry | ✅ Windows Registry | ✅ | ✅ | ✅ | ✅ Windows Registry |
| Command/shell monitoring | ✅ CMD_EXEC events | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 Log-based |
| Login/auth monitoring | ✅ auth.log tailing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Browser URL monitoring | ✅ Chrome/Firefox extension | ❌ | 🟡 SmartScreen/Web Content Filter | ❌ | ❌ | ✅ Web Control | ❌ | ❌ | ❌ |
| USB/removable media monitoring | ❌ | ✅ Device Control | ✅ Device Control | ✅ Device Control | 🟡 | ✅ Peripheral Control | 🟡 | 🟡 Via rules | ❌ |
| Kernel module monitoring | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 Via FIM | 🟡 Via FIM |

### Detection & Response

| Feature | TraceGuard | CrowdStrike Falcon | MS Defender | SentinelOne | Carbon Black | Sophos Intercept X | Elastic Security | Wazuh | OSSEC |
|---------|------|-------------------|-------------|-------------|--------------|-------------------|-----------------|-------|-------|
| Signature-based detection | 🟡 IOC hash matching | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ CDB lists | ✅ |
| Behavioral/heuristic detection | ✅ 30+ rules (webshell, ptrace, C2 beaconing, DGA) | ✅ IOA-based | ✅ | ✅ Storyline | ✅ | ✅ Deep Learning | ✅ | ✅ | 🟡 |
| Machine learning detection | ❌ | ✅ Cloud ML + on-sensor | ✅ Cloud + local | ✅ On-agent AI | 🟡 | ✅ Deep Learning | ✅ ML jobs | 🟡 Anomaly detection | ❌ |
| IOC matching (IP, domain, hash) | ✅ Real-time + bulk import + feed sync | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Via CDB/integrations | 🟡 Manual |
| MITRE ATT&CK mapping | ✅ On rules and alerts | ✅ Full coverage | ✅ Full coverage | ✅ Full coverage | ✅ | ✅ | ✅ | ✅ | ❌ |
| Custom detection rules | ✅ Match + threshold rules | ✅ Custom IOAs | ✅ Custom rules | ✅ STAR rules | ✅ Watchlists | ✅ | ✅ Detection rules | ✅ XML rules | ✅ XML rules |
| Threshold/correlation rules | ✅ Time-window thresholds + auto-correlation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Typosquat domain detection | ✅ Levenshtein + homoglyph (32 brands) | ❌ (via threat intel) | ❌ (via threat intel) | ❌ (via threat intel) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Auto-quarantine files | ✅ On IOC hash match | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Active Response | ✅ Active Response |
| Auto-block IPs | ✅ iptables-based on IOC match | ✅ | ✅ | ✅ Firewall Control | ✅ | ✅ | 🟡 Via response actions | ✅ Active Response | ✅ Active Response |
| Network containment/isolation | ✅ iptables isolation, preserve backend comms | ✅ One-click | ✅ One-click | ✅ One-click | ✅ | ✅ | ✅ | 🟡 Manual | ❌ |
| Live response/remote shell | ✅ gRPC bidi stream, safe allowlist | ✅ Real Time Response | ✅ Live Response | ✅ Remote Shell | ✅ Live Response | ✅ | ✅ Osquery + response actions | ❌ | ❌ |
| Process tree visualization | ✅ In UI with indented tree | ✅ Full interactive | ✅ | ✅ Storyline | ✅ Process tree | ✅ | ✅ Session View | ❌ | ❌ |

### Investigation

| Feature | TraceGuard | CrowdStrike Falcon | MS Defender | SentinelOne | Carbon Black | Sophos Intercept X | Elastic Security | Wazuh | OSSEC |
|---------|------|-------------------|-------------|-------------|--------------|-------------------|-----------------|-------|-------|
| Real-time event streaming (SSE/WebSocket) | ✅ SSE broker | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 Kibana refresh | ❌ |
| Full-text search | ✅ | ✅ | ✅ | ✅ Deep Visibility | ✅ Process search | ✅ | ✅ Elasticsearch | ✅ Via Elasticsearch | 🟡 Log search |
| SQL-like threat hunting | ✅ POST /api/v1/hunt | ✅ Falcon Query (FQL) | ✅ KQL + Advanced Hunting | ✅ Deep Visibility (S1QL) | ✅ Process search | 🟡 Live Discover (SQL) | ✅ EQL + ES|QL | 🟡 Via Elasticsearch | ❌ |
| Alert correlation & incidents | ✅ Auto-grouping by agent + time window | ✅ | ✅ Automated investigation | ✅ Storyline auto-correlation | ✅ | ✅ | ✅ | 🟡 Manual grouping | ❌ |
| AI-powered alert explanation | ✅ Ollama/OpenAI/Anthropic/Gemini | ✅ Charlotte AI | ✅ Copilot for Security | ✅ Purple AI | ❌ | ✅ AI Assistant | ✅ AI Assistant | 🟡 New AI agent (2025) | ❌ |
| Timeline view | 🟡 Event list with timestamps | ✅ | ✅ | ✅ Attack Storyline | ✅ | ✅ | ✅ Timeline | ❌ | ❌ |
| IOC management & threat feeds | ✅ CRUD + bulk import + feed sync | ✅ Built-in + marketplace | ✅ TI integration | ✅ Built-in + marketplace | ✅ Feeds | ✅ SophosLabs | ✅ Threat Intel module | ✅ Via MISP/integrations | 🟡 Manual |

### Operations

| Feature | TraceGuard | CrowdStrike Falcon | MS Defender | SentinelOne | Carbon Black | Sophos Intercept X | Elastic Security | Wazuh | OSSEC |
|---------|------|-------------------|-------------|-------------|--------------|-------------------|-----------------|-------|-------|
| Multi-tenant support | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Spaces | ✅ | ❌ |
| Role-based access control | 🟡 JWT auth + API keys (no granular roles) | ✅ Fine-grained RBAC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| API key management | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Prometheus metrics | ✅ 13 metric families | ❌ (proprietary dashboards) | ❌ (Azure Monitor) | ❌ (proprietary) | ❌ (proprietary) | ❌ (proprietary) | ✅ | 🟡 Via integration | ❌ |
| SIEM integration (syslog/webhook) | 🔧 Planned | ✅ SIEM connector, S3 | ✅ Syslog, Sentinel | ✅ Syslog, API, SIEM | ✅ Syslog, API | ✅ Syslog, API | ✅ Native SIEM | ✅ Syslog, JSON | ✅ Syslog |
| Agent auto-update | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Agent policy push | ✅ Config version via heartbeat | ✅ Real-time policy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Data retention management | ✅ Hourly sweep, DB-configurable | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ ILM policies | ✅ | 🟡 |
| Vulnerability scanning | ✅ dpkg/rpm + CVE matching | ✅ Falcon Spotlight | ✅ TVM | 🟡 Ranger | 🟡 | ❌ (separate product) | 🟡 | ✅ | ❌ |
| Package inventory | ✅ | ✅ | ✅ | ✅ | 🟡 | ❌ | 🟡 | ✅ | ❌ |

### Platform

| Feature | TraceGuard | CrowdStrike Falcon | MS Defender | SentinelOne | Carbon Black | Sophos Intercept X | Elastic Security | Wazuh | OSSEC |
|---------|------|-------------------|-------------|-------------|--------------|-------------------|-----------------|-------|-------|
| Linux agent | ✅ eBPF (kernel >= 5.8) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windows agent | ❌ | ✅ | ✅ Native | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| macOS agent | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cloud/SaaS deployment | ❌ Self-hosted only | ✅ Cloud-native | ✅ Azure-native | ✅ Cloud-native | ✅ Cloud + on-prem | ✅ Sophos Central | ✅ Elastic Cloud | 🟡 Cloud optional | ❌ |
| On-premise deployment | ✅ | 🟡 GovCloud only | 🟡 Arc-connected | ✅ | ✅ | ❌ Cloud only | ✅ | ✅ | ✅ |
| Open source | ✅ Fully open | ❌ | ❌ | ❌ | ❌ | ❌ | 🟡 Source-available (SSPL) | ✅ GPLv2 | ✅ GPLv2 |
| Browser extension for URL monitoring | ✅ Chrome + Firefox | ❌ | ❌ | ❌ | ❌ | ❌ (network-layer only) | ❌ | ❌ | ❌ |
| Mobile device support | ❌ | ✅ Falcon for Mobile | ✅ iOS/Android | ✅ Mobile Threat Defense | ❌ | ✅ | ❌ | 🟡 | ❌ |
| Container/K8s awareness | ✅ Cgroup parsing, container ID | ✅ Cloud Workload Protection | ✅ Defender for Containers | ✅ Cloud Workload Security | ✅ | 🟡 Server protection | ✅ | ✅ Docker | ❌ |

---

## 2. Where TraceGuard Stands

### Strengths

TraceGuard is a genuinely capable open-source EDR for Linux-focused environments. Its use of eBPF for kernel-level process, network, and file monitoring provides the same high-fidelity telemetry approach used by CrowdStrike and other top-tier vendors. The detection engine with 30+ seeded behavioral rules (webshell detection, ptrace injection, memfd exec, C2 beaconing, DGA domains, brute force) covers real-world Linux attack patterns that many generic EDR products handle poorly. The live response capability with network containment, auto-quarantine, and auto-IP-blocking puts TraceGuard ahead of both open-source alternatives (Wazuh and OSSEC lack live response entirely). The browser extension with typosquat detection via Levenshtein distance and homoglyph normalization is a genuinely unique feature that no commercial EDR offers natively. The AI-powered alert explanation supporting multiple LLM backends (Ollama, OpenAI, Anthropic, Gemini) is on par with features that CrowdStrike (Charlotte AI), Microsoft (Copilot), and SentinelOne (Purple AI) charge premium prices for. Being fully self-hosted and open source means no per-endpoint licensing fees, no data leaving the network, and full auditability -- critical for air-gapped, government, and privacy-sensitive deployments.

### Weaknesses

TraceGuard is a Linux-only solution. The absence of Windows and macOS agents is the single largest gap -- every commercial product and both open-source alternatives (Wazuh, OSSEC) support all three major operating systems. There is no machine learning detection; TraceGuard relies entirely on rule-based and IOC-based detection, which means it will miss novel threats that behavioral ML models would catch. The platform lacks a managed cloud console, agent auto-update, and multi-tenant support, making it unsuitable for organizations managing thousands of endpoints without significant custom tooling. There is no SIEM integration (syslog/webhook export), which limits TraceGuard's ability to fit into existing SOC workflows. Role-based access control is basic (JWT authentication without granular permission models). The UI, while well-designed, lacks the deep interactive investigation features (attack timelines, automated investigation playbooks, forensic artifact collection) that mature commercial platforms provide.

### Unique Differentiators

1. **Browser URL monitoring with phishing detection** -- No commercial EDR ships a browser extension that captures full URL telemetry with typosquat and credential-phishing detection rules. This is a genuine innovation.
2. **Fully open source, self-hosted** -- Unlike Elastic (SSPL-licensed, not truly open source), TraceGuard is fully open with no license restrictions and no cloud dependency.
3. **eBPF-native on Linux** -- Purpose-built for Linux with modern eBPF, not a cross-platform agent adapted for Linux as an afterthought (a common weakness of commercial EDR Linux agents).
4. **Multi-provider LLM integration** -- Supports Ollama (local), OpenAI, Anthropic, and Gemini for AI alert explanation, offering flexibility no commercial product provides.
5. **Prometheus-native metrics** -- First-class observability integration, unlike commercial products that lock metrics into proprietary dashboards.

---

## 3. Feature Gap Analysis

### Critical Gaps (Required to be taken seriously as an EDR)

These are features that any organization evaluating EDR solutions will consider table-stakes:

| Gap | Impact | Difficulty |
|-----|--------|------------|
| **No Windows agent** | Eliminates TraceGuard from any mixed-OS environment. Most enterprises are Windows-majority. | Very High — requires ETW-based agent rewrite |
| **No macOS agent** | Eliminates TraceGuard from organizations with Mac fleets (engineering, creative, executive laptops). | High — requires Endpoint Security Framework agent |
| **No machine learning detection** | Rule-based detection alone will miss novel and fileless attacks. Every serious EDR uses ML. | High — requires training data, model pipeline |
| **No SIEM integration** | SOC teams need to feed EDR alerts into Splunk, Sentinel, QRadar, etc. Without syslog/webhook export, TraceGuard operates in a silo. | Low — webhook/syslog output is straightforward |
| **No agent auto-update** | Manual agent updates across hundreds of endpoints is operationally unacceptable. | Medium — requires signed binary distribution and rollback |
| **No multi-tenant support** | MSPs and large enterprises need tenant isolation. | Medium — DB-level or schema-level isolation |

### Important Gaps (Expected for production deployments)

| Gap | Impact | Difficulty |
|-----|--------|------------|
| **No granular RBAC** | Production deployments need analyst/admin/viewer roles with scoped permissions. | Low-Medium |
| **No USB/removable media monitoring** | A common data exfiltration vector, especially in regulated industries. | Medium — udev monitoring on Linux |
| **No kernel module monitoring** | Rootkit loading via kernel modules is a critical detection vector. | Medium — eBPF probe on `init_module`/`finit_module` |
| **No automated investigation playbooks** | Commercial EDRs auto-triage alerts, reducing analyst workload significantly. | High — requires workflow engine |
| **No attack timeline view** | Analysts need to visualize the full kill chain, not just individual events. | Medium — frontend feature using existing event data |
| **No forensic artifact collection** | Collecting memory dumps, browser artifacts, registry hives for investigation. | High |
| **Limited HTTPS everywhere** | REST API should support native TLS without requiring a reverse proxy. | Low |
| **No CI/CD pipeline** | No automated build, test, or release process. | Low — GitHub Actions setup |
| **No HA/horizontal scaling** | Single backend instance is a production risk. | Medium-High |

### Nice-to-Have Gaps (Polish and competitive parity)

| Gap | Impact | Difficulty |
|-----|--------|------------|
| **No mobile device support** | iOS/Android monitoring is increasingly expected in XDR. | Very High |
| **No cloud/SaaS deployment option** | Many organizations prefer managed solutions. | High — infrastructure + ops |
| **No data loss prevention (DLP)** | Sophos and others include DLP. Niche but valued. | High |
| **No network discovery** | SentinelOne Ranger discovers unmanaged devices. | Medium |
| **No structured JSON logging** | Operational maturity for backend troubleshooting. | Low |
| **No case management** | Grouping alerts into investigations with notes and status. | Medium |
| **No report generation** | PDF/scheduled reports for compliance and management. | Medium |
| **No EDR benchmarking/AV-TEST results** | Commercial products publish third-party test results. Not applicable to TraceGuard's scope, but worth noting. | N/A |
| **eBPF TLS SNI extraction** | Capturing HTTPS domains without browser extension. On roadmap but not built. | Medium |

---

## 4. Roadmap Recommendations

Based on the gap analysis, here is a prioritized build order that maximizes TraceGuard's value at each stage:

### Phase 1: Production Readiness (Weeks 1-4)

These are low-to-medium effort items that immediately make TraceGuard viable for real deployments:

1. **SIEM integration (webhook + syslog export)** — Add a configurable output that forwards alerts and events to external systems via webhook (HTTP POST) and syslog (RFC 5424). This single feature unblocks SOC adoption. Already planned in TODO.md.

2. **Granular RBAC** — Extend JWT auth with role definitions (admin, analyst, viewer) and per-endpoint permission scoping. Most of the auth infrastructure exists.

3. **Native TLS on REST API** — Add `tls_cert` and `tls_key` config options to the Gin server. Trivial but important for production.

4. **CI/CD pipeline** — GitHub Actions for build, test, lint on every PR. Ensures quality as the project grows.

5. **Structured JSON logging** — Replace log.Printf with structured logger (zerolog or zap) across backend and agent.

### Phase 2: Detection Maturity (Weeks 5-10)

Raise the detection quality to be competitive with Wazuh and approach commercial parity:

6. **Kernel module monitoring** — Add eBPF probes on `init_module`/`finit_module` syscalls. Critical for rootkit detection. Relatively contained scope.

7. **USB/removable media monitoring** — Monitor udev events for device attach/detach. Important for data exfiltration detection.

8. **eBPF TLS SNI extraction** — Already on the roadmap. Captures HTTPS domains at the kernel level without requiring browser extensions.

9. **Attack timeline view** — Build a frontend component that visualizes the kill chain for an incident (process tree + network + file events on a time axis). The data already exists; this is a UI feature.

10. **Improved rule engine** — Add support for chained/multi-stage rules (e.g., "process X followed by network connection to Y within 60 seconds"). Moves beyond single-event matching.

### Phase 3: Operational Scale (Weeks 11-18)

Make TraceGuard viable for larger deployments:

11. **Agent auto-update** — Implement a signed binary distribution mechanism. Agent checks for updates on heartbeat, downloads, verifies signature, restarts. Essential for fleet management.

12. **Multi-tenant support** — Add tenant isolation at the database level. Required for MSPs and large organizations with multiple business units.

13. **HA/horizontal scaling** — Make the backend stateless (it mostly is already), add load balancer support, document read replica setup for PostgreSQL.

14. **Case management** — Group related alerts and incidents into investigation cases with notes, status, and assignment. This is a UI + API + DB feature.

### Phase 4: Platform Expansion (Months 5-12)

The largest and most impactful investments:

15. **Windows agent** — This is the single most impactful feature for adoption. Start with ETW (Event Tracing for Windows) for process, network, and file monitoring. This is a multi-month project requiring Windows expertise, but without it TraceGuard cannot compete outside Linux-only environments.

16. **macOS agent** — Use Apple's Endpoint Security Framework. Smaller market than Windows but important for mixed environments.

17. **Machine learning detection** — Start with anomaly detection on process behavior (unusual parent-child relationships, rare binaries, time-of-day anomalies). Can use the existing event data as training input. Consider starting with simple statistical models before investing in deep learning.

### Not Recommended (Low ROI for TraceGuard's niche)

- **Mobile device support** — Extremely high effort, limited overlap with TraceGuard's Linux-focused mission. Leave to MDM products.
- **Cloud/SaaS hosted offering** — Requires operational investment that is orthogonal to the core product. Focus on making self-hosted excellent.
- **DLP** — Specialized feature that is better served by dedicated DLP products.

---

## Summary

TraceGuard is a strong Linux EDR with modern architecture (eBPF, gRPC, SSE, LLM integration) and genuine innovations (browser URL monitoring, typosquat detection, multi-provider AI). It competes favorably with Wazuh and OSSEC on detection and response capabilities while offering a more modern stack. However, it is a Linux-only, single-tenant, rule-based detection system without SIEM integration -- limitations that restrict it to Linux-focused environments willing to operate without ML detection and external SOC tool integration.

The fastest path to broader adoption is: SIEM export (unblocks SOC teams) followed by Windows agent support (unblocks mixed environments) followed by ML detection (closes the detection quality gap). The browser extension and typosquat detection remain genuine differentiators worth highlighting, as no commercial EDR offers equivalent functionality.
