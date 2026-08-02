# TraceGuard XDR Gap Analysis
## Comparison against Microsoft Defender XDR, CrowdStrike Falcon XDR, and Palo Alto Cortex XDR

**Date:** April 2026  
**Scope:** edr-backend, edr-agent (Linux), edr-agent-win, edr-ui-new  
**Analyst note:** All findings are based on direct code inspection. "IMPLEMENTED" means the feature exists in production-grade code. "STUB" means the framework exists but no real integration is wired. "MISSING" means no code at all.

---

## Executive Summary

TraceGuard has a solid, production-quality EDR foundation — comprehensive endpoint telemetry on both Linux and Windows, real-time behavioral detection with threshold and sequence rules, case management, live response, and a SOAR-lite playbook engine. The XDR transformation is partially underway (identity graph, cross-source correlation, webhook ingestion framework) but four critical XDR pillars are either stubbed or entirely absent:

1. **Cloud telemetry** — no production connectors for AWS, Azure, or GCP
2. **Email and collaboration security** — completely blind to phishing and BEC
3. **Native identity provider integration** — no AD, Entra ID, or Okta connector
4. **Network Detection and Response (NDR)** — agent-level network events only; no perimeter or east-west flow analysis

Against Microsoft Defender XDR specifically, TraceGuard currently covers approximately **55–60%** of the feature surface. Against CrowdStrike Falcon XDR it covers approximately **65%** (Falcon's cloud and identity story is narrower). The gap is meaningful but bridgeable with a structured 12–18 month roadmap.

---

## Part 1 — Current State Assessment

### 1.1 What TraceGuard Already Does Well

| Pillar | Current capability |
|--------|--------------------|
| **Endpoint — Linux** | 15 active monitors via eBPF + polling. Process, network (TCP/UDP/DNS/TLS SNI), file, auth, shell commands, kernel modules, USB, memory injection, cron, named pipes, network shares, container/K8s awareness, vulnerability scanning. SHA-256 hashing on file events. |
| **Endpoint — Windows** | 9 ETW-based monitors: process, network, file, registry, DNS, auth (Security Event Log), PowerShell, custom Windows Events (configurable IDs), memory. |
| **Detection engine** | Three rule types: `match`, `threshold` (sliding window), `sequence_cross` (multi-event chains). 21 built-in rules covering 12 MITRE ATT&CK tactics. Sigma import, STIX import, IOC matching (IP/domain/hash). Typosquat detection across 32 brand names. |
| **Investigation** | Alert triage workflow, case management (link/unlink alerts, notes), threat hunting with a SQL-like DSL (37 pre-built queries), process tree reconstruction, timeline view. |
| **Response** | Host isolation (iptables), process kill, file quarantine, IP block, SOAR playbooks (10 action types: Slack, PagerDuty, email, webhook, Jira, live-response, LLM enrichment). Interactive live-response shell (gRPC bidirectional). |
| **Identity** | User risk scorer (impossible travel, burst login, off-hours, privilege escalation). Cross-source identity graph with account_ids and agent_ids arrays. Risk score 0–100 on IdentityRecord. |
| **Threat intelligence** | IOC feed sync, bulk import, STIX bundle ingestion, NVD CVE lookup, package vulnerability inventory (dpkg/rpm). |
| **AI** | Alert explanation, AI triage verdict + confidence score, LLM-generated hunt queries, case narrative summarization. Supports OpenAI, Anthropic, Gemini, Ollama. |
| **Platform** | Multi-tenancy (schema in place), RBAC (admin/analyst), TOTP MFA for backend users, audit logging, Prometheus metrics, HA via PostgreSQL LISTEN/NOTIFY, data retention policies. |

### 1.2 The XDR Definition Used Here

XDR (Extended Detection and Response) is defined by three expansions beyond EDR:

1. **Multi-signal telemetry** — endpoint + network + identity + cloud + email, all normalized into a single event schema
2. **Cross-pillar correlation** — incidents that chain signals across those sources (e.g., phishing email → credential theft → lateral movement → data exfiltration)
3. **Unified investigation and response** — a single pane that allows a SOC analyst to investigate and respond across all pillars without switching tools

Microsoft Defender XDR achieves this by unifying Defender for Endpoint (EDR), Defender for Identity (AD), Defender for Office 365 (email), Defender for Cloud Apps (CASB), and Entra ID Protection (identity risk). CrowdStrike achieves it through Falcon Insight (EDR), Falcon Identity (AD telemetry), and Falcon Intelligence (TI). Palo Alto Cortex XDR uses its firewall telemetry as the network pillar.

---

## Part 2 — Gap Analysis by XDR Pillar

### Pillar 1: Cloud Telemetry (CRITICAL GAP)

**What commercial XDR does:**  
Microsoft Defender for Cloud Apps ingests Azure Activity Logs, AWS CloudTrail, GCP Audit Logs, and dozens of SaaS apps (O365, Salesforce, Box, Dropbox, ServiceNow). Every API call, admin action, data movement, and authentication event flows into the same incident graph as endpoint events.

**What TraceGuard has:**  
An XDR connector framework (`xdr_sources` table, webhook ingestion endpoint at `/api/v1/ingest/webhook/:source_id`) exists as a Phase 1 stub. No production integrations with any cloud provider. There is no CloudTrail reader, no Azure Activity Log pull, no GCP Pub/Sub subscriber.

**Impact:**  
An attacker who steals credentials from an endpoint and then pivots into the cloud (creates IAM users, exfiltrates S3 buckets, deploys crypto miners) is completely invisible to TraceGuard. This is the most common post-compromise path in enterprise attacks today.

**Specific missing items:**
- AWS CloudTrail → S3 event reader or CloudTrail Lake integration
- Azure Activity Log + Microsoft Entra ID Sign-In Logs (via Azure Monitor or Event Hub)
- GCP Cloud Audit Logs (via Pub/Sub)
- Cloud identity risk: impossible travel across cloud console + endpoint (currently only endpoint auth)
- Cloud misconfiguration detection (open S3 buckets, overprivileged roles)
- Kubernetes audit log ingestion (TraceGuard detects containers but not K8s API-server events)

---

### Pillar 2: Email and Collaboration Security (CRITICAL GAP)

**What commercial XDR does:**  
Microsoft Defender for Office 365 provides phishing link detonation, attachment sandbox, BEC detection (business email compromise via anomalous login + email rule creation), and mail flow metadata. CrowdStrike correlates email delivery events with endpoint execution (the user opened an attachment → ran a macro → spawned cmd.exe).

**What TraceGuard has:**  
Nothing. No email connector, no mail server integration, no O365 or Google Workspace API connection. The browser extension detects form submissions and outbound requests but cannot see inbound email or attachments.

**Impact:**  
Phishing is the #1 initial access vector. Without email telemetry, TraceGuard cannot detect spear-phishing, BEC, or malicious attachments at delivery time. It may detect the downstream execution (macro → child process), but cannot correlate it back to the email source or identify other recipients of the same campaign.

**Specific missing items:**
- Microsoft Graph API connector for Exchange Online / Defender for Office 365 alerts
- Google Workspace Admin SDK connector for Gmail events
- Email threat metadata storage model (sender, recipients, subject, attachment hashes, link detonation result)
- Phishing campaign correlation (same sender → multiple recipients across the org)
- Mail header anomaly detection (SPF/DKIM/DMARC failures → alert)
- BEC detection rule: password reset + inbox rule creation + bulk forward within 1 hour

---

### Pillar 3: Identity Provider Integration (HIGH GAP)

**What commercial XDR does:**  
Microsoft Defender for Identity consumes Active Directory replication traffic (LDAP) and Windows Event 4624/4625/4768/4769 from domain controllers to detect pass-the-hash, pass-the-ticket, golden ticket, DCSync, and reconnaissance (LDAP enumeration). CrowdStrike Falcon Identity Protection does the same via a dedicated sensor on DCs.

**What TraceGuard has:**  
Linux auth.log tailing and Windows Security Event Log capture on individual endpoints. The identity graph (`IdentityRecord`, cross-source aliases) exists, but there is no connector to domain controllers, no AD LDAP monitoring, and no Kerberos ticket inspection.

**Impact:**  
The most dangerous credential attacks (Kerberoasting, Golden Ticket, DCSync, LDAP enumeration) happen at the AD layer — between endpoints and domain controllers — and are invisible to host-only sensors. An attacker who compromises one endpoint and pivots to AD can operate undetected.

**Specific missing items:**
- AD Domain Controller event log connector (Event IDs: 4768 TGT, 4769 TGS, 4776 NTLM, 4662 DCSync, 4625 failed auth)
- LDAP enumeration detection (high-volume LDAP queries from a single host)
- Pass-the-hash detection (NTLM auth from a host that never logged in interactively)
- Pass-the-ticket / Golden Ticket detection (Kerberos TGT with anomalous PAC data or unusually long lifetime)
- Kerberoasting detection (unusual TGS requests for service accounts)
- DCSync detection (Replicating Directory Changes permission used from non-DC)
- Okta / Entra ID connector for cloud identity events (impossible travel, MFA fatigue)
- Privileged Access Management (PAM) integration: CyberArk, HashiCorp Vault session events

---

### Pillar 4: Network Detection and Response (HIGH GAP)

**What commercial XDR does:**  
Palo Alto Cortex XDR ingests firewall logs (PAN-OS), proxy logs, and NetFlow to detect lateral movement, command-and-control, and data exfiltration at the network layer — independent of the endpoint. Microsoft Defender also ingests network proxy and DNS logs from Defender for Endpoint's network protection feature.

**What TraceGuard has:**  
Agent-level network telemetry (TCP connections, DNS, TLS SNI) captured per-host. There is no network-layer sensor (flow collector, IDS, proxy log ingestion). The threat hunting DSL can query per-host connection events but there is no east-west traffic graph.

**Impact:**  
Lateral movement, C2 beaconing through a compromised proxy, and data exfiltration via encrypted channels are detectable from the network layer even when the endpoint agent is bypassed (e.g., rootkit, agentless system, IoT device). Without NDR, these attack paths are blind spots.

**Specific missing items:**
- NetFlow / IPFIX ingestion endpoint (for router/switch flow export)
- Network proxy log connector (Squid, Zscaler, Bluecoat, Cisco Umbrella)
- DNS sinkhole / RPZ log connector
- Network baseline + anomaly detection (new host communication, beaconing pattern at network level)
- East-west traffic visualization (network map between agents/assets)
- IDS/IPS alert ingestion (Suricata, Snort, Zeek) to correlate with endpoint events
- Passive DNS analytics: domain age, registrar, WHOIS enrichment on observed connections

---

### Pillar 5: UEBA and Machine Learning (MEDIUM GAP)

**What commercial XDR does:**  
Microsoft Sentinel (integrated with Defender XDR) and CrowdStrike use ML models trained on peer groups to detect anomalous behavior: a user logging in at unusual hours is low signal, but that same user + unusual process execution + unusual network destination is a high-confidence detection. Baselines are established per user/entity over 30–90 days.

**What TraceGuard has:**  
A rule-based user risk scorer (`internal/userrisk/`) that applies fixed thresholds: impossible travel (haversine distance > 500km in < 2h), burst login (> 5 logins in 5 min), off-hours activity (outside 7am–10pm local time), failed auth count. There is no statistical baseline, no peer-group comparison, no ML model inference.

**Impact:**  
Sophisticated attackers operate at low velocity specifically to avoid threshold rules. Insider threats and slow-and-low APT campaigns will evade detection because there is no "this user has never done this before" signal.

**Specific missing items:**
- Per-user behavioral baseline (rolling 30-day window for login times, source IPs, command patterns)
- Peer-group comparison (flag users whose behavior diverges from their department/role cohort)
- Entity risk aggregation: combine multiple weak signals into a composite risk score with decay
- Process anomaly scoring: flag processes that are rare for this agent (outside historical 95th percentile)
- ML inference pipeline: feature extraction from event stream → model serving → risk score update
- Training data export for offline model development

---

### Pillar 6: YARA and Memory Forensics (MEDIUM GAP)

**What commercial XDR does:**  
CrowdStrike and Microsoft Defender continuously scan process memory and file system against YARA rules and ML-based PE classifiers. They detect packed executables, shellcode injection, and fileless malware that never touches disk.

**What TraceGuard has:**  
Anonymous executable memory region detection (`memmon` monitor via `/proc/*/maps` polling). File SHA-256 hashing on write events. No YARA rule engine. No PE file analysis. No memory dump capability.

**Specific missing items:**
- YARA rule storage model and management UI (create/import/enable/disable rules)
- YARA scan on file write events (async, off the hot path)
- YARA scan on process memory regions flagged by `memmon`
- PE header analysis (detect packers, suspicious imports, anomalous section entropy)
- Memory dump collection via live response and remote upload
- Volatility plugin integration for offline memory forensics

---

### Pillar 7: Mobile Device Monitoring (LOW-MEDIUM GAP)

**What commercial XDR does:**  
Microsoft Defender for Endpoint on Android/iOS and CrowdStrike Falcon for Mobile provide jailbreak/root detection, app permission monitoring, certificate inspection, and network protection on mobile.

**What TraceGuard has:**  
Android agent skeleton exists (`edr-agent-android/`) but is non-functional. No iOS agent exists at all.

**Specific missing items:**
- Functional Android agent: process events via `/proc`, network via VpnService, app inventory via PackageManager
- iOS agent: configuration profile-based monitoring (limited by iOS sandbox), MDM API integration
- MDM platform connector: Microsoft Intune, Jamf, VMware Workspace ONE for device compliance posture
- Mobile app risk scoring: permission analysis, anomalous data access patterns

---

### Pillar 8: SaaS and CASB Visibility (MEDIUM GAP)

**What commercial XDR does:**  
Microsoft Defender for Cloud Apps acts as a CASB: it proxies SaaS traffic (O365, Salesforce, Box) and generates alerts for mass download, impossible travel on SaaS login, risky OAuth application grants, and shadow IT discovery.

**What TraceGuard has:**  
Browser extension captures HTTP request metadata including form submissions and navigation. No SaaS API connectors. No OAuth grant monitoring.

**Specific missing items:**
- O365 / Microsoft Graph connector: SharePoint bulk download detection, Teams message metadata, Exchange Online mail flow
- Google Workspace connector: Drive bulk download, admin audit log, Gmail metadata
- Generic OAuth app grant monitoring (detect when users authorize unknown apps)
- Shadow IT discovery: correlate browser extension DNS/URL data with known SaaS app catalogue
- Data Loss Prevention (DLP) signals: large file upload to personal storage, sensitive keyword in clipboard

---

### Pillar 9: Compliance and Reporting (LOW GAP)

**What commercial XDR does:**  
Microsoft Defender XDR provides built-in compliance reports (NIST, SOC2, ISO27001, PCI-DSS, HIPAA) with control mapping and audit-ready evidence packages.

**What TraceGuard has:**  
Audit logging (all admin actions), data retention policies, RBAC. No structured compliance reports.

**Specific missing items:**
- MITRE ATT&CK coverage matrix view: which tactics/techniques have active detection rules vs. gaps
- Compliance framework control mapping (rules tagged to SOC2 CC6.x, NIST 800-53 controls, PCI-DSS requirements)
- Scheduled compliance summary reports (PDF/CSV, emailed to stakeholders)
- Evidence package export: for a given incident, export all relevant events, alerts, cases, analyst notes as a single ZIP
- Data residency controls: per-tenant data isolation with documented retention periods

---

### Pillar 10: Visualization and Graph Analysis (LOW-MEDIUM GAP)

**What commercial XDR does:**  
Microsoft Defender XDR's "Attack Story" renders a visual kill chain graph showing how entities (users, processes, files, IPs) connected during an incident. CrowdStrike's Incident Workbench renders a process tree overlaid on the MITRE ATT&CK framework.

**What TraceGuard has:**  
Process tree reconstruction API and UI (`/api/v1/processes/:pid/tree`), alert timeline view. No force-directed network graph. No lateral movement path visualization. No MITRE ATT&CK heatmap.

**Specific missing items:**
- Incident attack story graph: render incident entities (user, process, file, IP, host) as nodes with edges showing the event chain
- MITRE ATT&CK heatmap: coverage overlay showing which techniques have rules and which have fired recently
- Lateral movement path visualization: directed graph of which user/credential moved between which hosts
- Network topology map: asset-to-asset communication graph derived from network events

---

## Part 3 — Feature Comparison Matrix

| Capability | MS Defender XDR | CrowdStrike Falcon XDR | Palo Alto Cortex XDR | **TraceGuard** |
|---|:---:|:---:|:---:|:---:|
| Endpoint telemetry (Windows) | ✅ | ✅ | ✅ | ✅ |
| Endpoint telemetry (Linux) | ✅ | ✅ | ✅ | ✅ |
| Endpoint telemetry (macOS) | ✅ | ✅ | ✅ | ❌ |
| Endpoint telemetry (Mobile) | ✅ | ✅ | ❌ | ⚠️ stub |
| Cloud telemetry (AWS/Azure/GCP) | ✅ | ⚠️ partial | ✅ | ❌ |
| Email security telemetry | ✅ | ❌ | ❌ | ❌ |
| Identity / AD telemetry | ✅ | ✅ | ⚠️ partial | ⚠️ host-only |
| Network / NDR telemetry | ⚠️ partial | ⚠️ partial | ✅ | ⚠️ host-only |
| SaaS / CASB visibility | ✅ | ❌ | ⚠️ partial | ❌ |
| Behavioral detection (rules) | ✅ | ✅ | ✅ | ✅ |
| ML / anomaly detection | ✅ | ✅ | ✅ | ❌ |
| UEBA (peer-group baselining) | ✅ | ✅ | ✅ | ⚠️ fixed-rule only |
| MITRE ATT&CK coverage tagging | ✅ | ✅ | ✅ | ✅ |
| Sigma rule import | ⚠️ partial | ❌ | ❌ | ✅ |
| YARA scanning | ✅ | ✅ | ✅ | ❌ |
| Pass-the-hash/ticket detection | ✅ | ✅ | ⚠️ partial | ❌ |
| Deception / honeypot | ⚠️ via Sentinel | ❌ | ❌ | ❌ |
| Case / investigation management | ✅ | ✅ | ✅ | ✅ |
| Process tree visualization | ✅ | ✅ | ✅ | ✅ API only |
| Attack story / incident graph | ✅ | ✅ | ✅ | ❌ |
| MITRE ATT&CK heatmap | ✅ | ✅ | ✅ | ❌ |
| Threat hunting (query language) | ✅ KQL | ✅ SPL-like | ✅ XQL | ✅ custom DSL |
| AI-assisted investigation | ✅ Copilot | ✅ Charlotte AI | ✅ XSIAM AI | ✅ LLM integration |
| Live response / remote shell | ✅ | ✅ | ✅ | ✅ |
| Host isolation | ✅ | ✅ | ✅ | ✅ |
| SOAR / playbook automation | ✅ | ✅ | ✅ | ✅ (10 actions) |
| Jira / ServiceNow ticketing | ✅ both | ✅ both | ✅ both | ⚠️ Jira only |
| Splunk / Sentinel SIEM export | ✅ | ✅ | ✅ | ⚠️ syslog/CEF only |
| Multi-tenancy | ✅ | ✅ | ✅ | ⚠️ schema only |
| RBAC | ✅ granular | ✅ granular | ✅ granular | ⚠️ 2 roles |
| Compliance reporting | ✅ | ✅ | ✅ | ❌ |
| Agent auto-update | ✅ | ✅ | ✅ | ❌ |
| macOS agent | ✅ | ✅ | ✅ | ❌ |
| Self-hosted / on-prem option | ❌ SaaS only | ❌ SaaS only | ⚠️ via Prisma | ✅ |
| Open-source extensibility | ❌ | ❌ | ❌ | ✅ |

**Legend:** ✅ Fully implemented — ⚠️ Partial / limited — ❌ Not present

---

## Part 4 — Roadmap to Full XDR

Priorities are ordered by security impact and implementation complexity. Each phase is self-contained and delivers value independently.

---

### Phase A — Close the Critical Blind Spots (0–3 months)

These are the features that enterprise buyers will block TraceGuard on immediately. Without them, TraceGuard cannot be positioned as XDR even informally.

#### A1. Active Directory / Domain Controller Integration
**Why first:** Every enterprise runs AD. Golden Ticket, DCSync, and Kerberoasting are in every APT playbook and are undetectable without DC telemetry.

- Design a new `connector` package alongside the existing `ingest` package
- Build a Windows service that runs on Domain Controllers: subscribes to Windows Security Event Log on the DC itself (not from endpoints), targeting Event IDs 4768, 4769, 4770, 4776, 4662, 4672, 4625, 4726
- Stream these events to the backend via the existing gRPC or a new dedicated HTTP batch ingestion API
- Add a new source type `active_directory` to `xdr_sources`
- Add detection rules: DCSync (4662 with replicating-directory-changes ACE from non-DC), Kerberoasting (spike in 4769 RC4 TGS requests), Golden Ticket (4768 with unusual flags or very long ticket lifetime), LDAP recon (burst of 4661/4662 from a single workstation)
- Enrich the existing `IdentityRecord` with AD group membership, last password change, account flags

#### A2. Webhook-based Cloud Connector (AWS CloudTrail, Azure Activity Logs)
**Why second:** Cloud pivot is the most common post-endpoint-compromise path. The ingestion framework already exists — what's missing is a pull mechanism and normalization.

- Build a CloudTrail-to-TraceGuard bridge: a lightweight Lambda or sidecar that reads from an S3+SQS CloudTrail delivery and POSTs normalized events to `/api/v1/ingest/webhook/:source_id`
- Build an Azure Event Hub subscriber that streams Azure Activity Logs and Entra ID Sign-In Logs to the same endpoint
- Define a normalized `cloud_event` schema (actor, resource, action, region, result, risk_context) as a new XDR event type
- Add cloud-specific detection rules: new IAM user created immediately after endpoint compromise (correlation across cloud + endpoint), bucket policy change exposing data publicly, impossible travel between endpoint auth and cloud console login
- Add a "Cloud" tab to the incidents view in the UI showing correlated cloud events alongside endpoint events

#### A3. Email Connector (Microsoft Graph / Google Workspace)
**Why third:** Email is the #1 initial access vector. Even basic mail flow metadata closes the phishing detection gap.

- Define a `mail_event` XDR event type: message_id, sender, recipients, subject_hash, attachment_hashes, links, spf_result, dkim_result, dmarc_result, delivery_action
- Build a Microsoft Graph API poller (or webhook receiver via O365 activity API) that ingests Exchange Online mail events and Defender for Office 365 alert webhooks
- Build a Google Workspace Admin SDK connector for Gmail events
- Add detection rules: phishing URL clicked (browser extension domain → matches email link within 5 min), attachment executed (mail attachment hash matches process image hash), BEC pattern (inbox rule creation + bulk forward within 1h of new login from unusual location)
- Add "Email" section to the alert detail view showing the originating email if the incident started from a mail event

---

### Phase B — Deepen Detection Quality (3–6 months)

These close the detection quality gap — the difference between "fires on known-bad" and "finds unknown-bad."

#### B1. YARA Rule Engine
- Add a `yara_rules` table and management API (CRUD, import `.yar` files)
- Integrate a YARA library (go-yara or a CGO wrapper) into the detection engine
- On every `FILE_CREATE` / `FILE_WRITE` event with a SHA-256 hash, schedule an async YARA scan if the file is executable (ELF/PE magic bytes) — do not block the hot path
- On every `MEMORY_INJECT` event, trigger YARA scan of the flagged memory region via the live response agent (if available)
- Surface YARA match alerts with matching rule name and matched strings in the alert detail

#### B2. Behavioral Baselining for UEBA
- Add a `behavioral_baselines` table (already exists in schema per Phase 6) with per-user/per-agent rolling statistics
- Define baseline dimensions: login hour distribution, login source IP set, command frequency histogram, process launch frequency per binary, outbound destination set
- Build a background worker that updates baselines on a 24-hour rolling window from stored events
- Add a baseline deviation scorer: for each new event, compute distance from baseline (z-score for numeric features, Jaccard for set features) and add the score to the `IdentityRecord.risk_score`
- Add threshold rules that trigger only when baseline deviation exceeds a configurable percentile — this turns weak signals into actionable alerts

#### B3. NTLM Relay and Kerberos Attack Detection
- These require AD integration (Phase A1) as a prerequisite
- Add rules: NTLM auth from a machine that has never used NTLM before (pass-the-hash proxy), Kerberos TGS for sensitive SPN (service account) with RC4 downgrade (Kerberoasting), TGT with abnormal PAC or unusually long validity (Golden Ticket)
- Track "credential ancestry" in the identity graph: which host first observed a credential → which hosts subsequently used it

#### B4. ServiceNow Integration
- Add `servicenow` as a new playbook action type alongside the existing `ticket` (Jira) action
- Implement OAuth2 or Basic Auth to ServiceNow Table API
- Map TraceGuard alert severity → ServiceNow priority and urgency fields
- Support bidirectional sync: ServiceNow incident resolution → update TraceGuard alert status

#### B5. RBAC Granularization
- Current RBAC has only two roles: `admin` and `analyst`
- Add a `viewer` role (read-only, no status updates)
- Add a `responder` role (can isolate hosts and run playbooks, cannot modify rules or users)
- Add a `hunter` role (can run hunt queries and create cases, cannot modify rules)
- Implement permission checks at the handler level rather than role checks where granularity is needed

---

### Phase C — Investigation and Visualization (6–9 months)

These close the investigation quality gap — the difference between "list of alerts" and "the full attack story."

#### C1. Incident Attack Story Graph
- Design a graph data model: nodes (User, Process, File, Network, Host, Email), edges (event type, timestamp, direction)
- Build an API endpoint that derives the graph for a given incident from its correlated events
- Implement a force-directed graph visualization in the dashboard using a library (D3.js or React Flow)
- Each node should be clickable to show the underlying events; edges should show the attack action label
- This single feature is the most visible gap when demoing TraceGuard against commercial XDR tools

#### C2. MITRE ATT&CK Coverage Heatmap
- Add MITRE ATT&CK tactic/technique metadata lookup (ATT&CK TAXII feed or embedded JSON)
- Build an API endpoint that returns: for each technique in ATT&CK, does TraceGuard have a detection rule? has it fired in the last 30 days?
- Render this as an interactive ATT&CK Navigator-style heatmap in the dashboard
- This is a key capability for SOC managers and customers evaluating coverage

#### C3. Network Topology Map
- Derive a network topology graph from stored `NET_CONNECT` / `NET_ACCEPT` events, aggregated per (agent_id, destination_ip, destination_port)
- Build an API that returns the graph for a time window
- Render as a node-link diagram in the dashboard, coloring nodes by risk score, showing port labels on edges
- Filter by incident to show the lateral movement path for a specific incident

#### C4. Evidence Package Export
- Build a "Generate Evidence Package" action on the Case detail view
- Export: case metadata, all linked alerts, all events in the timeline, all analyst notes, all playbook runs, all LLM-generated summaries → single ZIP file signed with SHA-256 manifest
- Useful for incident response handoff, legal hold, and compliance audits

---

### Phase D — Platform Maturity (9–12 months)

These close the enterprise deployment and compliance gaps.

#### D1. macOS Agent
- TraceGuard has no macOS sensor. This is a significant gap for any org with Apple devices.
- macOS sensor can use Endpoint Security Framework (ESF) via the system extension approach (requires Apple notarization)
- Target monitors: process execution (ESEvent), file events (ESEvent), network (Network Extension API), auth (ESEvent), XPC service activity
- The existing agent architecture (gRPC + config hot-reload) applies directly; add a new `cmd/agent-mac` entry point

#### D2. Agent Auto-Update
- Add a `version` field to the agents table, populated from the Heartbeat RPC
- Build an admin UI to upload new agent binaries and publish a target version per OS/arch
- Backend serves the target version in the Heartbeat response; agent compares to its current version
- Agent downloads the new binary over mTLS from a `/api/v1/agent-update/:os/:arch` endpoint, verifies SHA-256 and signature, then self-replaces and restarts via a helper launcher process
- Prevents the operational problem of stale sensors running outdated code

#### D3. Compliance Reporting
- Build a report generation service: accepts a framework name (SOC2, PCI-DSS, ISO27001, NIST 800-53) and date range
- Map each control to TraceGuard capabilities: for example, SOC2 CC6.1 (logical access) → RBAC audit log; PCI-DSS 10.2.4 (root access) → sudo events
- For each control, generate a "passed / at risk / gap" status with evidence links (alert IDs, audit log entries)
- Export as PDF and JSON; schedule regular delivery via email playbook action

#### D4. Native Splunk / Microsoft Sentinel Integration
- Current export is syslog CEF (push only). Both Splunk and Sentinel have richer pull APIs.
- Build a Splunk HEC (HTTP Event Collector) export destination in addition to syslog
- Build an Azure Log Analytics Workspace / Sentinel Data Connector API integration
- For Sentinel specifically, build a proper Analytics Rule template export so TraceGuard rules can be represented in Sentinel KQL alongside the data

#### D5. Multi-Tenancy UI Enforcement
- The schema has `tenant_id` on all tables (now enforced at the store layer after rounds 1–6 of hardening)
- The UI does not yet segment tenants — all UI pages are single-tenant
- Add a tenant selector to the admin portal and dashboard header
- Enforce tenant context in all Next.js API routes by reading `claims.TenantID` from the JWT
- Add a tenant management page (admin only): create tenant, set name/logo/data retention, assign users to tenants

#### D6. Deception / Honeypot Integration
- Add a `honeypot_assets` table: fake assets (hostnames, IPs, credentials, files) that should never be touched legitimately
- Any event involving a honeypot asset (connection attempt, credential use, file access) triggers a high-confidence alert
- Integration with external honeypot frameworks (Canarytokens, OpenCanary) via webhook ingestion

---

### Phase E — Mobile and IoT (12–18 months)

#### E1. Functional Android Agent
- Complete the existing skeleton in `edr-agent-android/`
- Use Android's `UsageStatsManager` for app activity, `ConnectivityManager` for network, `AccessibilityService` for process-level monitoring
- Target: package inventory, network connection events, screen lock/unlock, USB events, sideloaded app detection

#### E2. MDM Integration (Intune / Jamf)
- Build connectors to MDM platforms to ingest device compliance posture, app inventory, and management events
- Correlate MDM device ID with TraceGuard agent ID via hostname/serial number matching
- Surface device compliance status (OS patch level, encryption enabled, screen lock policy) in the asset inventory view

---

## Part 5 — Prioritization Summary

| Priority | Feature | Phase | Est. Effort | XDR Pillar Closed |
|----------|---------|-------|-------------|-------------------|
| P0 | AD / Domain Controller connector | A1 | 4–6 weeks | Identity |
| P0 | AWS CloudTrail + Azure Activity connector | A2 | 3–5 weeks | Cloud |
| P0 | Email connector (Graph API / Workspace) | A3 | 3–4 weeks | Email |
| P1 | YARA rule engine | B1 | 3–4 weeks | Detection quality |
| P1 | Behavioral baselining (UEBA) | B2 | 4–6 weeks | Detection quality |
| P1 | Incident attack story graph (UI) | C1 | 3–4 weeks | Investigation |
| P1 | MITRE ATT&CK heatmap (UI) | C2 | 1–2 weeks | Investigation |
| P2 | NTLM/Kerberos attack detection | B3 | 2–3 weeks (needs A1) | Identity |
| P2 | ServiceNow integration | B4 | 1–2 weeks | Platform |
| P2 | RBAC granularization | B5 | 2–3 weeks | Platform |
| P2 | Network topology map (UI) | C3 | 2–3 weeks | Investigation |
| P2 | Evidence package export | C4 | 1 week | Investigation |
| P3 | macOS agent | D1 | 8–12 weeks | Endpoint |
| P3 | Agent auto-update | D2 | 3–4 weeks | Platform |
| P3 | Compliance reporting | D3 | 3–4 weeks | Platform |
| P3 | Splunk HEC / Sentinel native export | D4 | 2–3 weeks | Integration |
| P3 | Multi-tenancy UI enforcement | D5 | 2–3 weeks | Platform |
| P3 | Honeypot integration | D6 | 2–3 weeks | Detection |
| P4 | Android agent (functional) | E1 | 6–8 weeks | Mobile |
| P4 | MDM integration | E2 | 3–4 weeks | Mobile |

**Total estimated effort to reach commercial XDR parity on core pillars (P0+P1):** approximately 5–7 months of focused engineering.

**Total estimated effort to reach full platform parity (P0–P3):** approximately 12–14 months.

---

## Part 6 — What TraceGuard Has That Commercial XDR Lacks

Not all gaps favor commercial tools. TraceGuard has meaningful advantages that should be preserved:

| Advantage | Detail |
|-----------|--------|
| **Sigma rule import** | Neither CrowdStrike nor Palo Alto supports native Sigma import. TraceGuard can consume the entire community rule library from SigmaHQ. |
| **Full self-hosted deployment** | Microsoft Defender XDR and CrowdStrike are SaaS-only. TraceGuard runs entirely on-prem with no data leaving the customer's network — a hard requirement for defence, government, banking, and healthcare. |
| **eBPF-based Linux telemetry** | TraceGuard's eBPF coverage (15 monitors) is comparable to Falcon's and deeper than Defender for Endpoint's Linux implementation. |
| **Open LLM integration** | TraceGuard supports Ollama (local LLM) — all AI features work air-gapped with no data sent to external API providers. Commercial tools require cloud LLM. |
| **TLS SNI extraction** | Parsing ClientHello at the raw socket level gives TLS visibility without breaking encryption or deploying a proxy — something most commercial tools cannot do without MITM. |
| **Transparent extensibility** | The webhook ingestion, playbook action framework, and export destinations can be extended by customers without waiting for vendor roadmap. |

---

*Document version 1.0 — based on codebase state as of April 2026. Re-run gap analysis after each major feature release.*
