# Detection Rules Guide

The TraceGuard detection engine evaluates every incoming event against loaded rules in real time, generating alerts when conditions are met.

## How Detection Works

The detection pipeline follows this sequence for each event:

```
Event received
  |
  v
Suppression check ──> Suppressed? ──> Drop (increment hit count)
  |
  | (not suppressed)
  v
IOC matching ──> IP/Domain/Hash match? ──> Create IOC alert
  |
  v
Rule evaluation ──> Conditions match?
  |                     |
  |              [match rule] ──> Fire alert (with dedup)
  |                     |
  |            [threshold rule] ──> Add to sliding window
  |                                     |
  |                             Window full? ──> Fire alert, reset window
  |
  v
Incident correlation ──> New or existing incident
```

### Key behaviors:

1. **Suppression first**: Suppression rules are evaluated before detection rules. If an event matches any enabled suppression rule, it is silently dropped and the suppression hit count is incremented.
2. **IOC matching**: After suppression, the event is checked against in-memory IOC caches (IP, domain, hash). IOC caches are refreshed from the database every 60 seconds.
3. **Rule evaluation**: Each enabled rule whose event types include the event's type has its conditions checked against the flattened event payload.
4. **Alert deduplication**: When a match rule fires, the engine checks for an existing open alert for the same rule and agent within a 10-minute window. If found, the existing alert's hit count is incremented rather than creating a new alert.
5. **Incident correlation**: Alerts are grouped into incidents based on related agents, hostnames, and MITRE ATT&CK technique IDs.

## Rule Types

### Match Rules

Match rules fire when a **single event** satisfies all conditions. This is the default rule type.

```json
{
  "rule_type": "match",
  "conditions": [
    {"field": "path", "op": "startswith", "value": "/etc/sudoers"}
  ]
}
```

### Threshold Rules

Threshold rules fire when **N matching events** occur within a sliding time window, grouped by a configurable key. The engine maintains in-memory sliding windows per `(rule_id, group_key)` pair.

```json
{
  "rule_type": "threshold",
  "threshold_count": 20,
  "threshold_window_s": 30,
  "group_by": "process.pid",
  "conditions": [
    {"field": "direction", "op": "eq", "value": "OUTBOUND"}
  ]
}
```

**Threshold parameters:**

| Field | Type | Description |
|---|---|---|
| `threshold_count` | int | Number of matching events required to fire |
| `threshold_window_s` | int | Time window in seconds |
| `group_by` | string | Grouping key: `agent_id`, `hostname`, `event_type`, or any payload field (e.g., `dst_ip`, `process.pid`, `domain`) |

When a threshold rule fires, the window is reset to prevent firing on every subsequent event. Stale windows are pruned every 5 minutes to prevent unbounded memory growth.

## Rule Conditions

Each rule has an array of conditions. **All conditions must match** for the rule to fire (logical AND).

### Condition Format

```json
{
  "field": "path",
  "op": "startswith",
  "value": "/etc/sudoers"
}
```

### Supported Operators

| Operator | Description | Value Type | Example |
|---|---|---|---|
| `eq` | Exact equality | string, number, bool | `{"field":"direction","op":"eq","value":"OUTBOUND"}` |
| `ne` | Not equal | string, number, bool | `{"field":"status","op":"ne","value":"cached"}` |
| `gt` | Greater than | number | `{"field":"dst_port","op":"gt","value":49151}` |
| `lt` | Less than | number | `{"field":"dst_port","op":"lt","value":1024}` |
| `gte` | Greater than or equal | number | `{"field":"status_code","op":"gte","value":400}` |
| `lte` | Less than or equal | number | `{"field":"status_code","op":"lte","value":599}` |
| `in` | Value is in list | string array | `{"field":"process.comm","op":"in","value":["bash","sh","zsh"]}` |
| `startswith` | String prefix match | string | `{"field":"path","op":"startswith","value":"/etc/sudoers"}` |
| `contains` | Substring match | string | `{"field":"tags","op":"contains","value":"revshell"}` |
| `regex` | Regular expression match | string (regex) | `{"field":"path","op":"regex","value":"^/etc/cron\|^/var/spool/cron"}` |

### Field Resolution

The engine flattens the event payload into a dot-notation map. For example, a payload with:

```json
{
  "process": {
    "comm": "bash",
    "pid": 1234
  },
  "path": "/bin/bash"
}
```

Produces these addressable fields: `process.comm`, `process.pid`, `path`, and also the top-level keys.

## Seeded Detection Rules

The backend ships with 45+ pre-configured detection rules across multiple categories.

### Process Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Web Server Spawning Shell** | High (3) | Match | T1059.004, T1190 | A web server process (nginx, apache, php) spawned an interactive shell (bash, sh, python, perl, ruby). Indicates webshell or RCE. |
| **Process Injection via ptrace** | High (3) | Match | T1055.008 | A process used ptrace ATTACH or POKETEXT on another process. Classic code injection pattern. |
| **Fileless Execution (memfd)** | Critical (4) | Match | T1620 | A binary was executed from a memfd. Common technique for in-memory malware execution. |
| **Execution Burst (threshold)** | Medium (2) | Threshold (30/60s by agent_id) | T1059 | 30+ process executions in 60 seconds on the same host. Indicates script-based attack. |

### File Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **sudoers File Modified** | Critical (4) | Match | T1548.003 | A process wrote to `/etc/sudoers` or `/etc/sudoers.d/`. Privilege escalation persistence. |
| **Cron Persistence Established** | High (3) | Match | T1053.003 | A file was created or modified in `/etc/cron*` or `/var/spool/cron`. Persistence mechanism. |
| **LD_PRELOAD Hijack Attempt** | Critical (4) | Match | T1574.006 | A process wrote to `/etc/ld.so.preload`. Classic rootkit persistence technique. |

### Network Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Unusual Outbound Connection on High Port** | Medium (2) | Match | T1071 | Process connected to an external IP on port > 49151. Potential C2 beaconing. |
| **Port Scan Detected (threshold)** | High (3) | Threshold (20/30s by process.pid) | T1046 | A single process made 20+ outbound TCP connections in 30 seconds. |
| **SSH Brute Force (threshold)** | High (3) | Threshold (20/60s by agent_id) | T1110 | 20+ inbound SSH connections (port 22) in 60 seconds. |
| **C2 Beaconing Detected (threshold)** | High (3) | Threshold (10/300s by dst_ip) | T1071 | 10+ outbound connections to the same external host in 5 minutes. |

### Command Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Reverse Shell Command Detected** | Critical (4) | Match | T1059.004 | Command containing reverse shell patterns (bash -i, nc -e, /dev/tcp). Tagged with `revshell`. |
| **History Evasion Detected** | High (3) | Match | T1070.003 | User attempted to clear or disable shell history. Tagged with `history-evasion`. |
| **Port Scanner Executed** | High (3) | Match | T1046 | nmap, masscan or similar port scanner run interactively. Tagged with `port-scan`. |
| **Credential Dumper Executed** | Critical (4) | Match | T1003 | mimikatz, LaZagne, or secretsdump executed. Tagged with `cred-dumper`. |
| **Sudo Root Shell Escalation** | High (3) | Match | T1548.003 | User escalated to root shell via sudo. Tagged with `sudo-root-shell`. |

### Auth Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Login Brute Force (threshold)** | High (3) | Threshold (10/120s by agent_id) | T1110.001 | 10+ failed login attempts on the same host in 120 seconds. |
| **SSH Brute Force from Single IP (threshold)** | High (3) | Threshold (5/60s by source_ip) | T1110.001 | 5+ failed SSH logins from the same source IP in 60 seconds. |
| **Sudo to Root Shell** | Medium (2) | Match | T1548.003 | User executed a root shell via sudo (bash, sh, zsh, dash, fish). |

### DNS Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **DGA Domain Detected** | High (3) | Match | T1568.002 | DNS query resolved a domain with DGA characteristics: excessive length (50+ chars), high digit proportion, or repeating alphanumeric patterns. |
| **DNS Query to Rare/Suspicious TLD** | Medium (2) | Match | T1071.004 | DNS query targeted a TLD frequently abused by threat actors: `.tk`, `.xyz`, `.top`, `.pw`, `.cc`, `.ws`, `.click`, `.link`, `.work`, `.date`, `.download`, `.racing`, `.stream`, `.gdn`, `.bid`. |

### Kernel Module Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Unsigned Kernel Module Loaded** | Critical (4) | Match | T1547.006 | A kernel module was loaded without a valid signature. Indicates a possible rootkit or unauthorized driver insertion. |
| **Kernel Tainted After Module Load** | Medium (2) | Match | T1547.006 | The kernel became tainted after loading a module, indicating an out-of-tree or proprietary module was inserted. |

### USB Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **USB Mass Storage Device Connected** | Medium (2) | Match | T1052.001 | A USB mass storage device (flash drive, external HDD) was plugged in. Potential data exfiltration or malware delivery vector. |
| **Multiple USB Devices Connected Rapidly (threshold)** | High (3) | Threshold (3/60s by agent_id) | T1200 | 3+ USB devices connected within 60 seconds. Indicates a possible USB attack (BadUSB, rubber ducky). |

### Memory Injection Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Suspicious Memory Injection Detected** | Critical (4) | Match | T1055.001, T1620 | Anonymous executable memory region detected in a process. Indicates possible shellcode injection or reflective loading. |

### Cron Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Suspicious Cron Job Created** | High (3) | Match | T1053.003 | A cron entry was created or modified containing download commands, encoded payloads, or reverse shell patterns. |
| **Cron Job with Reverse Shell Pattern** | Critical (4) | Match | T1053.003, T1059.004 | A cron entry contains reverse shell indicators (/dev/tcp, nc -e, bash -i). |

### Named Pipe Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Named Pipe Created in Temp Directory** | High (3) | Match | T1570, T1071 | A FIFO/named pipe was created in /tmp, /var/tmp, or /dev/shm. Used by C2 frameworks (Cobalt Strike, PsExec) for inter-process communication. |

### Network Share Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Network Share Mounted** | Medium (2) | Match | T1021.002 | A CIFS/NFS network share was mounted. Potential lateral movement or data staging activity. |

### TLS SNI Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **TLS Connection to Rare TLD** | Medium (2) | Match | T1071.001 | A process established a TLS connection to a domain with a known-abuse TLD (.tk, .xyz, .top, .pw, .click, etc.). |
| **TLS Beaconing to Single Domain (threshold)** | High (3) | Threshold (20/300s by domain) | T1071.001, T1573.002 | 20+ TLS connections to the same external domain in 5 minutes. Possible C2 beaconing over HTTPS. |

### Browser Rules

| Rule | Severity | Type | MITRE | Description |
|---|---|---|---|---|
| **Credential Submission to Non-Allowlisted Domain** | High (3) | Match | T1056.004 | User submitted a form on a login/signin/auth page. |
| **Browser Visited IOC-Flagged Domain** | Critical (4) | Match | T1566.002 | User navigated to a domain flagged in the IOC database. |
| **Suspicious Redirect Chain Detected** | Medium (2) | Match | T1566.002 | Browser request followed 3+ redirect hops. |
| **Form Submission to Rare TLD** | High (3) | Match | T1566.002 | User submitted a form to a domain with an abuse-prone TLD. |
| **Browser High Volume Requests (threshold)** | Medium (2) | Threshold (50/60s by domain) | T1204.001 | 50+ browser requests to the same domain in 60 seconds. |

## Typosquat Domain Detection

The detection engine includes a built-in typosquat/lookalike domain detection system that operates independently of the rule engine. It is evaluated against BROWSER_REQUEST events automatically.

### How It Works

1. When a BROWSER_REQUEST event arrives, the engine extracts the domain from the URL.
2. The domain is normalized using homoglyph substitution (e.g., replacing Cyrillic characters that visually resemble Latin ones).
3. The normalized domain is compared against a list of 32 well-known brand domains (Google, Microsoft, Apple, Amazon, PayPal, etc.) using Levenshtein distance.
4. If the edit distance is within a configurable threshold (indicating a near-match but not exact match), an alert is generated with the title "Typosquat Domain Detection".
5. This catches domains like `g00gle.com`, `micros0ft.com`, `paypa1.com`, etc.

### Key Properties

- **Not a rule** -- this is built into the detection engine itself and cannot be disabled via the rules API.
- **32 monitored brands** -- covers major tech companies, banks, social media, and email providers.
- **Homoglyph-aware** -- normalizes Unicode lookalike characters before comparison.
- **Levenshtein distance** -- catches character transpositions, additions, and substitutions.

## Suppression Rules

Suppression rules filter out known-benign events before they reach the detection engine. They use the same condition syntax as detection rules.

### How Suppressions Work

1. Suppression rules are stored in the `suppression_rules` table.
2. They are loaded into the engine's memory cache alongside detection rules (via `Reload()`).
3. On each event, suppression rules are checked **before** detection rules.
4. If any enabled suppression rule matches (all conditions satisfied for the matching event types), the event is dropped from detection.
5. The suppression rule's `hit_count` is incremented and `last_hit_at` is updated.

### Suppression Rule Schema

```json
{
  "id": "sup-example",
  "name": "Suppress apt-get updates",
  "description": "Ignore apt-get process events during automated updates",
  "enabled": true,
  "event_types": ["PROCESS_EXEC"],
  "conditions": [
    {"field": "process.comm", "op": "eq", "value": "apt-get"}
  ]
}
```

### Managing Suppressions

Suppressions are managed through the Suppressions page in the dashboard or via the API:

- `GET /api/v1/suppressions` -- List all suppression rules
- `POST /api/v1/suppressions` -- Create a new suppression rule
- `PATCH /api/v1/suppressions/:id` -- Update (enable/disable, modify conditions)
- `DELETE /api/v1/suppressions/:id` -- Delete a suppression rule

## IOC Matching

The detection engine maintains in-memory caches of Indicators of Compromise, refreshed from the database every 60 seconds.

### IOC Types

| Type | Checked Against | Fields Examined |
|---|---|---|
| `ip` | Network events | `dst_ip`, `src_ip` |
| `domain` | DNS and browser events | `dns_query`, `resolved_domain`, `query` |
| `hash_sha256` | File and process events | `exe_hash`, `hash_after`, `hash_before` |
| `hash_md5` | File and process events | `exe_hash`, `hash_after`, `hash_before` |

### IOC Alert Generation

When an event field matches an IOC value:

1. A deduplication check is performed (same IOC + agent within 10 minutes).
2. If no existing alert, a new alert is created with title "IOC Match: {type} {value}".
3. The IOC's `hit_count` is incremented.
4. The alert severity matches the IOC's severity level.

### Managing IOCs

IOCs are managed through the IOCs page in the dashboard or via the API:

- `GET /api/v1/iocs` -- List IOCs (with type filter)
- `POST /api/v1/iocs` -- Create a new IOC
- `PATCH /api/v1/iocs/:id` -- Update
- `DELETE /api/v1/iocs/:id` -- Delete
- `POST /api/v1/iocs/sync` -- Sync from threat intelligence feeds

IOC fields:

| Field | Description |
|---|---|
| `type` | ip, domain, hash_sha256, hash_md5 |
| `value` | The indicator value |
| `source` | Origin (manual, feed name) |
| `severity` | 0-4 (info through critical) |
| `description` | Context about the threat |
| `tags` | Classification tags |
| `enabled` | Active/inactive toggle |
| `expires_at` | Optional expiry date |

## Creating Custom Rules via API

### Create a Match Rule

```bash
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Suspicious wget to /tmp",
    "description": "wget or curl downloading files to /tmp directory",
    "severity": 3,
    "event_types": ["PROCESS_EXEC"],
    "conditions": [
      {"field": "process.comm", "op": "in", "value": ["wget", "curl"]},
      {"field": "cmdline", "op": "contains", "value": "/tmp/"}
    ],
    "mitre_ids": ["T1105"],
    "rule_type": "match"
  }'
```

### Create a Threshold Rule

```bash
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DNS Tunneling Detected",
    "description": "100+ DNS queries to the same domain in 5 minutes",
    "severity": 3,
    "event_types": ["NET_DNS"],
    "conditions": [],
    "mitre_ids": ["T1071.004"],
    "rule_type": "threshold",
    "threshold_count": 100,
    "threshold_window_s": 300,
    "group_by": "dns_query"
  }'
```

### Rule API Endpoints

- `GET /api/v1/rules` -- List all rules
- `POST /api/v1/rules` -- Create a new rule
- `PATCH /api/v1/rules/:id` -- Update rule (enable/disable, modify conditions)
- `DELETE /api/v1/rules/:id` -- Delete a rule
- `POST /api/v1/rules/reload` -- Reload all rules from database into engine memory

## Backtesting Rules Against Historical Events

The backend supports backtesting rules against stored events via:

```
POST /api/v1/rules/:id/backtest?window_hours=168
```

This endpoint:

1. Fetches the rule's conditions from the database.
2. Queries up to 10,000 historical events matching the rule's event types within the specified time window (default: 168 hours / 7 days).
3. Evaluates the rule's conditions against each event.
4. Returns:
   - **match_count**: Number of events that would have triggered the rule.
   - **match_rate**: Percentage of evaluated events that matched.
   - **samples**: Up to 5 sample matching events for review.

This allows analysts to test rule effectiveness before enabling it, or to tune conditions to reduce false positives.

### Example

```bash
curl -X POST \
  "http://localhost:8080/api/v1/rules/rule-suspicious-shell/backtest?window_hours=24" \
  -H "Authorization: Bearer <token>"
```

## MITRE ATT&CK Mapping

All seeded rules include MITRE ATT&CK technique IDs. The dashboard renders these as clickable links that open the corresponding technique page on `attack.mitre.org`.

### Techniques Used in Seeded Rules

| Technique | Name | Rules |
|---|---|---|
| T1003 | OS Credential Dumping | Credential Dumper Executed |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Network Share Mounted |
| T1046 | Network Service Discovery | Port Scanner, Port Scan (threshold) |
| T1052.001 | Exfiltration Over Physical Medium: USB | USB Mass Storage Device Connected |
| T1053.003 | Scheduled Task/Job: Cron | Cron Persistence, Suspicious Cron Job, Cron Reverse Shell |
| T1055.001 | Process Injection: DLL Injection | Suspicious Memory Injection |
| T1055.008 | Process Injection: Ptrace | ptrace Injection |
| T1056.004 | Input Capture: Credential API Hooking | Browser Credential Submission |
| T1059 | Command and Scripting Interpreter | Execution Burst |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Web Shell, Reverse Shell, Cron Reverse Shell |
| T1070.003 | Indicator Removal: Clear Command History | History Evasion |
| T1071 | Application Layer Protocol | Outbound High Port, Beaconing, Named Pipe in Temp |
| T1071.001 | Application Layer Protocol: Web Protocols | TLS Rare TLD, TLS Beaconing |
| T1071.004 | Application Layer Protocol: DNS | DNS Rare TLD |
| T1110 | Brute Force | SSH Brute Force |
| T1110.001 | Brute Force: Password Guessing | Login Brute Force, SSH Brute Force Single IP |
| T1190 | Exploit Public-Facing Application | Web Shell |
| T1200 | Hardware Additions | USB Rapid Connect Burst |
| T1204.001 | User Execution: Malicious Link | Browser High Volume |
| T1547.006 | Boot or Logon Autostart: Kernel Modules and Extensions | Unsigned Kernel Module, Kernel Tainted |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | sudoers Write, Sudo Root Shell |
| T1566.002 | Phishing: Spearphishing Link | IOC Domain, Redirect Chain, Rare TLD Form |
| T1568.002 | Dynamic Resolution: DGA | DGA Domain |
| T1570 | Lateral Tool Transfer | Named Pipe in Temp |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | TLS Beaconing |
| T1574.006 | Hijack Execution Flow: LD_PRELOAD | LD_PRELOAD Hijack |
| T1620 | Reflective Code Loading | memfd Exec, Memory Injection |
