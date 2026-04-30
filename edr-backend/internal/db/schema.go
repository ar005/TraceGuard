// internal/db/schema.go
// PostgreSQL schema for the EDR backend.
// Applied at startup via RunMigrations().

package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
)

// migrations is an ordered list of SQL statements.
// Each is idempotent (IF NOT EXISTS / CREATE INDEX CONCURRENTLY etc.).
var migrations = []struct {
	name string
	sql  string
}{
	{
		name: "create_agents",
		sql: `
		CREATE TABLE IF NOT EXISTS agents (
			id           TEXT PRIMARY KEY,
			hostname     TEXT NOT NULL,
			os           TEXT NOT NULL DEFAULT '',
			os_version   TEXT NOT NULL DEFAULT '',
			ip           TEXT NOT NULL DEFAULT '',
			agent_ver    TEXT NOT NULL DEFAULT '',
			first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			is_online    BOOLEAN NOT NULL DEFAULT FALSE,
			config_ver   TEXT NOT NULL DEFAULT '0'
		);`,
	},
	{
		name: "create_events",
		sql: `
		CREATE TABLE IF NOT EXISTS events (
			id           TEXT PRIMARY KEY,
			agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			hostname     TEXT NOT NULL,
			event_type   TEXT NOT NULL,
			timestamp    TIMESTAMPTZ NOT NULL,
			payload      JSONB NOT NULL,
			received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			severity     SMALLINT NOT NULL DEFAULT 0,
			rule_id      TEXT NOT NULL DEFAULT '',
			alert_id     TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS events_agent_id_idx   ON events(agent_id);
		CREATE INDEX IF NOT EXISTS events_event_type_idx ON events(event_type);
		CREATE INDEX IF NOT EXISTS events_timestamp_idx  ON events(timestamp DESC);
		CREATE INDEX IF NOT EXISTS events_payload_gin    ON events USING GIN(payload);
		`,
	},
	{
		name: "create_alerts",
		sql: `
		CREATE TABLE IF NOT EXISTS alerts (
			id           TEXT PRIMARY KEY,
			title        TEXT NOT NULL,
			description  TEXT NOT NULL DEFAULT '',
			severity     SMALLINT NOT NULL DEFAULT 2,
			status       TEXT NOT NULL DEFAULT 'OPEN',
			rule_id      TEXT NOT NULL DEFAULT '',
			rule_name    TEXT NOT NULL DEFAULT '',
			mitre_ids    TEXT[] NOT NULL DEFAULT '{}',
			event_ids    TEXT[] NOT NULL DEFAULT '{}',
			agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			hostname     TEXT NOT NULL,
			first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			assignee     TEXT NOT NULL DEFAULT '',
			notes        TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS alerts_agent_id_idx  ON alerts(agent_id);
		CREATE INDEX IF NOT EXISTS alerts_status_idx    ON alerts(status);
		CREATE INDEX IF NOT EXISTS alerts_severity_idx  ON alerts(severity DESC);
		CREATE INDEX IF NOT EXISTS alerts_first_seen_idx ON alerts(first_seen DESC);
		`,
	},
	{
		name: "create_rules",
		sql: `
		CREATE TABLE IF NOT EXISTS rules (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			enabled     BOOLEAN NOT NULL DEFAULT TRUE,
			severity    SMALLINT NOT NULL DEFAULT 2,
			event_types TEXT[] NOT NULL DEFAULT '{}',
			conditions  JSONB NOT NULL DEFAULT '[]',
			mitre_ids   TEXT[] NOT NULL DEFAULT '{}',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			author      TEXT NOT NULL DEFAULT 'system'
		);
		`,
	},
	{
		name: "seed_default_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author)
		VALUES
		(
			'rule-suspicious-shell',
			'Web Server Spawning Shell',
			'A web server process (nginx, apache, php) spawned an interactive shell — possible webshell or RCE.',
			3,
			ARRAY['PROCESS_EXEC'],
			'[{"field":"process.comm","op":"in","value":["nginx","apache2","httpd","php","php-fpm"]},{"field":"process.child_comm","op":"in","value":["bash","sh","dash","zsh","ksh","python","python3","perl","ruby"]}]',
			ARRAY['T1059.004','T1190'],
			'system'
		),
		(
			'rule-ptrace-injection',
			'Process Injection via ptrace',
			'A process used ptrace ATTACH or POKETEXT on another process — classic code injection pattern.',
			3,
			ARRAY['PROCESS_PTRACE'],
			'[{"field":"ptrace_request","op":"in","value":[16,4,5,13]}]',
			ARRAY['T1055.008'],
			'system'
		),
		(
			'rule-memfd-exec',
			'Fileless Execution (memfd)',
			'A binary was executed from a memfd — common technique for in-memory malware.',
			4,
			ARRAY['PROCESS_EXEC'],
			'[{"field":"is_memfd","op":"eq","value":true}]',
			ARRAY['T1620'],
			'system'
		),
		(
			'rule-sudoers-write',
			'sudoers File Modified',
			'A process wrote to /etc/sudoers or /etc/sudoers.d/ — possible privilege escalation persistence.',
			4,
			ARRAY['FILE_WRITE','FILE_CREATE'],
			'[{"field":"path","op":"startswith","value":"/etc/sudoers"}]',
			ARRAY['T1548.003'],
			'system'
		),
		(
			'rule-cron-write',
			'Cron Persistence Established',
			'A file was created or modified in a cron directory — possible persistence mechanism.',
			3,
			ARRAY['FILE_WRITE','FILE_CREATE'],
			'[{"field":"path","op":"regex","value":"^/etc/cron|^/var/spool/cron"}]',
			ARRAY['T1053.003'],
			'system'
		),
		(
			'rule-outbound-high-port',
			'Unusual Outbound Connection on High Port',
			'Process connected to an external IP on a high port (>49151) — potential C2 beaconing.',
			2,
			ARRAY['NET_CONNECT'],
			'[{"field":"direction","op":"eq","value":"OUTBOUND"},{"field":"dst_port","op":"gt","value":49151},{"field":"is_private","op":"eq","value":false}]',
			ARRAY['T1071'],
			'system'
		),
		(
			'rule-ld-preload-write',
			'LD_PRELOAD Hijack Attempt',
			'A process wrote to /etc/ld.so.preload — classic rootkit persistence technique.',
			4,
			ARRAY['FILE_WRITE','FILE_CREATE'],
			'[{"field":"path","op":"eq","value":"/etc/ld.so.preload"}]',
			ARRAY['T1574.006'],
			'system'
		)

		-- CMD monitor rules (added in phase 2)
		,
		(
			'rule-cmd-revshell',
			'Reverse Shell Command Detected',
			'A command containing reverse shell patterns (bash -i, nc -e, /dev/tcp) was executed in an interactive terminal.',
			4,
			ARRAY['CMD_EXEC','CMD_HISTORY'],
			'[{"field":"tags","op":"contains","value":"revshell"}]',
			ARRAY['T1059.004'],
			'system'
		),
		(
			'rule-cmd-history-evasion',
			'History Evasion Detected',
			'User attempted to clear or disable shell history — likely cover-track behavior.',
			3,
			ARRAY['CMD_EXEC','CMD_HISTORY'],
			'[{"field":"tags","op":"contains","value":"history-evasion"}]',
			ARRAY['T1070.003'],
			'system'
		),
		(
			'rule-cmd-port-scan',
			'Port Scanner Executed',
			'nmap, masscan or similar port scanner was run interactively.',
			3,
			ARRAY['CMD_EXEC','CMD_HISTORY'],
			'[{"field":"tags","op":"contains","value":"port-scan"}]',
			ARRAY['T1046'],
			'system'
		),
		(
			'rule-cmd-cred-dumper',
			'Credential Dumper Executed',
			'mimikatz, LaZagne or secretsdump was executed — credential theft attempt.',
			4,
			ARRAY['CMD_EXEC','CMD_HISTORY'],
			'[{"field":"tags","op":"contains","value":"cred-dumper"}]',
			ARRAY['T1003'],
			'system'
		),
		(
			'rule-cmd-sudo-root',
			'Sudo Root Shell Escalation',
			'User escalated to root shell via sudo — verify legitimacy.',
			3,
			ARRAY['CMD_EXEC','CMD_HISTORY'],
			'[{"field":"tags","op":"contains","value":"sudo-root-shell"}]',
			ARRAY['T1548.003'],
			'system'
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "create_api_keys",
		sql: `
		CREATE TABLE IF NOT EXISTS api_keys (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			prefix       TEXT NOT NULL,
			hash         TEXT NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at   TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			created_by   TEXT NOT NULL DEFAULT 'api',
			enabled      BOOLEAN NOT NULL DEFAULT TRUE
		);
		CREATE INDEX IF NOT EXISTS api_keys_prefix_idx  ON api_keys(prefix);
		CREATE INDEX IF NOT EXISTS api_keys_enabled_idx ON api_keys(enabled);
		`,
	},
	{
		name: "create_users",
		sql: `
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			username      TEXT NOT NULL UNIQUE,
			email         TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			role          TEXT NOT NULL DEFAULT 'analyst',
			enabled       BOOLEAN NOT NULL DEFAULT TRUE,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_login_at TIMESTAMPTZ,
			created_by    TEXT NOT NULL DEFAULT 'system'
		);
		CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);
		`,
	},
	{
		name: "create_audit_log",
		sql: `
		CREATE TABLE IF NOT EXISTS audit_log (
			id          BIGSERIAL PRIMARY KEY,
			timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			actor_id    TEXT NOT NULL DEFAULT '',
			actor_name  TEXT NOT NULL DEFAULT '',
			action      TEXT NOT NULL,
			target_type TEXT NOT NULL DEFAULT '',
			target_id   TEXT NOT NULL DEFAULT '',
			target_name TEXT NOT NULL DEFAULT '',
			ip          TEXT NOT NULL DEFAULT '',
			details     TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS audit_log_timestamp_idx ON audit_log(timestamp DESC);
		CREATE INDEX IF NOT EXISTS audit_log_actor_id_idx  ON audit_log(actor_id);
		`,
	},
	{
		name: "add_agent_tags",
		sql: `
		ALTER TABLE agents ADD COLUMN IF NOT EXISTS tags  TEXT[]  NOT NULL DEFAULT '{}';
		ALTER TABLE agents ADD COLUMN IF NOT EXISTS env   TEXT    NOT NULL DEFAULT '';
		ALTER TABLE agents ADD COLUMN IF NOT EXISTS notes TEXT    NOT NULL DEFAULT '';
		CREATE INDEX IF NOT EXISTS agents_tags_idx ON agents USING GIN(tags);
		`,
	},
	{
		name: "create_settings",
		sql: `
		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		-- Default retention: 30 days events, 90 days alerts
		INSERT INTO settings (key, value) VALUES
			('retention_events_days', '30'),
			('retention_alerts_days', '90')
		ON CONFLICT (key) DO NOTHING;
		`,
	},
	{
		name: "add_alert_dedup_fields",
		sql: `
		ALTER TABLE alerts ADD COLUMN IF NOT EXISTS hit_count BIGINT NOT NULL DEFAULT 1;
		`,
	},
	{
		name: "add_threshold_rule_fields",
		sql: `
		-- rule_type: 'match' (default, current behaviour) or 'threshold'
		ALTER TABLE rules ADD COLUMN IF NOT EXISTS rule_type           TEXT    NOT NULL DEFAULT 'match';
		ALTER TABLE rules ADD COLUMN IF NOT EXISTS threshold_count     INT     NOT NULL DEFAULT 0;
		ALTER TABLE rules ADD COLUMN IF NOT EXISTS threshold_window_s  INT     NOT NULL DEFAULT 60;
		ALTER TABLE rules ADD COLUMN IF NOT EXISTS group_by            TEXT    NOT NULL DEFAULT 'agent_id';
		-- Threshold rules: seed three real-world examples
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by)
		VALUES
		(
			'rule-thresh-port-scan',
			'Port Scan Detected (threshold)',
			'A single process made 20+ outbound TCP connections in 30 seconds — likely port scanning.',
			3,
			ARRAY['NET_CONNECT'],
			'[{"field":"direction","op":"eq","value":"OUTBOUND"}]',
			ARRAY['T1046'],
			'system',
			'threshold', 20, 30, 'process.pid'
		),
		(
			'rule-thresh-brute-force',
			'SSH Brute Force (threshold)',
			'20+ inbound SSH connections from different sources in 60 seconds — possible brute force.',
			3,
			ARRAY['NET_ACCEPT','NET_CONNECT'],
			'[{"field":"dst_port","op":"eq","value":22}]',
			ARRAY['T1110'],
			'system',
			'threshold', 20, 60, 'agent_id'
		),
		(
			'rule-thresh-beaconing',
			'C2 Beaconing Detected (threshold)',
			'10+ outbound connections to the same external host in 5 minutes — possible C2 beaconing.',
			3,
			ARRAY['NET_CONNECT'],
			'[{"field":"direction","op":"eq","value":"OUTBOUND"},{"field":"is_private","op":"eq","value":false}]',
			ARRAY['T1071'],
			'system',
			'threshold', 10, 300, 'dst_ip'
		),
		(
			'rule-thresh-exec-burst',
			'Execution Burst (threshold)',
			'30+ process executions in 60 seconds on the same host — possible script-based attack.',
			2,
			ARRAY['PROCESS_EXEC'],
			'[]',
			ARRAY['T1059'],
			'system',
			'threshold', 30, 60, 'agent_id'
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "create_suppression_rules",
		sql: `
		CREATE TABLE IF NOT EXISTS suppression_rules (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			enabled     BOOLEAN NOT NULL DEFAULT TRUE,
			event_types TEXT[] NOT NULL DEFAULT '{}',
			conditions  JSONB NOT NULL DEFAULT '[]',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			author      TEXT NOT NULL DEFAULT 'system',
			hit_count   BIGINT NOT NULL DEFAULT 0,
			last_hit_at TIMESTAMPTZ
		);
		CREATE INDEX IF NOT EXISTS sup_rules_enabled_idx ON suppression_rules(enabled);
		`,
	},
	{
		name: "create_incidents",
		sql: `
		CREATE TABLE IF NOT EXISTS incidents (
			id          TEXT PRIMARY KEY,
			title       TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			severity    SMALLINT NOT NULL DEFAULT 2,
			status      TEXT NOT NULL DEFAULT 'OPEN',
			alert_ids   TEXT[] NOT NULL DEFAULT '{}',
			agent_ids   TEXT[] NOT NULL DEFAULT '{}',
			hostnames   TEXT[] NOT NULL DEFAULT '{}',
			mitre_ids   TEXT[] NOT NULL DEFAULT '{}',
			alert_count INT NOT NULL DEFAULT 0,
			first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			assignee    TEXT NOT NULL DEFAULT '',
			notes       TEXT NOT NULL DEFAULT '',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS incidents_status_idx     ON incidents(status);
		CREATE INDEX IF NOT EXISTS incidents_severity_idx   ON incidents(severity DESC);
		CREATE INDEX IF NOT EXISTS incidents_last_seen_idx  ON incidents(last_seen DESC);

		ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident_id TEXT NOT NULL DEFAULT '';
		CREATE INDEX IF NOT EXISTS alerts_incident_id_idx ON alerts(incident_id);
		`,
	},
	{
		name: "seed_auth_detection_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by)
		VALUES
		(
			'rule-thresh-login-brute',
			'Login Brute Force (threshold)',
			'10+ failed login attempts on the same host in 120 seconds — possible brute force attack.',
			3,
			ARRAY['LOGIN_FAILED'],
			'[]',
			ARRAY['T1110.001'],
			'system',
			'threshold', 10, 120, 'agent_id'
		),
		(
			'rule-ssh-brute-source',
			'SSH Brute Force from Single IP (threshold)',
			'5+ failed SSH logins from the same source IP in 60 seconds.',
			3,
			ARRAY['LOGIN_FAILED'],
			'[{"field":"service","op":"eq","value":"sshd"}]',
			ARRAY['T1110.001'],
			'system',
			'threshold', 5, 60, 'source_ip'
		),
		(
			'rule-sudo-root-shell',
			'Sudo to Root Shell',
			'User executed a root shell via sudo — verify this was authorized.',
			2,
			ARRAY['SUDO_EXEC'],
			'[{"field":"target_user","op":"eq","value":"root"},{"field":"command","op":"regex","value":"(bash|sh|zsh|dash|fish)$"}]',
			ARRAY['T1548.003'],
			'system',
			'match', 0, 0, ''
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "create_agent_packages_and_vulnerabilities",
		sql: `
		CREATE TABLE IF NOT EXISTS agent_packages (
			id BIGSERIAL PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			arch TEXT NOT NULL DEFAULT '',
			collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS agent_packages_agent_idx ON agent_packages(agent_id);
		CREATE INDEX IF NOT EXISTS agent_packages_name_idx ON agent_packages(name);

		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id BIGSERIAL PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			package_name TEXT NOT NULL,
			package_version TEXT NOT NULL,
			cve_id TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'UNKNOWN',
			description TEXT NOT NULL DEFAULT '',
			fixed_version TEXT NOT NULL DEFAULT '',
			detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS vulns_agent_idx ON vulnerabilities(agent_id);
		CREATE INDEX IF NOT EXISTS vulns_cve_idx ON vulnerabilities(cve_id);
		CREATE INDEX IF NOT EXISTS vulns_severity_idx ON vulnerabilities(severity);
		`,
	},
	{
		name: "create_iocs",
		sql: `
		CREATE TABLE IF NOT EXISTS iocs (
			id           TEXT PRIMARY KEY,
			type         TEXT NOT NULL,
			value        TEXT NOT NULL,
			source       TEXT NOT NULL DEFAULT 'manual',
			severity     SMALLINT NOT NULL DEFAULT 3,
			description  TEXT NOT NULL DEFAULT '',
			tags         TEXT[] NOT NULL DEFAULT '{}',
			enabled      BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at   TIMESTAMPTZ,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			hit_count    BIGINT NOT NULL DEFAULT 0,
			last_hit_at  TIMESTAMPTZ
		);
		CREATE UNIQUE INDEX IF NOT EXISTS iocs_type_value_idx ON iocs(type, value);
		CREATE INDEX IF NOT EXISTS iocs_type_idx     ON iocs(type);
		CREATE INDEX IF NOT EXISTS iocs_enabled_idx  ON iocs(enabled);
		CREATE INDEX IF NOT EXISTS iocs_source_idx   ON iocs(source);
		CREATE INDEX IF NOT EXISTS iocs_value_idx    ON iocs(value);
		`,
	},
	{
		name: "seed_browser_phishing_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by)
		VALUES
		(
			'rule-browser-form-submit-unknown',
			'Credential Submission to Non-Allowlisted Domain',
			'A user submitted a form (POST to main_frame) to a domain not in the organization allowlist — possible phishing credential harvest.',
			3,
			ARRAY['BROWSER_REQUEST'],
			'[{"field":"is_form_submit","op":"eq","value":true},{"field":"tags","op":"contains","value":"auth-page"}]',
			ARRAY['T1056.004'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-browser-ioc-domain-visit',
			'Browser Visited IOC-Flagged Domain',
			'A user navigated to a domain flagged in the threat intelligence IOC feed.',
			4,
			ARRAY['BROWSER_REQUEST'],
			'[{"field":"resource_type","op":"eq","value":"main_frame"}]',
			ARRAY['T1566.002'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-browser-redirect-chain',
			'Suspicious Redirect Chain Detected',
			'A browser request followed a redirect chain (3+ hops) — common in phishing campaigns using URL shorteners.',
			2,
			ARRAY['BROWSER_REQUEST'],
			'[{"field":"redirect_chain","op":"length_gte","value":3}]',
			ARRAY['T1566.002'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-browser-rare-tld-form',
			'Form Submission to Rare TLD',
			'A user submitted a form to a domain with a known-abuse TLD (.tk, .xyz, .top, .pw, .click, etc.).',
			3,
			ARRAY['BROWSER_REQUEST'],
			'[{"field":"is_form_submit","op":"eq","value":true},{"field":"domain","op":"regex","value":"\\.(tk|xyz|top|pw|cc|ws|click|link|work|date|download|racing|stream|gdn|bid)$"}]',
			ARRAY['T1566.002'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-browser-high-volume',
			'Browser High Volume Requests (threshold)',
			'50+ browser requests in 60 seconds to the same domain — possible automated phishing page or malicious redirect loop.',
			2,
			ARRAY['BROWSER_REQUEST'],
			'[]',
			ARRAY['T1204.001'],
			'system',
			'threshold', 50, 60, 'domain'
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "seed_kmod_usb_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by)
		VALUES
		(
			'rule-kmod-unsigned',
			'Unsigned Kernel Module Loaded',
			'A kernel module was loaded without a valid signature — possible rootkit or unauthorized driver.',
			4,
			ARRAY['KERNEL_MODULE_LOAD'],
			'[{"field":"signed","op":"eq","value":false}]',
			ARRAY['T1547.006'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-kmod-tainted',
			'Kernel Tainted After Module Load',
			'The kernel became tainted after loading a module — indicates an out-of-tree or proprietary module.',
			2,
			ARRAY['KERNEL_MODULE_LOAD'],
			'[{"field":"tainted","op":"eq","value":true}]',
			ARRAY['T1547.006'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-usb-mass-storage',
			'USB Mass Storage Device Connected',
			'A USB mass storage device (flash drive, external HDD) was plugged in — potential data exfiltration or malware vector.',
			2,
			ARRAY['USB_CONNECT'],
			'[{"field":"dev_type","op":"eq","value":"mass_storage"}]',
			ARRAY['T1052.001'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-usb-burst',
			'Multiple USB Devices Connected Rapidly (threshold)',
			'3+ USB devices connected within 60 seconds — possible USB attack (BadUSB, rubber ducky).',
			3,
			ARRAY['USB_CONNECT'],
			'[]',
			ARRAY['T1200'],
			'system',
			'threshold', 3, 60, 'agent_id'
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "seed_memmon_cron_pipe_share_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by)
		VALUES
		(
			'rule-memory-inject',
			'Suspicious Memory Injection Detected',
			'Anonymous executable memory region detected in a process — possible shellcode injection or reflective loading.',
			4,
			ARRAY['MEMORY_INJECT'],
			'[]',
			ARRAY['T1055.001','T1620'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-cron-suspicious',
			'Suspicious Cron Job Created',
			'A cron entry was created or modified containing download commands, encoded payloads, or reverse shell patterns.',
			3,
			ARRAY['CRON_MODIFY'],
			'[{"field":"suspicious","op":"eq","value":true}]',
			ARRAY['T1053.003'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-cron-reverse-shell',
			'Cron Job with Reverse Shell Pattern',
			'A cron entry contains reverse shell indicators (/dev/tcp, nc -e, bash -i).',
			4,
			ARRAY['CRON_MODIFY'],
			'[{"field":"cron_tags","op":"contains","value":"reverse-shell"}]',
			ARRAY['T1053.003','T1059.004'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-pipe-tmp',
			'Named Pipe Created in Temp Directory',
			'A FIFO/named pipe was created in /tmp, /var/tmp, or /dev/shm — used by C2 frameworks (Cobalt Strike, PsExec) for inter-process communication.',
			3,
			ARRAY['PIPE_CREATE'],
			'[{"field":"location","op":"in","value":["tmp","dev_shm"]}]',
			ARRAY['T1570','T1071'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-share-mount',
			'Network Share Mounted',
			'A CIFS/NFS network share was mounted — potential lateral movement or data staging.',
			2,
			ARRAY['SHARE_MOUNT'],
			'[]',
			ARRAY['T1021.002'],
			'system',
			'match', 0, 0, ''
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "seed_tlssni_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
		                   rule_type, threshold_count, threshold_window_s, group_by)
		VALUES
		(
			'rule-tlssni-rare-tld',
			'TLS Connection to Rare TLD',
			'A process established a TLS connection to a domain with a known-abuse TLD (.tk, .xyz, .top, .pw, .click, etc.).',
			2,
			ARRAY['NET_TLS_SNI'],
			'[{"field":"domain","op":"regex","value":"\\.(tk|xyz|top|pw|cc|ws|click|link|work|date|download|racing|stream|gdn|bid)$"}]',
			ARRAY['T1071.001'],
			'system',
			'match', 0, 0, ''
		),
		(
			'rule-tlssni-beaconing',
			'TLS Beaconing to Single Domain (threshold)',
			'20+ TLS connections to the same external domain in 5 minutes — possible C2 beaconing.',
			3,
			ARRAY['NET_TLS_SNI'],
			'[]',
			ARRAY['T1071.001','T1573.002'],
			'system',
			'threshold', 20, 300, 'domain'
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	},
	{
		name: "create_cve_cache",
		sql: `
		CREATE TABLE IF NOT EXISTS cve_cache (
			cve_id         TEXT PRIMARY KEY,
			severity       TEXT NOT NULL DEFAULT 'UNKNOWN',
			description    TEXT NOT NULL DEFAULT '',
			published_date TIMESTAMPTZ,
			"references"   TEXT[] NOT NULL DEFAULT '{}',
			exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
			cisa_kev       BOOLEAN NOT NULL DEFAULT FALSE,
			source         TEXT NOT NULL DEFAULT 'nvd',
			fetched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			raw_json       JSONB
		);
		CREATE INDEX IF NOT EXISTS cve_cache_severity_idx ON cve_cache(severity);
		CREATE INDEX IF NOT EXISTS cve_cache_fetched_idx ON cve_cache(fetched_at);
		`,
	},
	{
		name: "add_agent_winevent_config",
		sql: `
		ALTER TABLE agents ADD COLUMN IF NOT EXISTS winevent_config JSONB NOT NULL DEFAULT '{}';
		`,
	},
	{
		name: "add_totp_columns",
		sql: `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret       TEXT NOT NULL DEFAULT '';
		ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled      BOOLEAN NOT NULL DEFAULT FALSE;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_backup_codes TEXT NOT NULL DEFAULT '';
		`,
	},
	{
		name: "create_pending_commands",
		sql: `
		CREATE TABLE IF NOT EXISTS pending_commands (
			id         TEXT PRIMARY KEY,
			agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			action     TEXT NOT NULL,
			args       JSONB NOT NULL DEFAULT '[]',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			status     TEXT NOT NULL DEFAULT 'pending',
			result     JSONB,
			executed_at TIMESTAMPTZ
		);
		CREATE INDEX IF NOT EXISTS idx_pending_commands_agent_status ON pending_commands(agent_id, status);
		`,
	},
	{
		name: "add_api_key_role",
		sql: `
		ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin';
		`,
	},
	{
		name: "add_performance_indexes",
		sql: `
    -- Fast alert dedup lookups (FindOpenAlert called on every event ingested)
    CREATE INDEX IF NOT EXISTS alerts_dedup_idx
        ON alerts(rule_id, agent_id, status, last_seen DESC);

    -- Fast alert list by agent
    CREATE INDEX IF NOT EXISTS alerts_agent_status_idx
        ON alerts(agent_id, status, last_seen DESC);

    -- Process tree PID lookups (avoids per-node table scan)
    CREATE INDEX IF NOT EXISTS events_process_pid_idx
        ON events(CAST(payload->>'pid' AS bigint))
        WHERE event_type = 'PROCESS_EXEC';

    -- Fast event lookup by agent + type + time (most common query pattern)
    CREATE INDEX IF NOT EXISTS events_agent_type_ts_idx
        ON events(agent_id, event_type, timestamp DESC);

    -- Incident alert joins
    CREATE INDEX IF NOT EXISTS alerts_incident_idx
        ON alerts(incident_id) WHERE incident_id IS NOT NULL;
    `,
	},
	{
		name: "xdr_phase0_schema",
		sql: `
    -- XDR Phase 0: extend events table with OCSF and cross-source fields.
    -- All new columns have safe defaults so existing rows are unaffected.

    ALTER TABLE events
        ADD COLUMN IF NOT EXISTS class_uid    INTEGER      NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS category_uid SMALLINT     NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS activity_id  SMALLINT     NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS source_type  TEXT         NOT NULL DEFAULT 'endpoint',
        ADD COLUMN IF NOT EXISTS source_id    TEXT         NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS tenant_id    TEXT         NOT NULL DEFAULT 'default',
        ADD COLUMN IF NOT EXISTS user_uid     TEXT         NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS src_ip       INET,
        ADD COLUMN IF NOT EXISTS dst_ip       INET,
        ADD COLUMN IF NOT EXISTS process_name TEXT         NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS raw_log      TEXT         NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS enrichments  JSONB        NOT NULL DEFAULT '{}';

    CREATE INDEX IF NOT EXISTS events_source_type_idx ON events(source_type, timestamp DESC);
    CREATE INDEX IF NOT EXISTS events_source_id_idx   ON events(source_id,   timestamp DESC)
        WHERE source_id != '';
    CREATE INDEX IF NOT EXISTS events_user_uid_idx    ON events(user_uid)
        WHERE user_uid != '';
    CREATE INDEX IF NOT EXISTS events_src_ip_idx      ON events(src_ip)
        WHERE src_ip IS NOT NULL;
    CREATE INDEX IF NOT EXISTS events_dst_ip_idx      ON events(dst_ip)
        WHERE dst_ip IS NOT NULL;
    CREATE INDEX IF NOT EXISTS events_tenant_idx      ON events(tenant_id, timestamp DESC);

    -- xdr_sources: connector registry
    CREATE TABLE IF NOT EXISTS xdr_sources (
        id            TEXT PRIMARY KEY,
        name          TEXT        NOT NULL,
        source_type   TEXT        NOT NULL,
        connector     TEXT        NOT NULL,
        config        JSONB       NOT NULL DEFAULT '{}',
        enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
        last_seen_at  TIMESTAMPTZ,
        events_today  BIGINT      NOT NULL DEFAULT 0,
        error_state   TEXT        NOT NULL DEFAULT '',
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS xdr_sources_type_idx ON xdr_sources(source_type);

    -- identity_graph: normalized cross-source user identities
    CREATE TABLE IF NOT EXISTS identity_graph (
        id              TEXT PRIMARY KEY,
        canonical_uid   TEXT        NOT NULL UNIQUE,
        display_name    TEXT        NOT NULL DEFAULT '',
        department      TEXT        NOT NULL DEFAULT '',
        title           TEXT        NOT NULL DEFAULT '',
        manager_uid     TEXT        NOT NULL DEFAULT '',
        account_ids     JSONB       NOT NULL DEFAULT '{}',
        risk_score      SMALLINT    NOT NULL DEFAULT 0,
        risk_factors    JSONB       NOT NULL DEFAULT '[]',
        is_privileged   BOOLEAN     NOT NULL DEFAULT FALSE,
        is_service_acct BOOLEAN     NOT NULL DEFAULT FALSE,
        last_login_at   TIMESTAMPTZ,
        last_seen_src   TEXT        NOT NULL DEFAULT '',
        agent_ids       TEXT[]      NOT NULL DEFAULT '{}',
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ig_risk_score_idx  ON identity_graph(risk_score DESC);
    CREATE INDEX IF NOT EXISTS ig_privileged_idx  ON identity_graph(is_privileged)
        WHERE is_privileged;
    CREATE INDEX IF NOT EXISTS ig_account_ids_idx ON identity_graph USING GIN(account_ids);

    -- asset_inventory: unified endpoint + cloud + network device registry
    CREATE TABLE IF NOT EXISTS asset_inventory (
        id                TEXT PRIMARY KEY,
        asset_type        TEXT        NOT NULL,
        hostname          TEXT        NOT NULL DEFAULT '',
        ip_addresses      TEXT[]      NOT NULL DEFAULT '{}',
        mac_addresses     TEXT[]      NOT NULL DEFAULT '{}',
        os                TEXT        NOT NULL DEFAULT '',
        os_version        TEXT        NOT NULL DEFAULT '',
        cloud_provider    TEXT        NOT NULL DEFAULT '',
        cloud_region      TEXT        NOT NULL DEFAULT '',
        cloud_account     TEXT        NOT NULL DEFAULT '',
        cloud_resource_id TEXT        NOT NULL DEFAULT '',
        agent_id          TEXT        REFERENCES agents(id) ON DELETE SET NULL,
        tags              TEXT[]      NOT NULL DEFAULT '{}',
        risk_score        SMALLINT    NOT NULL DEFAULT 0,
        criticality       SMALLINT    NOT NULL DEFAULT 1,
        owner_uid         TEXT        NOT NULL DEFAULT '',
        first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        source_id         TEXT        REFERENCES xdr_sources(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS asset_hostname_idx ON asset_inventory(hostname);
    CREATE INDEX IF NOT EXISTS asset_ip_idx       ON asset_inventory USING GIN(ip_addresses);
    CREATE INDEX IF NOT EXISTS asset_type_idx     ON asset_inventory(asset_type);
    CREATE INDEX IF NOT EXISTS asset_agent_idx    ON asset_inventory(agent_id)
        WHERE agent_id IS NOT NULL;

    -- playbook_runs: SOAR execution audit trail (Phase 3)
    CREATE TABLE IF NOT EXISTS playbook_runs (
        id            TEXT PRIMARY KEY,
        playbook_id   TEXT        NOT NULL,
        playbook_name TEXT        NOT NULL,
        trigger_type  TEXT        NOT NULL,
        trigger_id    TEXT        NOT NULL,
        status        TEXT        NOT NULL DEFAULT 'running',
        started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        finished_at   TIMESTAMPTZ,
        actions_log   JSONB       NOT NULL DEFAULT '[]',
        triggered_by  TEXT        NOT NULL DEFAULT 'system',
        error         TEXT        NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS pr_trigger_idx ON playbook_runs(trigger_id);
    CREATE INDEX IF NOT EXISTS pr_status_idx  ON playbook_runs(status, started_at DESC);

    -- xdr_network_flows: high-volume network flow data (separate from events).
    -- Partitioned by start_time (daily). PRIMARY KEY must include partition key.
    CREATE TABLE IF NOT EXISTS xdr_network_flows (
        id          TEXT        NOT NULL,
        source_id   TEXT        NOT NULL,
        tenant_id   TEXT        NOT NULL DEFAULT 'default',
        start_time  TIMESTAMPTZ NOT NULL,
        end_time    TIMESTAMPTZ,
        src_ip      INET        NOT NULL,
        dst_ip      INET        NOT NULL,
        src_port    INTEGER,
        dst_port    INTEGER,
        protocol    TEXT        NOT NULL DEFAULT '',
        bytes_in    BIGINT      NOT NULL DEFAULT 0,
        bytes_out   BIGINT      NOT NULL DEFAULT 0,
        packets_in  INTEGER     NOT NULL DEFAULT 0,
        packets_out INTEGER     NOT NULL DEFAULT 0,
        flow_state  TEXT        NOT NULL DEFAULT '',
        service     TEXT        NOT NULL DEFAULT '',
        agent_id    TEXT,
        user_uid    TEXT        NOT NULL DEFAULT '',
        enrichments JSONB       NOT NULL DEFAULT '{}',
        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (id, start_time)
    ) PARTITION BY RANGE (start_time);

    CREATE TABLE IF NOT EXISTS xdr_network_flows_default
        PARTITION OF xdr_network_flows DEFAULT;

    CREATE INDEX IF NOT EXISTS flows_src_ip_idx ON xdr_network_flows(src_ip, start_time DESC);
    CREATE INDEX IF NOT EXISTS flows_dst_ip_idx ON xdr_network_flows(dst_ip, start_time DESC);
    CREATE INDEX IF NOT EXISTS flows_agent_idx  ON xdr_network_flows(agent_id)
        WHERE agent_id IS NOT NULL;
    `,
	},
	{
		name: "xdr_phase2_schema",
		sql: `
    -- XDR Phase 2: extend alerts + incidents with cross-source identity fields.

    ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS user_uid     TEXT    NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS source_types TEXT[]  NOT NULL DEFAULT '{}';

    CREATE INDEX IF NOT EXISTS alerts_user_uid_idx      ON alerts(user_uid)      WHERE user_uid != '';
    CREATE INDEX IF NOT EXISTS alerts_source_types_idx  ON alerts USING GIN(source_types);

    ALTER TABLE incidents
        ADD COLUMN IF NOT EXISTS user_uids    TEXT[]  NOT NULL DEFAULT '{}',
        ADD COLUMN IF NOT EXISTS src_ips      INET[]  NOT NULL DEFAULT '{}',
        ADD COLUMN IF NOT EXISTS source_types TEXT[]  NOT NULL DEFAULT '{}';

    CREATE INDEX IF NOT EXISTS incidents_user_uids_idx    ON incidents USING GIN(user_uids);
    CREATE INDEX IF NOT EXISTS incidents_source_types_idx ON incidents USING GIN(source_types);

    -- Identity graph: add email + alias support for Phase 2 stitcher.
    ALTER TABLE identity_graph
        ADD COLUMN IF NOT EXISTS email        TEXT    NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS aliases      TEXT[]  NOT NULL DEFAULT '{}';

    CREATE INDEX IF NOT EXISTS identity_email_idx   ON identity_graph(email)   WHERE email != '';
    CREATE INDEX IF NOT EXISTS identity_aliases_idx ON identity_graph USING GIN(aliases);

    -- Asset inventory: track last-seen IP for impossible-travel lookups.
    ALTER TABLE asset_inventory
        ADD COLUMN IF NOT EXISTS last_seen_ip INET;
    `,
	},
	{
		name: "xdr_phase3_schema",
		sql: `
    -- XDR Phase 3: SOAR playbooks + export destinations.

    -- playbooks: SOAR automation rules
    CREATE TABLE IF NOT EXISTS playbooks (
        id            TEXT PRIMARY KEY,
        name          TEXT        NOT NULL,
        description   TEXT        NOT NULL DEFAULT '',
        enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
        trigger_type  TEXT        NOT NULL DEFAULT 'alert',
        trigger_filter JSONB      NOT NULL DEFAULT '{}',
        actions       JSONB       NOT NULL DEFAULT '[]',
        run_count     BIGINT      NOT NULL DEFAULT 0,
        last_run_at   TIMESTAMPTZ,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by    TEXT        NOT NULL DEFAULT 'system'
    );
    CREATE INDEX IF NOT EXISTS playbooks_enabled_idx ON playbooks(enabled);

    -- export_destinations: SIEM / notification sinks
    CREATE TABLE IF NOT EXISTS export_destinations (
        id            TEXT PRIMARY KEY,
        name          TEXT        NOT NULL,
        dest_type     TEXT        NOT NULL,   -- slack|pagerduty|webhook|syslog_cef|email
        config        JSONB       NOT NULL DEFAULT '{}',
        enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
        filter_sev    SMALLINT    NOT NULL DEFAULT 0,
        filter_types  TEXT[]      NOT NULL DEFAULT '{}',
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS export_dest_type_idx ON export_destinations(dest_type);
    CREATE INDEX IF NOT EXISTS export_dest_enabled_idx ON export_destinations(enabled);
    `,
	},
	{
		name: "phase4_case_management",
		sql: `
    -- Phase 4: Case Management — analyst investigation workflow.

    CREATE TABLE IF NOT EXISTS cases (
        id          TEXT PRIMARY KEY,
        title       TEXT        NOT NULL,
        description TEXT        NOT NULL DEFAULT '',
        status      TEXT        NOT NULL DEFAULT 'OPEN',
        severity    SMALLINT    NOT NULL DEFAULT 2,
        assignee    TEXT        NOT NULL DEFAULT '',
        tags        TEXT[]      NOT NULL DEFAULT '{}',
        mitre_ids   TEXT[]      NOT NULL DEFAULT '{}',
        alert_count INT         NOT NULL DEFAULT 0,
        created_by  TEXT        NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        closed_at   TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS cases_status_idx   ON cases(status);
    CREATE INDEX IF NOT EXISTS cases_severity_idx ON cases(severity DESC);
    CREATE INDEX IF NOT EXISTS cases_created_idx  ON cases(created_at DESC);
    CREATE INDEX IF NOT EXISTS cases_assignee_idx ON cases(assignee) WHERE assignee != '';

    CREATE TABLE IF NOT EXISTS case_alerts (
        case_id    TEXT        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        alert_id   TEXT        NOT NULL,
        linked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        linked_by  TEXT        NOT NULL DEFAULT '',
        PRIMARY KEY (case_id, alert_id)
    );
    CREATE INDEX IF NOT EXISTS case_alerts_alert_idx ON case_alerts(alert_id);

    CREATE TABLE IF NOT EXISTS case_notes (
        id         TEXT PRIMARY KEY,
        case_id    TEXT        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        body       TEXT        NOT NULL,
        author     TEXT        NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS case_notes_case_idx ON case_notes(case_id, created_at DESC);
    `,
	},
	{
		name: "phase5_ai_triage",
		sql: `
    -- Phase 5: AI triage fields on alerts.
    ALTER TABLE alerts
        ADD COLUMN IF NOT EXISTS triage_verdict TEXT        NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS triage_score   SMALLINT    NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS triage_notes   TEXT        NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS triage_at      TIMESTAMPTZ;

    CREATE INDEX IF NOT EXISTS alerts_triage_verdict_idx ON alerts(triage_verdict)
        WHERE triage_verdict != '';
    `,
	},
	{
		name: "phase6_container_inventory",
		sql: `
    -- Phase 6: Container & Kubernetes Security Monitoring.

    -- container_inventory: tracked container instances observed via process events.
    CREATE TABLE IF NOT EXISTS container_inventory (
        container_id TEXT        NOT NULL,
        agent_id     TEXT        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        hostname     TEXT        NOT NULL DEFAULT '',
        runtime      TEXT        NOT NULL DEFAULT '',   -- docker, containerd, podman, cri-o
        image_name   TEXT        NOT NULL DEFAULT '',
        pod_name     TEXT        NOT NULL DEFAULT '',
        namespace    TEXT        NOT NULL DEFAULT '',
        first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        event_count  BIGINT      NOT NULL DEFAULT 0,
        PRIMARY KEY (container_id, agent_id)
    );
    CREATE INDEX IF NOT EXISTS ci_agent_idx     ON container_inventory(agent_id);
    CREATE INDEX IF NOT EXISTS ci_runtime_idx   ON container_inventory(runtime)   WHERE runtime   != '';
    CREATE INDEX IF NOT EXISTS ci_namespace_idx ON container_inventory(namespace) WHERE namespace  != '';
    CREATE INDEX IF NOT EXISTS ci_last_seen_idx ON container_inventory(last_seen DESC);

    -- Functional index for fast container_id lookups in event payloads.
    CREATE INDEX IF NOT EXISTS events_container_idx
        ON events ((payload->'process'->>'container_id'))
        WHERE (payload->'process'->>'container_id') IS NOT NULL
          AND (payload->'process'->>'container_id') != '';

    -- Container escape & privilege escalation detection rules.
    INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
                       rule_type, threshold_count, threshold_window_s, group_by)
    VALUES
    (
        'rule-container-nsenter',
        'Container Namespace Escape via nsenter',
        'nsenter or unshare executed inside a container — technique used to escape to host namespaces.',
        4,
        ARRAY['PROCESS_EXEC'],
        '[{"field":"process.container_id","op":"neq","value":""},{"field":"process.comm","op":"in","value":["nsenter","unshare","chroot"]}]',
        ARRAY['T1611'],
        'system',
        'match', 0, 0, ''
    ),
    (
        'rule-container-docker-socket',
        'Docker Socket Accessed from Container',
        'A process inside a container opened /var/run/docker.sock — could allow full host takeover.',
        4,
        ARRAY['FILE_CREATE','FILE_WRITE'],
        '[{"field":"process.container_id","op":"neq","value":""},{"field":"path","op":"eq","value":"/var/run/docker.sock"}]',
        ARRAY['T1611'],
        'system',
        'match', 0, 0, ''
    ),
    (
        'rule-container-proc-host',
        'Container Process Accessing Host /proc',
        'A container process accessed /proc/1 or /proc/*/root — possible container escape via procfs.',
        4,
        ARRAY['FILE_CREATE','FILE_WRITE'],
        '[{"field":"process.container_id","op":"neq","value":""},{"field":"path","op":"regex","value":"^/proc/1/|^/proc/[0-9]+/root"}]',
        ARRAY['T1611'],
        'system',
        'match', 0, 0, ''
    ),
    (
        'rule-container-root-exec',
        'High-Privilege Binary Executed in Container',
        'A root-capability binary (mount, fdisk, modprobe, insmod) was executed inside a container.',
        3,
        ARRAY['PROCESS_EXEC'],
        '[{"field":"process.container_id","op":"neq","value":""},{"field":"process.comm","op":"in","value":["mount","umount","fdisk","modprobe","insmod","rmmod","iptables","ip6tables"]}]',
        ARRAY['T1611','T1548'],
        'system',
        'match', 0, 0, ''
    ),
    (
        'rule-container-shell-spawn',
        'Interactive Shell Spawned Inside Container',
        'An interactive shell was started inside a container — possible attacker lateral movement or container compromise.',
        3,
        ARRAY['PROCESS_EXEC'],
        '[{"field":"process.container_id","op":"neq","value":""},{"field":"process.comm","op":"in","value":["bash","sh","dash","zsh","ksh","fish"]}]',
        ARRAY['T1059.004','T1610'],
        'system',
        'match', 0, 0, ''
    )
    ON CONFLICT (id) DO NOTHING;
    `,
	},
	{
		name: "xdr_phase1_rules",
		sql: `
    -- XDR Phase 1: source_types filter on rules + cross-source network detection rules.

    ALTER TABLE rules
        ADD COLUMN IF NOT EXISTS source_types TEXT[] NOT NULL DEFAULT '{}';

    CREATE INDEX IF NOT EXISTS rules_source_types_idx ON rules USING GIN(source_types)
        WHERE array_length(source_types, 1) > 0;

    -- Seed 3 cross-source network detection rules (source_types = '{network}').
    INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
                       rule_type, threshold_count, threshold_window_s, group_by, source_types)
    VALUES
    (
        'rule-net-internal-recon',
        'Network Internal Reconnaissance Sweep',
        'A single source IP made connections to 20+ distinct destination ports within 60 seconds — classic port scan or internal lateral movement recon.',
        3,
        ARRAY['NET_FLOW'],
        '[{"field":"proto","op":"in","value":["tcp","udp"]}]',
        ARRAY['T1046'],
        'system',
        'threshold', 20, 60, 'src_ip',
        ARRAY['network']
    ),
    (
        'rule-net-dns-tunnel',
        'Potential DNS Tunnelling — High Query Rate',
        'A host issued 50+ DNS queries within 60 seconds — may indicate DNS tunnelling for C2 or data exfiltration.',
        3,
        ARRAY['NET_DNS'],
        '[{"field":"qtype_name","op":"neq","value":"PTR"}]',
        ARRAY['T1071.004'],
        'system',
        'threshold', 50, 60, 'src_ip',
        ARRAY['network']
    ),
    (
        'rule-net-large-upload',
        'Unusually Large Outbound Transfer',
        'A single network flow carried more than 100 MB outbound — possible data exfiltration.',
        3,
        ARRAY['NET_FLOW'],
        '[{"field":"resp_bytes","op":"gt","value":"104857600"}]',
        ARRAY['T1048'],
        'system',
        'match', 0, 0, '',
        ARRAY['network']
    )
    ON CONFLICT (id) DO NOTHING;
    `,
	},
	{
		name: "xdr_phase2_rules",
		sql: `
    -- XDR Phase 2: cross-source identity detection rules.
    -- Requires source_types column added in xdr_phase1_rules.

    ALTER TABLE rules
        ADD COLUMN IF NOT EXISTS sequence_window_s INTEGER NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS sequence_by        TEXT    NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS sequence_steps     JSONB;

    INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author,
                       rule_type, threshold_count, threshold_window_s, group_by, source_types,
                       sequence_window_s, sequence_by, sequence_steps)
    VALUES
    (
        'rule-xdr-burst-login-failure',
        'Identity Burst Login Failure',
        '10 or more failed authentication events for the same user within 60 seconds across any identity source — possible credential stuffing or brute force.',
        3,
        ARRAY['AUTH_FAILED','LOGIN_FAILED','IDENTITY_AUTH_LOGIN_FAILED'],
        '[]',
        ARRAY['T1110','T1110.001'],
        'system',
        'threshold', 10, 60, 'user_uid',
        ARRAY['identity'],
        0, '', NULL
    ),
    (
        'rule-xdr-cloud-priv-escalation',
        'Cloud Privilege Escalation',
        'A user attached an IAM policy, created an access key, or assumed a privileged role — possible cloud account takeover or insider threat.',
        4,
        ARRAY['CLOUD_API_CALL'],
        '[{"field":"event_name","op":"in","value":["AttachRolePolicy","AttachUserPolicy","CreateAccessKey","AssumeRole","PutUserPolicy","AddUserToGroup"]}]',
        ARRAY['T1078.004','T1098'],
        'system',
        'match', 0, 0, '',
        ARRAY['cloud'],
        0, '', NULL
    ),
    (
        'rule-xdr-impossible-travel',
        'Impossible Travel Login',
        'Login from two geographically distant IPs within 1 hour for the same user — physical travel at this speed is impossible.',
        4,
        ARRAY['AUTH_SUCCESS','LOGIN_SUCCESS','IDENTITY_AUTH_LOGIN_SUCCESS'],
        '[]',
        ARRAY['T1078'],
        'system',
        'threshold', 2, 3600, 'user_uid',
        ARRAY['identity'],
        0, '', NULL
    ),
    (
        'rule-xdr-lateral-movement-chain',
        'Lateral Movement: Endpoint + Identity Sequence',
        'Same user performed a privileged endpoint action followed by an identity-source login from a different IP within 5 minutes — possible credential theft and lateral movement.',
        4,
        ARRAY['PROCESS_EXEC','LOGIN_SUCCESS','AUTH_SUCCESS'],
        '[]',
        ARRAY['T1021','T1550'],
        'system',
        'sequence_cross', 0, 0, '',
        ARRAY['endpoint','identity'],
        300, 'user_uid',
        '[{"event_type":"PROCESS_EXEC","source_types":["endpoint"],"conditions":[{"field":"process.comm","op":"in","value":["sudo","su","runas","psexec"]}]},{"event_type":"LOGIN_SUCCESS","source_types":["identity"],"conditions":[]}]'
    )
    ON CONFLICT (id) DO NOTHING;
    `,
	},
	{
		name: "xdr_phase3_response_actions",
		sql: `
    -- XDR Phase 3: response_actions audit trail.
    CREATE TABLE IF NOT EXISTS response_actions (
        id              TEXT PRIMARY KEY,
        action_type     TEXT        NOT NULL,
        target_type     TEXT        NOT NULL,
        target_id       TEXT        NOT NULL,
        status          TEXT        NOT NULL DEFAULT 'pending',
        triggered_by    TEXT        NOT NULL DEFAULT 'system',
        playbook_run_id TEXT        NOT NULL DEFAULT '',
        params          JSONB       NOT NULL DEFAULT '{}',
        result          JSONB       NOT NULL DEFAULT '{}',
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        reversed_at     TIMESTAMPTZ,
        reversed_by     TEXT        NOT NULL DEFAULT '',
        notes           TEXT        NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ra_target_idx    ON response_actions(target_type, target_id);
    CREATE INDEX IF NOT EXISTS ra_status_idx    ON response_actions(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS ra_triggered_idx ON response_actions(triggered_by);
    `,
	},
	{
		name: "xdr_phase3_seed_playbooks",
		sql: `
    -- XDR Phase 3: seed 5 common SOC workflow playbooks.
    INSERT INTO playbooks (id, name, description, enabled, trigger_type, trigger_filter, actions)
    VALUES
    (
        'pb-critical-alert-notify',
        'Critical Alert — Slack + PagerDuty',
        'Notify SOC via Slack and page on-call via PagerDuty when a CRITICAL severity alert fires.',
        TRUE,
        'alert',
        '{"min_severity": 4}',
        '[{"type":"slack","config":{"webhook_env":"SLACK_SOC_WEBHOOK","message":"*CRITICAL ALERT* on {{.Hostname}}: {{.Title}}"}},{"type":"pagerduty","config":{"integration_key_env":"PD_INTEGRATION_KEY","severity":"critical"}}]'
    ),
    (
        'pb-high-alert-email',
        'High Alert — Email SOC Team',
        'Send an email to the SOC distribution list when a HIGH severity alert fires.',
        TRUE,
        'alert',
        '{"min_severity": 3}',
        '[{"type":"email","config":{"to_env":"SOC_EMAIL","subject":"[HIGH] Alert on {{.Hostname}}: {{.Title}}"}}]'
    ),
    (
        'pb-isolate-on-critical',
        'Auto-Isolate Endpoint on Critical Malware Alert',
        'Automatically isolate the endpoint when a critical detection fires for known malware rules.',
        FALSE,
        'alert',
        '{"min_severity": 4, "rule_ids": ["rule-memory-inject", "rule-kmod-load"]}',
        '[{"type":"isolate_host","config":{}},{"type":"update_alert","config":{"status":"INVESTIGATING","notes":"Auto-isolated by playbook"}},{"type":"slack","config":{"webhook_env":"SLACK_SOC_WEBHOOK","message":"Host *{{.Hostname}}* isolated — critical alert: {{.Title}}"}}]'
    ),
    (
        'pb-block-ip-on-ioc',
        'Block IP on IOC Match',
        'Block the source IP on the endpoint when an IOC network indicator fires.',
        FALSE,
        'alert',
        '{"rule_ids": ["ioc-ip-match"]}',
        '[{"type":"block_ip","config":{}},{"type":"update_alert","config":{"status":"INVESTIGATING","notes":"IP blocked by playbook"}}]'
    ),
    (
        'pb-disable-user-impossible-travel',
        'Disable Identity on Impossible Travel',
        'Disable the Okta user account when an impossible travel alert fires and risk score is high.',
        FALSE,
        'alert',
        '{"rule_ids": ["rule-xdr-impossible-travel"], "min_severity": 3}',
        '[{"type":"disable_identity","config":{"provider":"okta","reason":"Auto-disabled: impossible travel detected"}},{"type":"slack","config":{"webhook_env":"SLACK_SOC_WEBHOOK","message":"User *{{.UserUID}}* disabled — impossible travel alert"}}]'
    )
    ON CONFLICT (id) DO NOTHING;
    `,
	},
	{
		name: "xdr_phase4_scale",
		sql: `
    -- XDR Phase 4: multi-tenancy, scale, behavioral analytics.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

    -- Per-tenant rate-limit overrides.
    CREATE TABLE IF NOT EXISTS tenant_rate_limits (
        tenant_id          TEXT    PRIMARY KEY,
        requests_per_second FLOAT  NOT NULL DEFAULT 20,
        burst              INT     NOT NULL DEFAULT 40,
        updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Add retention_flows_days to the settings key-value store if not present.
    INSERT INTO settings (key, value) VALUES ('retention_flows_days', '7')
    ON CONFLICT (key) DO NOTHING;

    -- Behavioural analytics baseline table (EWMA state per user).
    CREATE TABLE IF NOT EXISTS behavioral_baselines (
        user_uid   TEXT        PRIMARY KEY,
        tenant_id  TEXT        NOT NULL DEFAULT 'default',
        ewma       FLOAT       NOT NULL DEFAULT 0,
        ewma_sq    FLOAT       NOT NULL DEFAULT 0,
        n          INT         NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS bb_tenant_idx ON behavioral_baselines(tenant_id);

    -- STIX import audit trail.
    CREATE TABLE IF NOT EXISTS stix_imports (
        id          TEXT        PRIMARY KEY,
        bundle_id   TEXT        NOT NULL DEFAULT '',
        source      TEXT        NOT NULL DEFAULT 'manual',
        ioc_count   INT         NOT NULL DEFAULT 0,
        errors      TEXT        NOT NULL DEFAULT '',
        imported_by TEXT        NOT NULL DEFAULT 'system',
        imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Sigma import audit trail.
    CREATE TABLE IF NOT EXISTS sigma_imports (
        id          TEXT        PRIMARY KEY,
        rule_count  INT         NOT NULL DEFAULT 0,
        errors      TEXT        NOT NULL DEFAULT '',
        imported_by TEXT        NOT NULL DEFAULT 'system',
        imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
	},
	{
		name: "xdr_phase5_case_tenancy",
		sql: `
    -- XDR Phase 5: add tenant isolation to the cases table.
    ALTER TABLE cases ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
    CREATE INDEX IF NOT EXISTS cases_tenant_idx ON cases(tenant_id);
    `,
	},
	{
		name: "xdr_phase6_incident_tenancy",
		sql: `
    -- XDR Phase 6: add tenant isolation to the incidents table.
    ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
    CREATE INDEX IF NOT EXISTS incidents_tenant_idx ON incidents(tenant_id);
    `,
	},
	{
		name: "xdr_phase7_alerts_tenant_idx",
		sql: `
    -- XDR Phase 7: index alerts by tenant_id for efficient multi-tenant queries.
    ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
    CREATE INDEX IF NOT EXISTS alerts_tenant_id_idx     ON alerts(tenant_id);
    CREATE INDEX IF NOT EXISTS alerts_tenant_status_idx ON alerts(tenant_id, status);
    CREATE INDEX IF NOT EXISTS alerts_tenant_created_idx ON alerts(tenant_id, first_seen DESC);
    `,
	},
	{
		name: "yara_rules_table",
		sql: `
    -- YARA rule management: agents pull enabled rules and scan files/memory locally.
    CREATE TABLE IF NOT EXISTS yara_rules (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        rule_text   TEXT NOT NULL,
        enabled     BOOLEAN NOT NULL DEFAULT TRUE,
        severity    SMALLINT NOT NULL DEFAULT 2,
        mitre_ids   TEXT[] NOT NULL DEFAULT '{}',
        tags        TEXT[] NOT NULL DEFAULT '{}',
        author      TEXT NOT NULL DEFAULT 'system',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS yara_rules_enabled_idx ON yara_rules(enabled);
    `,
	},
	{
		name: "email_endpoint_detection_rules",
		sql: `
    -- Email endpoint detection: catch malicious activity triggered by email clients
    -- (Outlook, Thunderbird, Evolution) without requiring email gateway access.
    INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author, rule_type)
    VALUES
    (
        'rule-email-client-suspicious-child',
        'Email Client Spawning Suspicious Process',
        'An email client (Outlook, Thunderbird, Evolution, Mutt) spawned a shell, script interpreter, or LOLBin — classic spear-phishing attachment execution.',
        4,
        ARRAY['PROCESS_EXEC'],
        '[
            {"field":"process.parent_comm","op":"in","value":["outlook.exe","OUTLOOK.EXE","thunderbird","evolution","mutt","claws-mail","geary","kmail","sylpheed","balsa"]},
            {"field":"process.comm","op":"in","value":["bash","sh","dash","zsh","ksh","python","python3","python2","perl","ruby","node","nodejs","powershell","pwsh","cmd.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe","curl","wget","nc","ncat","netcat"]}
        ]',
        ARRAY['T1566.001','T1059','T1204.002'],
        'system',
        'match'
    ),
    (
        'rule-email-attachment-temp-exec',
        'Process Executed from Email Attachment Temp Path',
        'A process was spawned from a path commonly used for email attachment staging: Outlook temp, Downloads, or browser download directories.',
        3,
        ARRAY['PROCESS_EXEC'],
        '[
            {"field":"process.exe_path","op":"regex","value":"(?i)(/tmp/|/var/tmp/|\\.thunderbird/|Content\\.Outlook|AppData.Local.Temp|AppData.Roaming.Microsoft.Windows.Recent|Downloads/).*\\.(sh|py|pl|rb|js|vbs|ps1|bat|cmd|exe|elf|bin)"}
        ]',
        ARRAY['T1566.001','T1204.002'],
        'system',
        'match'
    ),
    (
        'rule-email-browser-phishing-download',
        'Suspicious Executable Downloaded via Browser from Email Provider',
        'A file with an executable extension was downloaded from a known webmail or file-sharing domain — possible phishing delivery.',
        3,
        ARRAY['FILE_CREATE'],
        '[
            {"field":"path","op":"regex","value":"(?i)(Downloads|/tmp|/var/tmp)/.*\\.(sh|py|pl|rb|elf|bin|deb|rpm|appimage|exe|dll|ps1|vbs|js|hta|jar|msi)$"}
        ]',
        ARRAY['T1566.002','T1105'],
        'system',
        'match'
    ),
    (
        'rule-email-client-network-c2',
        'Email Client Making Unexpected Outbound Connection',
        'An email client process connected to an unusual port — not SMTP (25/465/587) or IMAP/POP3 (143/993/110/995). Possible C2 initiated from a malicious attachment.',
        3,
        ARRAY['NET_CONNECT'],
        '[
            {"field":"process.comm","op":"in","value":["outlook.exe","thunderbird","evolution","mutt","claws-mail"]},
            {"field":"direction","op":"eq","value":"OUTBOUND"},
            {"field":"dst_port","op":"not_in","value":[25,465,587,143,993,110,995,80,443,53]}
        ]',
        ARRAY['T1071','T1566'],
        'system',
        'match'
    ),
    (
        'rule-office-macro-exec',
        'Office Application Spawning Script Interpreter',
        'LibreOffice, OnlyOffice, or Microsoft Office spawned a script interpreter — macro execution from a malicious document.',
        4,
        ARRAY['PROCESS_EXEC'],
        '[
            {"field":"process.parent_comm","op":"in","value":["soffice.bin","soffice","libreoffice","oosplash","python3","onlyoffice","WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","MSPUB.EXE","MSACCESS.EXE"]},
            {"field":"process.comm","op":"in","value":["bash","sh","dash","zsh","python","python3","perl","ruby","powershell","pwsh","cmd.exe","wscript.exe","cscript.exe","mshta.exe","curl","wget","nc","ncat"]}
        ]',
        ARRAY['T1566.001','T1059','T1137'],
        'system',
        'match'
    )
    ON CONFLICT (id) DO NOTHING;
    `,
	},
	{
		name: "xdr_phase8_alert_src_ip",
		sql: `
    -- Add src_ip to alerts so XDR network/cloud alerts carry the correlated IP
    -- into the incident correlator, enabling FindOpenIncidentXdr to match by IP.
    ALTER TABLE alerts ADD COLUMN IF NOT EXISTS src_ip inet;
    CREATE INDEX IF NOT EXISTS alerts_src_ip_idx ON alerts(src_ip) WHERE src_ip IS NOT NULL;
    `,
	},
}

// Open opens a PostgreSQL connection and verifies connectivity.
func Open(dsn string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	db.SetMaxOpenConns(75)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(15 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}

// OpenReplica opens a read-only connection pool to a PostgreSQL read replica.
// Pool is tuned conservatively since it handles SELECT traffic only.
func OpenReplica(dsn string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("connect read replica: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(10 * time.Minute)
	db.SetConnMaxIdleTime(3 * time.Minute)
	return db, nil
}

// RunMigrations applies all pending schema migrations.
func RunMigrations(ctx context.Context, db *sqlx.DB, log zerolog.Logger) error {
	// Ensure migration tracking table exists.
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range migrations {
		var exists bool
		err := db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, m.name,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %q: %w", m.name, err)
		}
		if exists {
			continue
		}

		log.Info().Str("migration", m.name).Msg("applying migration")
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("apply migration %q: %w", m.name, err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO schema_migrations(name) VALUES($1)`, m.name,
		); err != nil {
			return fmt.Errorf("record migration %q: %w", m.name, err)
		}
	}
	return nil
}
