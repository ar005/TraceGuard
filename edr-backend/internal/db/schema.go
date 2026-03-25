// internal/db/schema.go
// PostgreSQL schema for the EDR backend.
// Applied at startup via RunMigrations().

package db

import (
	"context"
	"fmt"

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
}

// Open opens a PostgreSQL connection and verifies connectivity.
func Open(dsn string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
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
