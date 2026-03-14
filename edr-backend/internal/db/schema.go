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
