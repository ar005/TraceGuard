// internal/audit/audit.go
//
// Audit log for the admin portal.
// Records create/delete/login/revoke actions with actor, target, and IP.

package audit

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
)

// Entry is one row from the audit_log table.
type Entry struct {
	ID         int64     `db:"id"          json:"id"`
	Timestamp  time.Time `db:"timestamp"   json:"timestamp"`
	ActorID    string    `db:"actor_id"    json:"actor_id"`
	ActorName  string    `db:"actor_name"  json:"actor_name"`
	Action     string    `db:"action"      json:"action"`
	TargetType string    `db:"target_type" json:"target_type"`
	TargetID   string    `db:"target_id"   json:"target_id"`
	TargetName string    `db:"target_name" json:"target_name"`
	IP         string    `db:"ip"          json:"ip"`
	Details    string    `db:"details"     json:"details"`
}

// Logger writes audit entries.
type Logger struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) *Logger {
	return &Logger{db: db}
}

// Log writes one audit entry. Errors are silently dropped (audit must not break the main flow).
func (l *Logger) Log(ctx context.Context, actorID, actorName, action, targetType, targetID, targetName, ip, details string) {
	_, _ = l.db.ExecContext(ctx, `
		INSERT INTO audit_log (timestamp, actor_id, actor_name, action, target_type, target_id, target_name, ip, details)
		VALUES (NOW(),$1,$2,$3,$4,$5,$6,$7,$8)
	`, actorID, actorName, action, targetType, targetID, targetName, ip, details)
}

// List returns recent audit log entries, newest first.
func (l *Logger) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit == 0 {
		limit = 100
	}
	var entries []Entry
	err := l.db.SelectContext(ctx, &entries,
		`SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT $1`, limit)
	return entries, err
}

// ListByTarget returns audit entries for a specific target, newest first.
func (l *Logger) ListByTarget(ctx context.Context, targetType, targetID string, limit int) ([]Entry, error) {
	if limit == 0 {
		limit = 100
	}
	var entries []Entry
	err := l.db.SelectContext(ctx, &entries,
		`SELECT * FROM audit_log WHERE target_type=$1 AND target_id=$2 ORDER BY timestamp DESC LIMIT $3`,
		targetType, targetID, limit)
	return entries, err
}
