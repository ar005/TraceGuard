// internal/migrate/migrate.go
//
// DB export / import for EDR backend migration.
//
// Export: streams a single JSON document containing all agents, events,
//         alerts, and rules in insertion order. Events are streamed in
//         batches to avoid loading the whole table into memory.
//
// Import: accepts the same JSON document, replays every row with
//         ON CONFLICT DO NOTHING so it is safe to re-run and safe to
//         import into an already-populated DB (existing rows are kept).
//
// Access is API-key gated (same key as the rest of the API) and is
//         intentionally NOT exposed in the frontend.
//
// Wire format  (application/json):
//
//   {
//     "version":    1,
//     "exported_at": "<RFC3339>",
//     "agents":  [ … ],
//     "rules":   [ … ],
//     "alerts":  [ … ],
//     "events":  [ … ]      ← largest table, streamed in pages
//   }

package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

const (
	exportVersion = 1
	eventPageSize = 2000 // rows per SELECT during export
)

// ─── Export ───────────────────────────────────────────────────────────────────

// Export writes a complete JSON dump of the database to w.
// It streams events in pages so memory usage stays bounded regardless of
// how many events are stored.
func Export(ctx context.Context, db *sqlx.DB, w io.Writer, log zerolog.Logger) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	// Write opening object fields one by one so we can stream events.
	if _, err := fmt.Fprintf(w, `{"version":%d,"exported_at":%q,`,
		exportVersion, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}

	// ── Agents ──────────────────────────────────────────────────────────────
	agents, err := queryAgents(ctx, db)
	if err != nil {
		return fmt.Errorf("export agents: %w", err)
	}
	if _, err := fmt.Fprintf(w, `"agents":`); err != nil {
		return err
	}
	if err := enc.Encode(agents); err != nil {
		return err
	}
	log.Info().Int("count", len(agents)).Msg("exported agents")

	// ── Rules ────────────────────────────────────────────────────────────────
	rules, err := queryRules(ctx, db)
	if err != nil {
		return fmt.Errorf("export rules: %w", err)
	}
	if _, err := fmt.Fprintf(w, `,"rules":`); err != nil {
		return err
	}
	if err := enc.Encode(rules); err != nil {
		return err
	}
	log.Info().Int("count", len(rules)).Msg("exported rules")

	// ── Alerts ───────────────────────────────────────────────────────────────
	alerts, err := queryAlerts(ctx, db)
	if err != nil {
		return fmt.Errorf("export alerts: %w", err)
	}
	if _, err := fmt.Fprintf(w, `,"alerts":`); err != nil {
		return err
	}
	if err := enc.Encode(alerts); err != nil {
		return err
	}
	log.Info().Int("count", len(alerts)).Msg("exported alerts")

	// ── Events (paged) ───────────────────────────────────────────────────────
	if _, err := fmt.Fprintf(w, `,"events":[`); err != nil {
		return err
	}

	total := 0
	first := true
	offset := 0
	for {
		page, err := queryEventsPage(ctx, db, offset, eventPageSize)
		if err != nil {
			return fmt.Errorf("export events page offset=%d: %w", offset, err)
		}
		for _, ev := range page {
			if !first {
				if _, err := fmt.Fprintf(w, ","); err != nil {
					return err
				}
			}
			first = false
			if err := enc.Encode(ev); err != nil {
				return err
			}
		}
		total += len(page)
		if len(page) < eventPageSize {
			break // last page
		}
		offset += eventPageSize

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	if _, err := fmt.Fprintf(w, `]}`); err != nil {
		return err
	}

	log.Info().Int("total_events", total).Msg("export complete")
	return nil
}

// ─── Import ───────────────────────────────────────────────────────────────────

// ImportResult summarises what was inserted during an import.
type ImportResult struct {
	Agents int `json:"agents_imported"`
	Rules  int `json:"rules_imported"`
	Alerts int `json:"alerts_imported"`
	Events int `json:"events_imported"`
}

// dump is the top-level wire format used for both export and import.
type dump struct {
	Version    int               `json:"version"`
	ExportedAt string            `json:"exported_at"`
	Agents     []models.Agent    `json:"agents"`
	Rules      []models.Rule     `json:"rules"`
	Alerts     []models.Alert    `json:"alerts"`
	Events     []models.Event    `json:"events"`
}

// Import reads a JSON dump from r and inserts every row into the database.
// ON CONFLICT DO NOTHING ensures existing rows are never overwritten.
// Agents must be imported before events/alerts due to the FK constraint.
func Import(ctx context.Context, db *sqlx.DB, r io.Reader, log zerolog.Logger) (*ImportResult, error) {
	var d dump
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode dump: %w", err)
	}
	if d.Version != exportVersion {
		return nil, fmt.Errorf("unsupported dump version %d (expected %d)", d.Version, exportVersion)
	}

	res := &ImportResult{}
	var err error

	// Order: agents → rules → alerts → events (FK dependency).
	if res.Agents, err = importAgents(ctx, db, d.Agents, log); err != nil {
		return nil, fmt.Errorf("import agents: %w", err)
	}
	if res.Rules, err = importRules(ctx, db, d.Rules, log); err != nil {
		return nil, fmt.Errorf("import rules: %w", err)
	}
	if res.Alerts, err = importAlerts(ctx, db, d.Alerts, log); err != nil {
		return nil, fmt.Errorf("import alerts: %w", err)
	}
	if res.Events, err = importEvents(ctx, db, d.Events, log); err != nil {
		return nil, fmt.Errorf("import events: %w", err)
	}

	log.Info().
		Int("agents", res.Agents).
		Int("rules", res.Rules).
		Int("alerts", res.Alerts).
		Int("events", res.Events).
		Msg("import complete")
	return res, nil
}

// ─── Query helpers ────────────────────────────────────────────────────────────

func queryAgents(ctx context.Context, db *sqlx.DB) ([]models.Agent, error) {
	var rows []models.Agent
	err := db.SelectContext(ctx, &rows, `SELECT * FROM agents ORDER BY first_seen`)
	return rows, err
}

func queryRules(ctx context.Context, db *sqlx.DB) ([]models.Rule, error) {
	var rows []models.Rule
	err := db.SelectContext(ctx, &rows, `SELECT * FROM rules ORDER BY created_at`)
	return rows, err
}

func queryAlerts(ctx context.Context, db *sqlx.DB) ([]models.Alert, error) {
	var rows []models.Alert
	err := db.SelectContext(ctx, &rows, `SELECT * FROM alerts ORDER BY first_seen`)
	return rows, err
}

func queryEventsPage(ctx context.Context, db *sqlx.DB, offset, limit int) ([]models.Event, error) {
	var rows []models.Event
	err := db.SelectContext(ctx, &rows,
		`SELECT * FROM events ORDER BY timestamp ASC, id ASC LIMIT $1 OFFSET $2`,
		limit, offset)
	return rows, err
}

// ─── Insert helpers ───────────────────────────────────────────────────────────

func importAgents(ctx context.Context, db *sqlx.DB, rows []models.Agent, log zerolog.Logger) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO agents (id, hostname, os, os_version, ip, agent_ver, first_seen, last_seen, is_online, config_ver)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO NOTHING
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, a := range rows {
		res, err := stmt.ExecContext(ctx,
			a.ID, a.Hostname, a.OS, a.OSVersion, a.IP, a.AgentVer,
			a.FirstSeen, a.LastSeen, a.IsOnline, a.ConfigVer)
		if err != nil {
			return n, err
		}
		if ra, _ := res.RowsAffected(); ra > 0 {
			n++
		}
	}
	log.Info().Int("inserted", n).Int("total", len(rows)).Msg("imported agents")
	return n, tx.Commit()
}

func importRules(ctx context.Context, db *sqlx.DB, rows []models.Rule, log zerolog.Logger) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO rules (id, name, description, enabled, severity, event_types, conditions, mitre_ids, author, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (id) DO NOTHING
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, r := range rows {
		conds, err := json.Marshal(r.Conditions)
		if err != nil {
			return n, err
		}
		res, err := stmt.ExecContext(ctx,
			r.ID, r.Name, r.Description, r.Enabled, r.Severity,
			pq.Array(r.EventTypes), conds, pq.Array(r.MitreIDs),
			r.Author, r.CreatedAt, r.UpdatedAt)
		if err != nil {
			return n, err
		}
		if ra, _ := res.RowsAffected(); ra > 0 {
			n++
		}
	}
	log.Info().Int("inserted", n).Int("total", len(rows)).Msg("imported rules")
	return n, tx.Commit()
}

func importAlerts(ctx context.Context, db *sqlx.DB, rows []models.Alert, log zerolog.Logger) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO alerts
		  (id, title, description, severity, status, rule_id, rule_name,
		   mitre_ids, event_ids, agent_id, hostname, first_seen, last_seen, assignee, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (id) DO NOTHING
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, a := range rows {
		res, err := stmt.ExecContext(ctx,
			a.ID, a.Title, a.Description, a.Severity, a.Status,
			a.RuleID, a.RuleName, pq.Array(a.MitreIDs), pq.Array(a.EventIDs),
			a.AgentID, a.Hostname, a.FirstSeen, a.LastSeen, a.Assignee, a.Notes)
		if err != nil {
			return n, err
		}
		if ra, _ := res.RowsAffected(); ra > 0 {
			n++
		}
	}
	log.Info().Int("inserted", n).Int("total", len(rows)).Msg("imported alerts")
	return n, tx.Commit()
}

func importEvents(ctx context.Context, db *sqlx.DB, rows []models.Event, log zerolog.Logger) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Batch into pages to keep transactions small.
	const batchSize = 500
	n := 0
	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		batch := rows[start:end]

		tx, err := db.BeginTxx(ctx, nil)
		if err != nil {
			return n, err
		}

		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO events (id, agent_id, hostname, event_type, timestamp, payload, received_at, severity, rule_id, alert_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (id) DO NOTHING
		`)
		if err != nil {
			tx.Rollback()
			return n, err
		}

		for _, e := range batch {
			res, err := stmt.ExecContext(ctx,
				e.ID, e.AgentID, e.Hostname, e.EventType,
				e.Timestamp, e.Payload, e.ReceivedAt,
				e.Severity, e.RuleID, e.AlertID)
			if err != nil {
				stmt.Close()
				tx.Rollback()
				return n, err
			}
			if ra, _ := res.RowsAffected(); ra > 0 {
				n++
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			return n, err
		}

		select {
		case <-ctx.Done():
			return n, ctx.Err()
		default:
		}
	}

	log.Info().Int("inserted", n).Int("total", len(rows)).Msg("imported events")
	return n, nil
}
