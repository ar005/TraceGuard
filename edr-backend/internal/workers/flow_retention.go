// internal/workers/flow_retention.go
//
// Manages xdr_network_flows table partitions:
//   - Creates tomorrow's partition before midnight so inserts never fail.
//   - Drops partitions older than retention_flows_days (default 7).
//
// Run via FlowRetentionWorker.Start(); call Stop() on shutdown.

package workers

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
)

// FlowRetentionWorker manages daily partition creation and expiry for
// the xdr_network_flows table.
type FlowRetentionWorker struct {
	db         *sqlx.DB
	defaultDays int
	log        zerolog.Logger
	stop       chan struct{}
}

func NewFlowRetentionWorker(db *sqlx.DB, defaultRetentionDays int, log zerolog.Logger) *FlowRetentionWorker {
	if defaultRetentionDays <= 0 {
		defaultRetentionDays = 7
	}
	return &FlowRetentionWorker{
		db:          db,
		defaultDays: defaultRetentionDays,
		log:         log.With().Str("worker", "flow_retention").Logger(),
		stop:        make(chan struct{}),
	}
}

func (w *FlowRetentionWorker) Start(ctx context.Context) {
	// Run immediately on startup, then every hour.
	w.runOnce(ctx)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.runOnce(ctx)
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (w *FlowRetentionWorker) Stop() {
	close(w.stop)
}

func (w *FlowRetentionWorker) runOnce(ctx context.Context) {
	days := w.retentionDays(ctx)
	now := time.Now().UTC()

	// Ensure partitions exist for today and tomorrow.
	for _, d := range []time.Time{now, now.Add(24 * time.Hour)} {
		if err := w.ensurePartition(ctx, d); err != nil {
			w.log.Error().Err(err).Str("date", d.Format("2006_01_02")).Msg("create partition failed")
		}
	}

	// Drop partitions older than retention window.
	cutoff := now.AddDate(0, 0, -days)
	if err := w.dropOldPartitions(ctx, cutoff); err != nil {
		w.log.Error().Err(err).Msg("drop old partitions failed")
	}
}

func (w *FlowRetentionWorker) retentionDays(ctx context.Context) int {
	var val string
	err := w.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='retention_flows_days'`).Scan(&val)
	if err != nil {
		return w.defaultDays
	}
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil || n <= 0 {
		return w.defaultDays
	}
	return n
}

func (w *FlowRetentionWorker) ensurePartition(ctx context.Context, day time.Time) error {
	name := partitionName(day)
	start := day.Truncate(24 * time.Hour).Format("2006-01-02")
	end := day.Truncate(24*time.Hour).Add(24 * time.Hour).Format("2006-01-02")

	sql := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s
		PARTITION OF xdr_network_flows
		FOR VALUES FROM ('%s') TO ('%s')`,
		name, start, end)

	_, err := w.db.ExecContext(ctx, sql)
	if err != nil {
		// "already exists" is harmless — PostgreSQL IF NOT EXISTS handles it but
		// some PG versions raise an error on partitioned tables.
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}
	w.log.Debug().Str("partition", name).Msg("partition ensured")
	return nil
}

func (w *FlowRetentionWorker) dropOldPartitions(ctx context.Context, cutoff time.Time) error {
	// List child tables of xdr_network_flows that are older than cutoff.
	rows, err := w.db.QueryContext(ctx, `
		SELECT inhrelid::regclass::text
		FROM   pg_inherits
		JOIN   pg_class parent ON parent.oid = inhparent
		WHERE  parent.relname = 'xdr_network_flows'`)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var partName string
		if err := rows.Scan(&partName); err != nil {
			continue
		}
		// Partition names are like: xdr_network_flows_2025_04_15
		// Strip schema prefix if present.
		bare := partName
		if idx := strings.LastIndex(bare, "."); idx >= 0 {
			bare = bare[idx+1:]
		}
		bare = strings.TrimPrefix(bare, "xdr_network_flows_")
		t, err := time.Parse("2006_01_02", bare)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			if _, err := w.db.ExecContext(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, partName)); err != nil {
				w.log.Error().Err(err).Str("partition", partName).Msg("drop partition failed")
			} else {
				w.log.Info().Str("partition", partName).Msg("dropped expired flow partition")
			}
		}
	}
	return rows.Err()
}

func partitionName(day time.Time) string {
	return "xdr_network_flows_" + day.UTC().Format("2006_01_02")
}
