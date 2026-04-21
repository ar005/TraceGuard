// internal/buffer/buffer.go
//
// Local SQLite event buffer.
// All events are written here FIRST before being sent to the backend.
// If the backend is unreachable, events accumulate here and are flushed
// once connectivity is restored.
// Implements a simple ring-buffer eviction: when max_size_mb is reached,
// the oldest events are purged.

package buffer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    timestamp   INTEGER NOT NULL,  -- unix nano
    severity    INTEGER NOT NULL,
    payload     BLOB NOT NULL,     -- JSON-encoded event
    sent        INTEGER NOT NULL DEFAULT 0,  -- 0=pending, 1=sent
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_events_sent     ON events(sent);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created  ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_sent_ts  ON events(sent, timestamp);
`

// Config controls the local buffer.
type Config struct {
	Path       string        // SQLite file path
	MaxSizeMB  int           // max DB size before eviction
	FlushEvery time.Duration // how often to mark old events as expired
}

// writeRequest is a single event pending async write to SQLite.
type writeRequest struct {
	id        string
	eventType string
	ts        int64
	severity  int
	payload   []byte
}

// LocalBuffer is a persistent event queue backed by SQLite.
type LocalBuffer struct {
	cfg     Config
	db      *sql.DB
	log     zerolog.Logger
	mu      sync.Mutex
	stopCh  chan struct{}
	writeCh chan writeRequest
}

// New opens (or creates) the SQLite buffer.
func New(cfg Config, log zerolog.Logger) (*LocalBuffer, error) {
	if cfg.Path == "" {
		cfg.Path = "/var/lib/edr/events.db"
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 512
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}

	// Ensure directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0700); err != nil {
		return nil, fmt.Errorf("create buffer dir: %w", err)
	}

	db, err := sql.Open("sqlite3", cfg.Path+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Single writer; multiple readers are fine.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	buf := &LocalBuffer{
		cfg:     cfg,
		db:      db,
		log:     log.With().Str("component", "buffer").Logger(),
		stopCh:  make(chan struct{}),
		writeCh: make(chan writeRequest, 8192),
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-buf.stopCh
		cancel()
	}()
	go buf.flushLoop(ctx)
	go buf.evictionLoop()
	return buf, nil
}

// Write persists an event to the buffer asynchronously via writeCh.
// Non-blocking: drops and logs a warning if the channel is full.
func (b *LocalBuffer) Write(ev events.Event) {
	payload, err := json.Marshal(ev)
	if err != nil {
		b.log.Error().Err(err).Msg("buffer: marshal event")
		return
	}
	req := writeRequest{
		id:        ev.EventID(),
		eventType: string(ev.EventType()),
		ts:        time.Now().UnixNano(),
		severity:  0,
		payload:   payload,
	}
	select {
	case b.writeCh <- req:
	default:
		b.log.Warn().Str("event_id", req.id).Msg("buffer: write channel full, event dropped")
	}
}

// flushLoop accumulates up to 500 events or 500ms and writes them in a single
// batched INSERT transaction for throughput.
func (b *LocalBuffer) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]writeRequest, 0, 500)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := b.db.Begin()
		if err != nil {
			b.log.Error().Err(err).Msg("buffer: begin tx")
			batch = batch[:0]
			return
		}
		stmt, err := tx.Prepare(`INSERT OR IGNORE INTO events(event_id,event_type,timestamp,severity,payload) VALUES(?,?,?,?,?)`)
		if err != nil {
			tx.Rollback()
			b.log.Error().Err(err).Msg("buffer: prepare stmt")
			batch = batch[:0]
			return
		}
		for _, r := range batch {
			stmt.Exec(r.id, r.eventType, r.ts, r.severity, r.payload)
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			b.log.Error().Err(err).Msg("buffer: commit batch")
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case r := <-b.writeCh:
			batch = append(batch, r)
			if len(batch) >= 500 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// MarkSent marks events as sent so they can be evicted.
func (b *LocalBuffer) MarkSent(eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`UPDATE events SET sent=1 WHERE event_id=?`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, id := range eventIDs {
		if _, err := stmt.Exec(id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ReadUnsent returns up to limit unsent events (for replay on reconnect).
func (b *LocalBuffer) ReadUnsent(limit int) ([]BufferedEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rows, err := b.db.Query(
		`SELECT event_id, event_type, timestamp, payload
		 FROM events WHERE sent=0
		 ORDER BY id ASC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []BufferedEvent
	for rows.Next() {
		var ev BufferedEvent
		if err := rows.Scan(&ev.EventID, &ev.EventType, &ev.Timestamp, &ev.Payload); err != nil {
			continue
		}
		result = append(result, ev)
	}
	return result, rows.Err()
}

// Stats returns buffer statistics.
func (b *LocalBuffer) Stats() (total, unsent int64, sizeMB float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&total)
	b.db.QueryRow(`SELECT COUNT(*) FROM events WHERE sent=0`).Scan(&unsent)

	var pageCount, pageSize int64
	b.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount)
	b.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize)
	sizeMB = float64(pageCount*pageSize) / 1024 / 1024
	return
}

// Close shuts down the buffer cleanly.
func (b *LocalBuffer) Close() {
	close(b.stopCh)
	b.db.Close()
}

// evictionLoop periodically:
//   - Deletes events that have been sent (keeping last 1h for reference).
//   - Evicts oldest events if the DB exceeds MaxSizeMB.
func (b *LocalBuffer) evictionLoop() {
	ticker := time.NewTicker(b.cfg.FlushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.evict()
		}
	}
}

func (b *LocalBuffer) evict() {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Delete sent events older than 1 hour.
	cutoff := time.Now().Add(-time.Hour).UnixNano()
	res, err := b.db.Exec(
		`DELETE FROM events WHERE sent=1 AND timestamp < ?`, cutoff)
	if err != nil {
		b.log.Error().Err(err).Msg("evict sent events")
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		b.log.Debug().Int64("deleted", n).Msg("evicted sent events")
		// VACUUM to reclaim space.
		b.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}

	// Check size; if over limit, delete oldest unsent events (ring buffer).
	var pageCount, pageSize int64
	b.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount)
	b.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize)
	currentSizeMB := float64(pageCount*pageSize) / 1024 / 1024

	if currentSizeMB > float64(b.cfg.MaxSizeMB) {
		// Delete oldest 10% of unsent events.
		b.db.Exec(`
			DELETE FROM events WHERE id IN (
				SELECT id FROM events WHERE sent=0
				ORDER BY id ASC
				LIMIT (SELECT COUNT(*)/10 FROM events WHERE sent=0)
			)`)
		b.log.Warn().
			Float64("size_mb", currentSizeMB).
			Int("limit_mb", b.cfg.MaxSizeMB).
			Msg("buffer size exceeded limit — oldest events evicted")
	}
}

// BufferedEvent is a row from the events table.
type BufferedEvent struct {
	EventID   string
	EventType string
	Timestamp int64
	Payload   []byte
}
