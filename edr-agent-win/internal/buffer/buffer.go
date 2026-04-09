// internal/buffer/buffer.go
// Local SQLite event buffer — identical to Linux except default path.

package buffer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite — no CGO required for cross-compilation
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    timestamp   INTEGER NOT NULL,
    severity    INTEGER NOT NULL,
    payload     BLOB NOT NULL,
    sent        INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_sent     ON events(sent);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created  ON events(created_at);
`

type Config struct {
	Path       string
	MaxSizeMB  int
	FlushEvery time.Duration
}

type LocalBuffer struct {
	cfg    Config
	db     *sql.DB
	log    zerolog.Logger
	mu     sync.Mutex
	stopCh chan struct{}
}

func New(cfg Config, log zerolog.Logger) (*LocalBuffer, error) {
	if cfg.Path == "" {
		cfg.Path = `C:\ProgramData\TraceGuard\events.db`
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 512
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0700); err != nil {
		return nil, fmt.Errorf("create buffer dir: %w", err)
	}

	db, err := sql.Open("sqlite", cfg.Path+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	buf := &LocalBuffer{
		cfg:    cfg,
		db:     db,
		log:    log.With().Str("component", "buffer").Logger(),
		stopCh: make(chan struct{}),
	}
	go buf.evictionLoop()
	return buf, nil
}

func (b *LocalBuffer) Write(ev events.Event) {
	payload, err := json.Marshal(ev)
	if err != nil {
		b.log.Error().Err(err).Msg("marshal event for buffer")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err = b.db.Exec(
		`INSERT INTO events (event_id, event_type, timestamp, severity, payload) VALUES (?, ?, ?, ?, ?)`,
		ev.EventID(), ev.EventType(), time.Now().UnixNano(), 0, payload,
	)
	if err != nil {
		b.log.Error().Err(err).Msg("write event to buffer")
	}
}

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

func (b *LocalBuffer) ReadUnsent(limit int) ([]BufferedEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rows, err := b.db.Query(
		`SELECT event_id, event_type, timestamp, payload FROM events WHERE sent=0 ORDER BY id ASC LIMIT ?`, limit)
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

func (b *LocalBuffer) Close() {
	close(b.stopCh)
	b.db.Close()
}

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
	cutoff := time.Now().Add(-time.Hour).UnixNano()
	res, err := b.db.Exec(`DELETE FROM events WHERE sent=1 AND timestamp < ?`, cutoff)
	if err != nil {
		b.log.Error().Err(err).Msg("evict sent events")
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		b.log.Debug().Int64("deleted", n).Msg("evicted sent events")
		b.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	var pageCount, pageSize int64
	b.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount)
	b.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize)
	currentSizeMB := float64(pageCount*pageSize) / 1024 / 1024
	if currentSizeMB > float64(b.cfg.MaxSizeMB) {
		b.db.Exec(`DELETE FROM events WHERE id IN (
			SELECT id FROM events WHERE sent=0 ORDER BY id ASC
			LIMIT (SELECT COUNT(*)/10 FROM events WHERE sent=0))`)
		b.log.Warn().Float64("size_mb", currentSizeMB).Int("limit_mb", b.cfg.MaxSizeMB).
			Msg("buffer size exceeded limit — oldest events evicted")
	}
}

type BufferedEvent struct {
	EventID   string
	EventType string
	Timestamp int64
	Payload   []byte
}
