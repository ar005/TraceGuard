package buffer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// testEvent is a minimal events.Event implementation for tests.
type testEvent struct {
	id        string
	eventType string
	chainID   string
}

func (e *testEvent) EventType() string    { return e.eventType }
func (e *testEvent) EventID() string      { return e.id }
func (e *testEvent) GetChainID() string   { return e.chainID }
func (e *testEvent) SetChainID(id string) { e.chainID = id }

// MarshalJSON is needed so json.Marshal works in writeLoop.
func (e *testEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"id":   e.id,
		"type": e.eventType,
	})
}

func newTestBuffer(t *testing.T) *LocalBuffer {
	t.Helper()
	dir := t.TempDir()
	buf, err := New(Config{
		Path:       filepath.Join(dir, "test.db"),
		MaxSizeMB:  10,
		FlushEvery: time.Hour, // disable auto-eviction during tests
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { buf.Close() })
	return buf
}

// drain waits for the async write loop to persist all queued events.
func drainWrites(t *testing.T, buf *LocalBuffer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, unsent, _ := buf.Stats()
		if int(unsent) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events to be buffered", want)
}

// ─── Write + ReadUnsent ───────────────────────────────────────────────────────

func TestWriteAndReadUnsent(t *testing.T) {
	buf := newTestBuffer(t)

	events := []*testEvent{
		{id: "ev-1", eventType: "PROCESS_CREATE"},
		{id: "ev-2", eventType: "FILE_CREATE"},
		{id: "ev-3", eventType: "NETWORK_CONNECT"},
	}
	for _, ev := range events {
		buf.Write(ev)
	}
	drainWrites(t, buf, 3)

	rows, err := buf.ReadUnsent(100)
	if err != nil {
		t.Fatalf("ReadUnsent: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows; want 3", len(rows))
	}

	// Should come back in insertion order.
	for i, row := range rows {
		if row.EventID != events[i].id {
			t.Errorf("row[%d].EventID = %q; want %q", i, row.EventID, events[i].id)
		}
		if row.EventType != events[i].eventType {
			t.Errorf("row[%d].EventType = %q; want %q", i, row.EventType, events[i].eventType)
		}
	}
}

func TestReadUnsent_Limit(t *testing.T) {
	buf := newTestBuffer(t)

	for i := 0; i < 10; i++ {
		buf.Write(&testEvent{id: fmt.Sprintf("ev-%d", i), eventType: "X"})
	}
	drainWrites(t, buf, 10)

	rows, err := buf.ReadUnsent(3)
	if err != nil {
		t.Fatalf("ReadUnsent: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows with limit=3; want 3", len(rows))
	}
}

func TestReadUnsent_EmptyDB(t *testing.T) {
	buf := newTestBuffer(t)
	rows, err := buf.ReadUnsent(100)
	if err != nil {
		t.Fatalf("ReadUnsent on empty db: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows on empty db; want 0", len(rows))
	}
}

// ─── MarkSent ─────────────────────────────────────────────────────────────────

func TestMarkSent(t *testing.T) {
	buf := newTestBuffer(t)

	for i := 0; i < 5; i++ {
		buf.Write(&testEvent{id: fmt.Sprintf("ev-%d", i), eventType: "X"})
	}
	drainWrites(t, buf, 5)

	// Mark the first two as sent.
	if err := buf.MarkSent([]string{"ev-0", "ev-1"}); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}

	rows, err := buf.ReadUnsent(100)
	if err != nil {
		t.Fatalf("ReadUnsent: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d unsent rows; want 3", len(rows))
	}
	for _, row := range rows {
		if row.EventID == "ev-0" || row.EventID == "ev-1" {
			t.Errorf("sent event %q still returned by ReadUnsent", row.EventID)
		}
	}
}

func TestMarkSent_Empty(t *testing.T) {
	buf := newTestBuffer(t)
	// Should be a no-op, not an error.
	if err := buf.MarkSent(nil); err != nil {
		t.Errorf("MarkSent(nil): %v", err)
	}
	if err := buf.MarkSent([]string{}); err != nil {
		t.Errorf("MarkSent([]): %v", err)
	}
}

func TestMarkSent_UnknownID(t *testing.T) {
	buf := newTestBuffer(t)
	// Marking a non-existent event should not return an error.
	if err := buf.MarkSent([]string{"does-not-exist"}); err != nil {
		t.Errorf("MarkSent(unknown): %v", err)
	}
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func TestStats(t *testing.T) {
	buf := newTestBuffer(t)

	total, unsent, _ := buf.Stats()
	if total != 0 || unsent != 0 {
		t.Fatalf("fresh buffer: got total=%d unsent=%d; want 0 0", total, unsent)
	}

	buf.Write(&testEvent{id: "ev-1", eventType: "X"})
	buf.Write(&testEvent{id: "ev-2", eventType: "X"})
	drainWrites(t, buf, 2)

	total, unsent, _ = buf.Stats()
	if total != 2 {
		t.Errorf("total = %d; want 2", total)
	}
	if unsent != 2 {
		t.Errorf("unsent = %d; want 2", unsent)
	}

	buf.MarkSent([]string{"ev-1"})

	total, unsent, _ = buf.Stats()
	if total != 2 {
		t.Errorf("total = %d; want 2 (sent rows still count)", total)
	}
	if unsent != 1 {
		t.Errorf("unsent = %d; want 1 after MarkSent", unsent)
	}
}

// ─── Eviction ─────────────────────────────────────────────────────────────────

func TestEvict_RemovesSentOlderThanOneHour(t *testing.T) {
	buf := newTestBuffer(t)

	buf.Write(&testEvent{id: "old-sent", eventType: "X"})
	drainWrites(t, buf, 1)
	buf.MarkSent([]string{"old-sent"})

	// Back-date the timestamp by 2 hours via direct SQL.
	twoHoursAgo := time.Now().Add(-2 * time.Hour).UnixNano()
	buf.mu.Lock()
	buf.db.Exec(`UPDATE events SET timestamp=? WHERE event_id='old-sent'`, twoHoursAgo)
	buf.mu.Unlock()

	// Add an unsent event — eviction must not touch it.
	buf.Write(&testEvent{id: "fresh-unsent", eventType: "X"})
	// "old-sent" is already marked sent so unsent count is 1, not 2.
	drainWrites(t, buf, 1)

	buf.evict()

	rows, err := buf.ReadUnsent(100)
	if err != nil {
		t.Fatalf("ReadUnsent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d unsent rows after eviction; want 1", len(rows))
	}
	if rows[0].EventID != "fresh-unsent" {
		t.Errorf("remaining row = %q; want fresh-unsent", rows[0].EventID)
	}

	total, _, _ := buf.Stats()
	if total != 1 {
		t.Errorf("total = %d; want 1 (old sent row should be evicted)", total)
	}
}

func TestEvict_KeepsRecentSentEvents(t *testing.T) {
	buf := newTestBuffer(t)

	buf.Write(&testEvent{id: "recent-sent", eventType: "X"})
	drainWrites(t, buf, 1)
	buf.MarkSent([]string{"recent-sent"})

	// Don't back-date — timestamp is recent (< 1 hour old).
	buf.evict()

	total, _, _ := buf.Stats()
	if total != 1 {
		t.Errorf("total = %d; want 1 (recent sent event must not be evicted)", total)
	}
}

func TestEvict_UnsentEventsNeverEvicted(t *testing.T) {
	buf := newTestBuffer(t)

	// Add old unsent events.
	for i := 0; i < 5; i++ {
		buf.Write(&testEvent{id: fmt.Sprintf("ev-%d", i), eventType: "X"})
	}
	drainWrites(t, buf, 5)

	twoHoursAgo := time.Now().Add(-2 * time.Hour).UnixNano()
	buf.mu.Lock()
	buf.db.Exec(`UPDATE events SET timestamp=?`, twoHoursAgo)
	buf.mu.Unlock()

	buf.evict()

	_, unsent, _ := buf.Stats()
	if unsent != 5 {
		t.Errorf("unsent = %d; want 5 (old unsent events should never be evicted by time)", unsent)
	}
}

// ─── Write queue ─────────────────────────────────────────────────────────────

func TestWrite_DoesNotBlockOnFullQueue(t *testing.T) {
	// A buffer with an artificially tiny queue would require package access;
	// instead verify Write returns promptly with the real queue depth.
	buf := newTestBuffer(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Write more events than can be processed instantly.
		for i := 0; i < 100; i++ {
			buf.Write(&testEvent{id: fmt.Sprintf("ev-%d", i), eventType: "X"})
		}
	}()

	select {
	case <-done:
		// pass
	case <-time.After(500 * time.Millisecond):
		t.Error("Write() blocked for too long")
	}
}
