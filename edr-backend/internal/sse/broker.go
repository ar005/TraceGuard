// internal/sse/broker.go
//
// Server-Sent Events broker backed by PostgreSQL LISTEN/NOTIFY.
//
// Architecture (single-node):
//   Ingest calls Broker.Publish(ev) → pg_notify('edr_events', json)
//   Broker's listener goroutine receives the notification and fans it out
//   to all locally connected SSE clients.
//
// Architecture (multi-node):
//   Every backend instance runs its own listener goroutine on the same PG
//   channel. When ingest on node A fires pg_notify, ALL nodes (A, B, C …)
//   receive the notification and fan it out to their own SSE clients.
//   Browser clients connecting to any node therefore receive the full event
//   stream regardless of which node holds the agent's gRPC connection.
//
// Note: live-response sessions are inherently streaming and require sticky
// load-balancer routing per agent connection (standard layer-4 affinity).

package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

const pgChannel = "edr_events"

// EventFetcher looks up a full event by ID. The broker uses it to rehydrate
// payloads that were truncated to fit pg_notify's 8 kB limit on the way in.
type EventFetcher interface {
	GetEvent(ctx context.Context, id, tenantID string) (*models.Event, error)
}

// Broker fans out events to all connected SSE clients via PostgreSQL LISTEN/NOTIFY.
type Broker struct {
	mu      sync.RWMutex
	clients map[string]chan []byte
	log     zerolog.Logger
	db      *sqlx.DB
	dsn     string
	fetcher EventFetcher
}

// SetEventFetcher wires a store lookup for rehydrating truncated notifications.
// Safe to call once after New() and before Start(). If unset, the broker fans
// out the slim id-only marker as-is.
func (b *Broker) SetEventFetcher(f EventFetcher) {
	b.fetcher = f
}

// New creates an SSE Broker. Call Start(ctx) after creation to begin listening.
func New(log zerolog.Logger, db *sqlx.DB, dsn string) *Broker {
	return &Broker{
		clients: make(map[string]chan []byte),
		log:     log.With().Str("component", "sse").Logger(),
		db:      db,
		dsn:     dsn,
	}
}

// newTestBroker creates a Broker with no database dependency, for unit tests only.
// It bypasses the PG listener; Publish fans out directly to in-memory channels.
func newTestBroker(log zerolog.Logger) *Broker {
	return &Broker{
		clients: make(map[string]chan []byte),
		log:     log,
	}
}

// Start begins the PostgreSQL LISTEN loop. It must be called once before
// any SSE clients connect. The goroutine exits when ctx is cancelled.
func (b *Broker) Start(ctx context.Context) {
	go b.listenLoop(ctx)
}

// listenLoop subscribes to the PostgreSQL edr_events channel and fans each
// notification payload to all locally registered SSE clients.
func (b *Broker) listenLoop(ctx context.Context) {
	reportProblem := func(ev pq.ListenerEventType, err error) {
		if err != nil {
			b.log.Warn().Err(err).Msg("SSE PG listener event")
		}
	}

	listener := pq.NewListener(b.dsn, 5*time.Second, 90*time.Second, reportProblem)
	if err := listener.Listen(pgChannel); err != nil {
		b.log.Error().Err(err).Msg("SSE: failed to LISTEN on PG channel — SSE stream disabled")
		return
	}
	defer listener.Close()

	b.log.Info().Str("channel", pgChannel).Msg("SSE broker listening on PostgreSQL channel")

	ping := time.NewTicker(90 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ping.C:
			if err := listener.Ping(); err != nil {
				b.log.Warn().Err(err).Msg("SSE PG listener ping failed")
			}

		case n, ok := <-listener.Notify:
			if !ok {
				b.log.Warn().Msg("SSE PG listener channel closed — restarting")
				return
			}
			if n == nil {
				continue
			}
			payload := b.rehydrate(n.Extra)
			msg := []byte(fmt.Sprintf("data: %s\n\n", payload))
			b.fanOut(msg)
		}
	}
}

// rehydrate replaces a truncated slim marker with the full event JSON fetched
// from the store. Without this, payloads larger than ~7.9 kB (pg_notify's
// 8000-byte limit) reach the UI as { id, event_type, agent_id, _truncated:true }
// stubs with no payload, breaking event detail and detection rules that ride
// the SSE stream.
func (b *Broker) rehydrate(extra string) string {
	if b.fetcher == nil {
		return extra
	}
	if !strings.Contains(extra, `"_truncated":true`) {
		return extra
	}
	var slim struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal([]byte(extra), &slim); err != nil || slim.ID == "" {
		return extra
	}
	tenant := slim.TenantID
	if tenant == "" {
		tenant = "default"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	full, err := b.fetcher.GetEvent(ctx, slim.ID, tenant)
	if err != nil || full == nil {
		b.log.Warn().Err(err).Str("event_id", slim.ID).Msg("SSE rehydrate failed; forwarding slim marker")
		return extra
	}
	data, err := json.Marshal(full)
	if err != nil {
		return extra
	}
	return string(data)
}

// fanOut delivers msg to all registered SSE clients. Non-blocking: slow clients
// are dropped rather than blocking the notification path.
func (b *Broker) fanOut(msg []byte) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

// Publish fires a pg_notify so every backend node fans the event to its SSE clients.
func (b *Broker) Publish(ev *models.Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	// pg_notify payload limit is 8000 bytes. When over, send a slim marker —
	// the receiving listener uses SetEventFetcher to rehydrate from the store
	// before fanning out. tenant_id is included so the lookup respects
	// multi-tenant isolation.
	if len(data) > 7900 {
		slim, _ := json.Marshal(struct {
			ID        string `json:"id"`
			EventType string `json:"event_type"`
			AgentID   string `json:"agent_id"`
			TenantID  string `json:"tenant_id"`
			Truncated bool   `json:"_truncated"`
		}{ev.ID, ev.EventType, ev.AgentID, ev.TenantID, true})
		data = slim
	}
	// When db is nil (test mode / no PG), fan out directly to in-memory clients.
	if b.db == nil {
		b.fanOut([]byte(fmt.Sprintf("data: %s\n\n", data)))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.db.ExecContext(ctx, "SELECT pg_notify($1, $2)", pgChannel, string(data)); err != nil {
		b.log.Warn().Err(err).Str("event_id", ev.ID).Msg("SSE pg_notify failed")
	}
}

// Handler returns a gin.HandlerFunc for GET /api/v1/events/stream.
func (b *Broker) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
			return
		}

		filterType  := c.Query("event_type")
		filterAgent := c.Query("agent_id")

		clientID := fmt.Sprintf("%d", time.Now().UnixNano())
		ch := make(chan []byte, 256)
		b.mu.Lock()
		b.clients[clientID] = ch
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			delete(b.clients, clientID)
			close(ch)
			b.mu.Unlock()
			b.log.Debug().Str("client", clientID).Int("remaining", len(b.clients)).Msg("SSE client disconnected")
		}()

		b.log.Debug().
			Str("client", clientID).
			Str("filter_type", filterType).
			Str("filter_agent", filterAgent).
			Msg("SSE client connected")

		c.Header("Content-Type",      "text/event-stream")
		c.Header("Cache-Control",     "no-cache")
		c.Header("Connection",        "keep-alive")
		c.Header("X-Accel-Buffering", "no")

		fmt.Fprintf(c.Writer, ": connected\n\n")
		flusher.Flush()

		keepalive := time.NewTicker(15 * time.Second)
		defer keepalive.Stop()

		for {
			select {
			case <-c.Request.Context().Done():
				return

			case <-keepalive.C:
				fmt.Fprintf(c.Writer, ": keepalive\n\n")
				flusher.Flush()

			case msg, ok := <-ch:
				if !ok {
					return
				}
				if filterType != "" || filterAgent != "" {
					var ev models.Event
					prefix := []byte("data: ")
					suffix := []byte("\n\n")
					if len(msg) > len(prefix)+len(suffix) {
						jsonBytes := msg[len(prefix) : len(msg)-len(suffix)]
						if err := json.Unmarshal(jsonBytes, &ev); err == nil {
							if filterType != "" && ev.EventType != filterType { continue }
							if filterAgent != "" && ev.AgentID != filterAgent  { continue }
						}
					}
				}
				c.Writer.Write(msg)
				flusher.Flush()
			}
		}
	}
}

// ClientCount returns the number of currently connected SSE clients on this node.
func (b *Broker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}
