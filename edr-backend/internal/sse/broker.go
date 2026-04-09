// internal/sse/broker.go
//
// Server-Sent Events broker.
// The ingest pipeline publishes events here; connected HTTP clients receive
// a real-time stream of JSON-encoded event envelopes via text/event-stream.
//
// Architecture:
//   Broker.Publish(ev)  — called by ingest after every InsertEvent
//   Broker.Handler()    — gin handler for GET /api/v1/events/stream
//
// Each connected client gets its own buffered channel (size 256).
// Slow clients are silently dropped (non-blocking send) — we never block
// the hot ingest path for a lagging browser tab.

package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// Broker fans out events to all connected SSE clients.
type Broker struct {
	mu      sync.RWMutex
	clients map[string]chan []byte // client-id → channel
	log     zerolog.Logger
}

// New creates an SSE Broker.
func New(log zerolog.Logger) *Broker {
	return &Broker{
		clients: make(map[string]chan []byte),
		log:     log.With().Str("component", "sse").Logger(),
	}
}

// Publish fans an event out to all connected clients.
// Non-blocking: slow clients are dropped, never block ingest.
func (b *Broker) Publish(ev *models.Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	msg := []byte(fmt.Sprintf("data: %s\n\n", data))

	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.clients {
		select {
		case ch <- msg:
		default:
			// Client is too slow — drop this event for that client.
		}
	}
}

// Handler returns a gin.HandlerFunc for GET /api/v1/events/stream.
// Streams events as SSE until the client disconnects.
// Auth is handled by the standard authMiddleware wrapping this route.
func (b *Broker) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// SSE requires flushing — check the ResponseWriter supports it.
		//flusher, ok := c.Writer.ResponseWriter.(http.Flusher)
		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
			return
		}

		// Optional filter params: ?event_type=NET_CONNECT&agent_id=xxx
		filterType  := c.Query("event_type")
		filterAgent := c.Query("agent_id")

		// Register this client.
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

		// SSE headers.
		c.Header("Content-Type",                "text/event-stream")
		c.Header("Cache-Control",               "no-cache")
		c.Header("Connection",                  "keep-alive")
		c.Header("X-Accel-Buffering",           "no") // disable nginx buffering
		c.Header("Access-Control-Allow-Origin", "*")

		// Send a comment immediately so the browser knows the stream is alive.
		fmt.Fprintf(c.Writer, ": connected\n\n")
		flusher.Flush()

		// Keepalive ticker — browsers disconnect if no data for ~30s.
		keepalive := time.NewTicker(15 * time.Second)
		defer keepalive.Stop()

		for {
			select {
			case <-c.Request.Context().Done():
				return

			case <-keepalive.C:
				// SSE comment line — keeps connection alive without emitting an event.
				fmt.Fprintf(c.Writer, ": keepalive\n\n")
				flusher.Flush()

			case msg, ok := <-ch:
				if !ok {
					return
				}
				// Apply filters if specified.
				if filterType != "" || filterAgent != "" {
					var ev models.Event
					// msg is "data: {...}\n\n" — strip prefix to get JSON
					if len(msg) > 6 {
						if err := json.Unmarshal(msg[6:len(msg)-2], &ev); err == nil {
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

// ClientCount returns the number of currently connected SSE clients.
func (b *Broker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}
