// internal/events/bus.go
//
// Central event bus. Every monitor publishes events here.
// Subscribers (detection engine, buffer, transport) consume from their channels.
// Designed for high throughput: non-blocking publish with configurable overflow policy.

package events

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Event is the interface all event types implement.
// Concrete types are defined in pkg/types/.
type Event interface {
	EventType() string
	EventID() string
}

// Handler is a function that receives an event.
type Handler func(event Event)

// Bus is the central event dispatcher.
type Bus interface {
	// Publish sends an event to all subscribers. Non-blocking.
	Publish(event Event)

	// Subscribe registers a handler for a specific event type (or "*" for all).
	// Returns an unsubscribe function.
	Subscribe(eventType string, handler Handler) func()

	// AgentID returns the agent's unique ID (used by monitors when building events).
	AgentID() string

	// Hostname returns the monitored host's hostname.
	Hostname() string

	// Stats returns current bus metrics.
	Stats() BusStats
}

// BusStats holds runtime metrics for the event bus.
type BusStats struct {
	Published uint64
	Dropped   uint64
	Handlers  int
}

// ─── DefaultBus ───────────────────────────────────────────────────────────────

// DefaultBus is a synchronous fan-out bus with per-subscriber async channels.
type DefaultBus struct {
	agentID  string
	hostname string

	mu          sync.RWMutex
	subscribers map[string][]*subscriberEntry // eventType → []handlers

	published atomic.Uint64
	dropped   atomic.Uint64
}

type subscriberEntry struct {
	id      string
	ch      chan Event
	handler Handler
	once    sync.Once // ensures close happens once
}

// NewBus creates a DefaultBus. agentID and hostname are embedded into every event.
func NewBus(agentID, hostname string) *DefaultBus {
	b := &DefaultBus{
		agentID:     agentID,
		hostname:    hostname,
		subscribers: make(map[string][]*subscriberEntry),
	}
	return b
}

// Publish fans out the event to all matching subscribers.
// Uses buffered channels; drops and counts if channel is full.
func (b *DefaultBus) Publish(event Event) {
	b.published.Add(1)

	b.mu.RLock()
	defer b.mu.RUnlock()

	evType := event.EventType()

	// Collect matching subscribers (specific type + wildcard "*").
	var targets []*subscriberEntry
	targets = append(targets, b.subscribers[evType]...)
	targets = append(targets, b.subscribers["*"]...)

	for _, target := range targets {
		select {
		case target.ch <- event:
		default:
			// Channel full: drop and count.
			b.dropped.Add(1)
		}
	}
}

// Subscribe registers a handler. The handler runs in its own goroutine.
// bufSize controls the channel buffer depth.
func (b *DefaultBus) Subscribe(eventType string, handler Handler) func() {
	const bufSize = 16384

	entry := &subscriberEntry{
		id:      newID(),
		ch:      make(chan Event, bufSize),
		handler: handler,
	}

	b.mu.Lock()
	b.subscribers[eventType] = append(b.subscribers[eventType], entry)
	b.mu.Unlock()

	// Consumer goroutine.
	go func() {
		for event := range entry.ch {
			handler(event)
		}
	}()

	// Return unsubscribe function.
	return func() {
		b.mu.Lock()
		subs := b.subscribers[eventType]
		filtered := subs[:0]
		for _, s := range subs {
			if s.id != entry.id {
				filtered = append(filtered, s)
			}
		}
		b.subscribers[eventType] = filtered
		b.mu.Unlock()

		entry.once.Do(func() {
			close(entry.ch)
		})
	}
}

func (b *DefaultBus) AgentID() string  { return b.agentID }
func (b *DefaultBus) Hostname() string { return b.hostname }
func (b *DefaultBus) Stats() BusStats {
	b.mu.RLock()
	handlers := 0
	for _, subs := range b.subscribers {
		handlers += len(subs)
	}
	b.mu.RUnlock()
	return BusStats{
		Published: b.published.Load(),
		Dropped:   b.dropped.Load(),
		Handlers:  handlers,
	}
}

func newID() string {
	// Simple monotonic counter — fine for internal subscriber IDs.
	return fmt.Sprintf("%d", idCounter.Add(1))
}

var idCounter atomic.Uint64

// ─── Event type adapters ──────────────────────────────────────────────────────
// Implement the Event interface on all pkg/types event structs.

