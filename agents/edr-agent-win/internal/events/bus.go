// internal/events/bus.go
// Central event bus — identical to Linux agent.

package events

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type Event interface {
	EventType() string
	EventID() string
}

type Handler func(event Event)

type Bus interface {
	Publish(event Event)
	Subscribe(eventType string, handler Handler) func()
	AgentID() string
	Hostname() string
	Stats() BusStats
}

type BusStats struct {
	Published uint64
	Dropped   uint64
	Handlers  int
}

type DefaultBus struct {
	agentID  string
	hostname string
	mu          sync.RWMutex
	subscribers map[string][]*subscriberEntry
	published atomic.Uint64
	dropped   atomic.Uint64
}

type subscriberEntry struct {
	id      string
	ch      chan Event
	handler Handler
	once    sync.Once
}

func NewBus(agentID, hostname string) *DefaultBus {
	return &DefaultBus{
		agentID:     agentID,
		hostname:    hostname,
		subscribers: make(map[string][]*subscriberEntry),
	}
}

func (b *DefaultBus) Publish(event Event) {
	b.published.Add(1)
	b.mu.RLock()
	defer b.mu.RUnlock()

	evType := event.EventType()
	var targets []*subscriberEntry
	targets = append(targets, b.subscribers[evType]...)
	targets = append(targets, b.subscribers["*"]...)
	for _, target := range targets {
		select {
		case target.ch <- event:
		default:
			b.dropped.Add(1)
		}
	}
}

func (b *DefaultBus) Subscribe(eventType string, handler Handler) func() {
	const bufSize = 4096
	entry := &subscriberEntry{
		id:      newID(),
		ch:      make(chan Event, bufSize),
		handler: handler,
	}
	b.mu.Lock()
	b.subscribers[eventType] = append(b.subscribers[eventType], entry)
	b.mu.Unlock()

	go func() {
		for event := range entry.ch {
			handler(event)
		}
	}()

	return func() {
		b.mu.Lock()
		subs := b.subscribers[eventType]
		filtered := make([]*subscriberEntry, 0, len(subs))
		for _, s := range subs {
			if s.id != entry.id {
				filtered = append(filtered, s)
			}
		}
		b.subscribers[eventType] = filtered
		b.mu.Unlock()
		entry.once.Do(func() { close(entry.ch) })
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

func newID() string { return fmt.Sprintf("%d", idCounter.Add(1)) }

var idCounter atomic.Uint64
