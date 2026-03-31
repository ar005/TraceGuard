package events

import (
	"sync"
	"testing"
	"time"
)

// testEvent is a minimal Event implementation for tests.
type testEvent struct {
	typ string
	id  string
}

func (e *testEvent) EventType() string { return e.typ }
func (e *testEvent) EventID() string   { return e.id }

func TestPublishSubscribeBasic(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	received := make(chan Event, 1)
	unsub := bus.Subscribe("PROCESS_EXEC", func(ev Event) {
		received <- ev
	})
	defer unsub()

	ev := &testEvent{typ: "PROCESS_EXEC", id: "e1"}
	bus.Publish(ev)

	select {
	case got := <-received:
		if got.EventID() != "e1" {
			t.Errorf("EventID = %q, want %q", got.EventID(), "e1")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestWildcardSubscriber(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	received := make(chan Event, 10)
	unsub := bus.Subscribe("*", func(ev Event) {
		received <- ev
	})
	defer unsub()

	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "e1"})
	bus.Publish(&testEvent{typ: "NET_CONNECT", id: "e2"})
	bus.Publish(&testEvent{typ: "FILE_OPEN", id: "e3"})

	// Wait briefly for async delivery.
	time.Sleep(100 * time.Millisecond)

	if len(received) < 3 {
		t.Errorf("wildcard subscriber received %d events, want 3", len(received))
	}
}

func TestTypeSpecificSubscriber(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	received := make(chan Event, 10)
	unsub := bus.Subscribe("NET_CONNECT", func(ev Event) {
		received <- ev
	})
	defer unsub()

	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "e1"})
	bus.Publish(&testEvent{typ: "NET_CONNECT", id: "e2"})
	bus.Publish(&testEvent{typ: "FILE_OPEN", id: "e3"})

	time.Sleep(100 * time.Millisecond)

	if len(received) != 1 {
		t.Fatalf("type-specific subscriber received %d events, want 1", len(received))
	}
	got := <-received
	if got.EventID() != "e2" {
		t.Errorf("EventID = %q, want %q", got.EventID(), "e2")
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	received := make(chan Event, 10)
	unsub := bus.Subscribe("PROCESS_EXEC", func(ev Event) {
		received <- ev
	})

	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "e1"})
	time.Sleep(50 * time.Millisecond)

	unsub()
	// Give the channel time to close.
	time.Sleep(50 * time.Millisecond)

	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "e2"})
	time.Sleep(50 * time.Millisecond)

	// Should have received only the first event.
	count := len(received)
	if count != 1 {
		t.Errorf("received %d events after unsub, want 1", count)
	}
}

func TestStatsTracking(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	unsub := bus.Subscribe("PROCESS_EXEC", func(ev Event) {})
	defer unsub()

	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "e1"})
	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "e2"})
	bus.Publish(&testEvent{typ: "NET_CONNECT", id: "e3"})

	stats := bus.Stats()
	if stats.Published != 3 {
		t.Errorf("Published = %d, want 3", stats.Published)
	}
	if stats.Handlers != 1 {
		t.Errorf("Handlers = %d, want 1", stats.Handlers)
	}
}

func TestMultipleSubscribersReceiveSameEvent(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	ch1 := make(chan Event, 1)
	ch2 := make(chan Event, 1)

	unsub1 := bus.Subscribe("PROCESS_EXEC", func(ev Event) { ch1 <- ev })
	unsub2 := bus.Subscribe("PROCESS_EXEC", func(ev Event) { ch2 <- ev })
	defer unsub1()
	defer unsub2()

	bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "shared"})

	for i, ch := range []chan Event{ch1, ch2} {
		select {
		case got := <-ch:
			if got.EventID() != "shared" {
				t.Errorf("subscriber %d: EventID = %q, want %q", i, got.EventID(), "shared")
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %d: timed out", i)
		}
	}
}

func TestAgentIDAndHostname(t *testing.T) {
	bus := NewBus("my-agent", "my-host")
	if bus.AgentID() != "my-agent" {
		t.Errorf("AgentID = %q, want %q", bus.AgentID(), "my-agent")
	}
	if bus.Hostname() != "my-host" {
		t.Errorf("Hostname = %q, want %q", bus.Hostname(), "my-host")
	}
}

func TestConcurrentPublish(t *testing.T) {
	bus := NewBus("test-agent", "test-host")

	var count int64
	var mu sync.Mutex
	unsub := bus.Subscribe("*", func(ev Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	defer unsub()

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			bus.Publish(&testEvent{typ: "PROCESS_EXEC", id: "concurrent"})
		}(i)
	}
	wg.Wait()

	// Give async handlers time to finish.
	time.Sleep(200 * time.Millisecond)

	stats := bus.Stats()
	if stats.Published != uint64(n) {
		t.Errorf("Published = %d, want %d", stats.Published, n)
	}
}
