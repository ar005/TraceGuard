package sse

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

func newTestBroker() *Broker {
	return New(zerolog.New(os.Stderr).Level(zerolog.Disabled))
}

func TestPublishToSubscriber(t *testing.T) {
	b := newTestBroker()

	// Manually register a client channel.
	ch := make(chan []byte, 16)
	b.mu.Lock()
	b.clients["test-1"] = ch
	b.mu.Unlock()

	ev := &models.Event{
		ID:        "ev-1",
		AgentID:   "agent-1",
		EventType: "PROCESS_EXEC",
	}
	b.Publish(ev)

	select {
	case msg := <-ch:
		// Verify the message is SSE-formatted with JSON data.
		if len(msg) < 6 {
			t.Fatalf("message too short: %q", msg)
		}
		// Strip "data: " prefix and trailing "\n\n".
		jsonBytes := msg[6 : len(msg)-2]
		var got models.Event
		if err := json.Unmarshal(jsonBytes, &got); err != nil {
			t.Fatalf("failed to unmarshal event: %v", err)
		}
		if got.ID != "ev-1" {
			t.Errorf("event ID = %q, want %q", got.ID, "ev-1")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestMultipleSubscribersReceiveSameEvent(t *testing.T) {
	b := newTestBroker()

	ch1 := make(chan []byte, 16)
	ch2 := make(chan []byte, 16)
	b.mu.Lock()
	b.clients["sub-1"] = ch1
	b.clients["sub-2"] = ch2
	b.mu.Unlock()

	ev := &models.Event{ID: "ev-multi", EventType: "NET_CONNECT"}
	b.Publish(ev)

	for _, ch := range []chan []byte{ch1, ch2} {
		select {
		case msg := <-ch:
			if len(msg) == 0 {
				t.Error("received empty message")
			}
		case <-time.After(time.Second):
			t.Error("subscriber did not receive event")
		}
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	b := newTestBroker()

	ch := make(chan []byte, 16)
	b.mu.Lock()
	b.clients["temp"] = ch
	b.mu.Unlock()

	// Remove the client (simulating unsubscribe/disconnect).
	b.mu.Lock()
	delete(b.clients, "temp")
	b.mu.Unlock()

	ev := &models.Event{ID: "ev-after-unsub", EventType: "FILE_OPEN"}
	b.Publish(ev)

	select {
	case msg := <-ch:
		t.Errorf("should not have received event after unsubscribe, got %q", msg)
	case <-time.After(50 * time.Millisecond):
		// Expected: no message.
	}
}

func TestNonBlockingPublish(t *testing.T) {
	b := newTestBroker()

	// Create a channel with buffer size 1 so it fills quickly.
	ch := make(chan []byte, 1)
	b.mu.Lock()
	b.clients["slow"] = ch
	b.mu.Unlock()

	// Fill the channel.
	ev := &models.Event{ID: "fill", EventType: "PROCESS_EXEC"}
	b.Publish(ev)

	// This second publish should not block even though channel is full.
	done := make(chan struct{})
	go func() {
		b.Publish(&models.Event{ID: "overflow", EventType: "PROCESS_EXEC"})
		close(done)
	}()

	select {
	case <-done:
		// Good: publish did not block.
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on full channel")
	}
}

func TestClientCount(t *testing.T) {
	b := newTestBroker()
	if b.ClientCount() != 0 {
		t.Errorf("initial ClientCount = %d, want 0", b.ClientCount())
	}

	b.mu.Lock()
	b.clients["a"] = make(chan []byte, 1)
	b.clients["b"] = make(chan []byte, 1)
	b.mu.Unlock()

	if b.ClientCount() != 2 {
		t.Errorf("ClientCount = %d, want 2", b.ClientCount())
	}
}
