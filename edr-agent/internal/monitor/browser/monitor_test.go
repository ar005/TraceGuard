package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

func TestBrowserMonitor_AcceptsEvents(t *testing.T) {
	bus := events.NewBus("test-agent", "test-host")
	var collected []events.Event
	var mu sync.Mutex

	bus.Subscribe("*", func(ev events.Event) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
	})

	m := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:19999",
	}, bus, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()

	// Wait for server to be ready.
	time.Sleep(100 * time.Millisecond)

	// Send a batch of browser events.
	batch := incomingBatch{
		Events: []incomingEvent{
			{
				URL:        "https://example.com/login",
				Method:     "GET",
				StatusCode: 200,
				Type:       "main_frame",
				Timestamp:  time.Now().Format(time.RFC3339),
			},
			{
				URL:        "https://phishing-site.tk/fake-bank",
				Method:     "POST",
				StatusCode: 200,
				Type:       "main_frame",
				Initiator:  "https://evil-email.com/link",
				Timestamp:  time.Now().Format(time.RFC3339),
			},
		},
	}

	body, _ := json.Marshal(batch)
	resp, err := http.Post("http://127.0.0.1:19999/browser-events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Accepted int `json:"accepted"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Accepted != 2 {
		t.Fatalf("expected 2 accepted, got %d", result.Accepted)
	}

	// Wait for events to propagate through bus.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 2 {
		t.Fatalf("expected 2 events on bus, got %d", len(collected))
	}

	// Check first event.
	if collected[0].EventType() != string(types.EventBrowserRequest) {
		t.Errorf("expected BROWSER_REQUEST, got %s", collected[0].EventType())
	}
}

func TestBrowserMonitor_FormSubmitTagging(t *testing.T) {
	bus := events.NewBus("test-agent", "test-host")
	var collected []events.Event
	var mu sync.Mutex

	bus.Subscribe("*", func(ev events.Event) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
	})

	m := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:19998",
	}, bus, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	// POST to main_frame = form submission.
	batch := incomingBatch{
		Events: []incomingEvent{
			{
				URL:        "https://suspicious-site.xyz/login",
				Method:     "POST",
				StatusCode: 302,
				Type:       "main_frame",
				Timestamp:  time.Now().Format(time.RFC3339),
			},
		},
	}

	body, _ := json.Marshal(batch)
	resp, err := http.Post("http://127.0.0.1:19998/browser-events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 1 {
		t.Fatalf("expected 1 event, got %d", len(collected))
	}

	// Verify it was tagged as form-submit and auth-page.
	ev, ok := collected[0].(*types.BrowserRequestEvent)
	if !ok {
		t.Fatal("event is not BrowserRequestEvent")
	}
	if !ev.IsFormSubmit {
		t.Error("expected IsFormSubmit=true")
	}

	hasTag := func(tag string) bool {
		for _, t := range ev.Tags {
			if t == tag {
				return true
			}
		}
		return false
	}
	if !hasTag("form-submit") {
		t.Error("expected form-submit tag")
	}
	if !hasTag("auth-page") {
		t.Error("expected auth-page tag for /login URL")
	}
}

func TestBrowserMonitor_RejectsNonLocalhost(t *testing.T) {
	m := New(Config{
		Enabled:    true,
		ListenAddr: "0.0.0.0:19997",
	}, events.NewBus("test", "test"), zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := m.Start(ctx)
	if err == nil {
		m.Stop()
		t.Fatal("expected error for non-localhost bind, got nil")
	}
}

func TestBrowserMonitor_Health(t *testing.T) {
	m := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:19996",
	}, events.NewBus("test", "test"), zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:19996/health")
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestBrowserMonitor_RedirectChain(t *testing.T) {
	bus := events.NewBus("test-agent", "test-host")
	var collected []events.Event
	var mu sync.Mutex

	bus.Subscribe("*", func(ev events.Event) {
		mu.Lock()
		collected = append(collected, ev)
		mu.Unlock()
	})

	m := New(Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:19995",
	}, bus, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)

	batch := incomingBatch{
		Events: []incomingEvent{
			{
				URL:        "https://final-phishing.com/steal",
				Method:     "GET",
				StatusCode: 200,
				Type:       "main_frame",
				Timestamp:  time.Now().Format(time.RFC3339),
				RedirectChain: []redirectEntry{
					{URL: "https://bit.ly/abc123", StatusCode: 301},
					{URL: "https://redirect1.com/go", StatusCode: 302},
					{URL: "https://redirect2.com/hop", StatusCode: 302},
				},
			},
		},
	}

	body, _ := json.Marshal(batch)
	resp, err := http.Post("http://127.0.0.1:19995/browser-events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(collected) != 1 {
		t.Fatalf("expected 1 event, got %d", len(collected))
	}

	ev := collected[0].(*types.BrowserRequestEvent)
	if len(ev.RedirectChain) != 3 {
		t.Errorf("expected 3 redirects, got %d", len(ev.RedirectChain))
	}

	hasTag := func(tag string) bool {
		for _, t := range ev.Tags {
			if t == tag {
				return true
			}
		}
		return false
	}
	if !hasTag("redirected") {
		t.Error("expected redirected tag")
	}
}
