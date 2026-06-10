// internal/llm/summarise_incident_test.go — unit tests for SummariseIncident.

package llm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// mockProvider implements Provider for testing.
type mockProvider struct {
	name     string
	response string
	err      error
	calls    int
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) ExplainAlert(_ context.Context, _ *models.Alert, _ []models.Event) (string, error) {
	m.calls++
	return m.response, m.err
}
func (m *mockProvider) Complete(_ context.Context, _, _ string) (string, error) {
	m.calls++
	return m.response, m.err
}

func newTestClient(p Provider, enabled bool) *Client {
	c := &Client{
		cfg:      Config{Enabled: enabled, Provider: "mock", Model: "mock-model"},
		log:      zerolog.Nop(),
		provider: p,
	}
	return c
}

func makeTestIncident() *models.Incident {
	now := time.Now()
	return &models.Incident{
		ID:         "inc-1",
		TenantID:   "t1",
		Title:      "Suspicious lateral movement",
		Severity:   3,
		Status:     "open",
		Hostnames:  []string{"host-a", "host-b"},
		MitreIDs:   []string{"T1021", "T1078"},
		AlertCount: 3,
		FirstSeen:  now.Add(-10 * time.Minute),
		LastSeen:   now,
	}
}

func makeTestAlerts() []models.Alert {
	now := time.Now()
	return []models.Alert{
		{ID: "a1", Title: "Brute force login", Severity: 3, Hostname: "host-a", RuleName: "brute-force"},
		{ID: "a2", Title: "Pass-the-hash", Severity: 4, Hostname: "host-b", RuleName: "pth-detect", FirstSeen: now},
	}
}

func TestSummariseIncident_NotEnabled(t *testing.T) {
	p := &mockProvider{response: "should not be called"}
	c := newTestClient(p, false)

	_, err := c.SummariseIncident(context.Background(), makeTestIncident(), makeTestAlerts())
	if err == nil {
		t.Fatal("want error when LLM not enabled")
	}
	if p.calls != 0 {
		t.Fatalf("provider should not be called, got %d calls", p.calls)
	}
}

func TestSummariseIncident_NilProvider(t *testing.T) {
	c := &Client{
		cfg: Config{Enabled: true},
		log: zerolog.Nop(),
	}
	_, err := c.SummariseIncident(context.Background(), makeTestIncident(), makeTestAlerts())
	if err == nil {
		t.Fatal("want error when provider is nil")
	}
}

func TestSummariseIncident_ProviderError(t *testing.T) {
	p := &mockProvider{err: errors.New("LLM timeout")}
	c := newTestClient(p, true)

	_, err := c.SummariseIncident(context.Background(), makeTestIncident(), makeTestAlerts())
	if err == nil {
		t.Fatal("want error propagated from provider")
	}
	if !errors.Is(err, p.err) && err.Error() != p.err.Error() {
		t.Errorf("error not propagated: got %v", err)
	}
}

func TestSummariseIncident_Success(t *testing.T) {
	expected := "Lateral movement detected across 2 hosts using stolen credentials."
	p := &mockProvider{response: expected}
	c := newTestClient(p, true)

	result, err := c.SummariseIncident(context.Background(), makeTestIncident(), makeTestAlerts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != expected {
		t.Errorf("want %q, got %q", expected, result)
	}
	if p.calls != 1 {
		t.Fatalf("provider should be called once, got %d", p.calls)
	}
}

func TestSummariseIncident_EmptyAlerts(t *testing.T) {
	p := &mockProvider{response: "incident with no linked alerts"}
	c := newTestClient(p, true)

	result, err := c.SummariseIncident(context.Background(), makeTestIncident(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("want non-empty result")
	}
	if p.calls != 1 {
		t.Fatalf("provider should be called once, got %d", p.calls)
	}
}

func TestSummariseIncident_TruncatesAlerts(t *testing.T) {
	// Provide 15 alerts — SummariseIncident should cap at 10.
	alerts := make([]models.Alert, 15)
	for i := range alerts {
		alerts[i] = models.Alert{ID: "a", Title: "Alert", Severity: 2, Hostname: "h"}
	}
	p := &mockProvider{response: "summary"}
	c := newTestClient(p, true)

	_, err := c.SummariseIncident(context.Background(), makeTestIncident(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The function must not panic with many alerts; just verify it completes.
	if p.calls != 1 {
		t.Fatalf("provider should be called once, got %d", p.calls)
	}
}
