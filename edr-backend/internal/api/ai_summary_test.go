// internal/api/ai_summary_test.go — unit tests for summariseAlertFrom / summariseIncidentFrom.
// Uses mock implementations of the narrow interfaces; no database or real LLM required.

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

func init() { gin.SetMode(gin.TestMode) }

// ── mocks ─────────────────────────────────────────────────────────────────────

type mockAlertStore struct {
	alert          *models.Alert
	alertErr       error
	events         []models.Event
	storedSummary  string
	updateErr      error
}

func (m *mockAlertStore) GetAlert(_ context.Context, _, _ string) (*models.Alert, error) {
	return m.alert, m.alertErr
}
func (m *mockAlertStore) GetAlertEvents(_ context.Context, _, _ string) ([]models.Event, error) {
	return m.events, nil
}
func (m *mockAlertStore) UpdateAlertAISummary(_ context.Context, _, _, summary string) error {
	m.storedSummary = summary
	return m.updateErr
}

type mockIncidentStore struct {
	incident      *models.Incident
	incidentErr   error
	alerts        []models.Alert
	storedSummary string
}

func (m *mockIncidentStore) GetIncident(_ context.Context, _, _ string) (*models.Incident, error) {
	return m.incident, m.incidentErr
}
func (m *mockIncidentStore) GetIncidentAlerts(_ context.Context, _ string) ([]models.Alert, error) {
	return m.alerts, nil
}
func (m *mockIncidentStore) UpdateIncidentAISummary(_ context.Context, _, _, summary string) error {
	m.storedSummary = summary
	return nil
}

type mockLLM struct {
	enabled      bool
	summary      string
	llmErr       error
	explainCalls int
	incCalls     int
}

func (m *mockLLM) Enabled() bool      { return m.enabled }
func (m *mockLLM) ModelName() string   { return "test-model" }
func (m *mockLLM) ProviderName() string { return "test-provider" }
func (m *mockLLM) ExplainAlert(_ context.Context, _ *models.Alert, _ []models.Event) (string, error) {
	m.explainCalls++
	return m.summary, m.llmErr
}
func (m *mockLLM) SummariseIncident(_ context.Context, _ *models.Incident, _ []models.Alert) (string, error) {
	m.incCalls++
	return m.summary, m.llmErr
}

// ── helpers ───────────────────────────────────────────────────────────────────

func nopLog() zerolog.Logger { return zerolog.Nop() }

func makeAlert(id, summary string) *models.Alert {
	now := time.Now()
	return &models.Alert{
		ID:        id,
		TenantID:  "t1",
		Title:     "Test Alert",
		Hostname:  "host1",
		Severity:  3,
		FirstSeen: now,
		LastSeen:  now,
		AISummary: summary,
	}
}

func makeIncident(id, summary string) *models.Incident {
	now := time.Now()
	return &models.Incident{
		ID:        id,
		TenantID:  "t1",
		Title:     "Test Incident",
		Severity:  3,
		FirstSeen: now,
		LastSeen:  now,
		AISummary: summary,
	}
}

// newAlertRouter builds a Gin router that exercises summariseAlertFrom with the given deps.
func newAlertRouter(st alertSummariseStore, lm summariseLLM, force bool) *gin.Engine {
	r := gin.New()
	r.POST("/api/v1/alerts/:id/summarise", func(c *gin.Context) {
		c.Set("tenant_id", "t1")
		summariseAlertFrom(c, st, lm, nopLog())
	})
	return r
}

func doAlertSummarise(r *gin.Engine, alertID string, force bool) *httptest.ResponseRecorder {
	url := "/api/v1/alerts/" + alertID + "/summarise"
	if force {
		url += "?force=1"
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, url, http.NoBody)
	r.ServeHTTP(w, req)
	return w
}

func newIncidentRouter(st incidentSummariseStore, lm summariseLLM) *gin.Engine {
	r := gin.New()
	r.POST("/api/v1/incidents/:id/summarise", func(c *gin.Context) {
		c.Set("tenant_id", "t1")
		summariseIncidentFrom(c, st, lm, nopLog())
	})
	return r
}

func doIncidentSummarise(r *gin.Engine, incID string, force bool) *httptest.ResponseRecorder {
	url := "/api/v1/incidents/" + incID + "/summarise"
	if force {
		url += "?force=1"
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, url, http.NoBody)
	r.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return out
}

// ── alert summarise tests ─────────────────────────────────────────────────────

func TestSummariseAlert_LLMDisabled(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("a1", "")}
	lm := &mockLLM{enabled: false}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "a1", false)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] == nil {
		t.Fatal("want error field in response")
	}
	if lm.explainCalls != 0 {
		t.Fatalf("LLM should not be called when disabled, got %d calls", lm.explainCalls)
	}
}

func TestSummariseAlert_LLMNil(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("a1", "")}
	w := doAlertSummarise(newAlertRouter(st, nil, false), "a1", false)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
}

func TestSummariseAlert_AlertNotFound(t *testing.T) {
	st := &mockAlertStore{alertErr: sql.ErrNoRows}
	lm := &mockLLM{enabled: true}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "missing", false)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", w.Code)
	}
}

func TestSummariseAlert_StoreError(t *testing.T) {
	st := &mockAlertStore{alertErr: errors.New("db connection lost")}
	lm := &mockLLM{enabled: true}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "a1", false)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", w.Code)
	}
	if lm.explainCalls != 0 {
		t.Fatalf("LLM should not be called on store error")
	}
}

func TestSummariseAlert_CachedSummaryReturned(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("a1", "cached explanation")}
	lm := &mockLLM{enabled: true, summary: "fresh explanation"}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "a1", false)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["summary"] != "cached explanation" {
		t.Errorf("want cached explanation, got %v", body["summary"])
	}
	if body["cached"] != true {
		t.Errorf("want cached=true, got %v", body["cached"])
	}
	if lm.explainCalls != 0 {
		t.Fatalf("LLM should not be called when summary is cached, got %d calls", lm.explainCalls)
	}
}

func TestSummariseAlert_ForceBypassesCache(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("a1", "old cached")}
	lm := &mockLLM{enabled: true, summary: "fresh summary"}
	w := doAlertSummarise(newAlertRouter(st, lm, true), "a1", true)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["summary"] != "fresh summary" {
		t.Errorf("want fresh summary, got %v", body["summary"])
	}
	if body["cached"] != false {
		t.Errorf("want cached=false, got %v", body["cached"])
	}
	if lm.explainCalls != 1 {
		t.Fatalf("LLM should be called exactly once with force=1, got %d", lm.explainCalls)
	}
	if st.storedSummary != "fresh summary" {
		t.Errorf("summary should be persisted; stored=%q", st.storedSummary)
	}
}

func TestSummariseAlert_FreshGeneration(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("a1", "")} // no cached summary
	lm := &mockLLM{enabled: true, summary: "new AI summary"}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "a1", false)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["summary"] != "new AI summary" {
		t.Errorf("want new AI summary, got %v", body["summary"])
	}
	if body["cached"] != false {
		t.Errorf("want cached=false, got %v", body["cached"])
	}
	if body["model"] != "test-model" {
		t.Errorf("want test-model, got %v", body["model"])
	}
	if body["provider"] != "test-provider" {
		t.Errorf("want test-provider, got %v", body["provider"])
	}
	if st.storedSummary != "new AI summary" {
		t.Errorf("summary should be persisted; stored=%q", st.storedSummary)
	}
	if lm.explainCalls != 1 {
		t.Fatalf("LLM should be called exactly once, got %d", lm.explainCalls)
	}
}

func TestSummariseAlert_LLMError(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("a1", "")}
	lm := &mockLLM{enabled: true, llmErr: errors.New("provider timeout")}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "a1", false)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] == nil {
		t.Fatal("want error field in response")
	}
	if st.storedSummary != "" {
		t.Errorf("nothing should be stored on LLM error; stored=%q", st.storedSummary)
	}
}

func TestSummariseAlert_ResponseFieldsPresent(t *testing.T) {
	st := &mockAlertStore{alert: makeAlert("alert-xyz", "")}
	lm := &mockLLM{enabled: true, summary: "summary text"}
	w := doAlertSummarise(newAlertRouter(st, lm, false), "alert-xyz", false)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeBody(t, w)
	for _, field := range []string{"alert_id", "summary", "cached", "model", "provider"} {
		if _, ok := body[field]; !ok {
			t.Errorf("response missing field %q", field)
		}
	}
	if body["alert_id"] != "alert-xyz" {
		t.Errorf("alert_id mismatch: %v", body["alert_id"])
	}
}

// ── incident summarise tests ──────────────────────────────────────────────────

func TestSummariseIncident_LLMDisabled(t *testing.T) {
	st := &mockIncidentStore{incident: makeIncident("i1", "")}
	lm := &mockLLM{enabled: false}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "i1", false)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
	if lm.incCalls != 0 {
		t.Fatalf("LLM should not be called when disabled, got %d calls", lm.incCalls)
	}
}

func TestSummariseIncident_IncidentNotFound(t *testing.T) {
	st := &mockIncidentStore{incidentErr: errors.New("not found")}
	lm := &mockLLM{enabled: true}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "missing", false)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", w.Code)
	}
}

func TestSummariseIncident_CachedSummaryReturned(t *testing.T) {
	st := &mockIncidentStore{incident: makeIncident("i1", "cached incident summary")}
	lm := &mockLLM{enabled: true, summary: "fresh"}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "i1", false)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["summary"] != "cached incident summary" {
		t.Errorf("want cached, got %v", body["summary"])
	}
	if body["cached"] != true {
		t.Errorf("want cached=true")
	}
	if lm.incCalls != 0 {
		t.Fatalf("LLM should not be called, got %d calls", lm.incCalls)
	}
}

func TestSummariseIncident_ForceBypassesCache(t *testing.T) {
	st := &mockIncidentStore{incident: makeIncident("i1", "old")}
	lm := &mockLLM{enabled: true, summary: "incident fresh summary"}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "i1", true)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["summary"] != "incident fresh summary" {
		t.Errorf("got %v", body["summary"])
	}
	if body["cached"] != false {
		t.Errorf("want cached=false")
	}
	if lm.incCalls != 1 {
		t.Fatalf("LLM should be called once, got %d", lm.incCalls)
	}
	if st.storedSummary != "incident fresh summary" {
		t.Errorf("summary not persisted: %q", st.storedSummary)
	}
}

func TestSummariseIncident_FreshGeneration(t *testing.T) {
	st := &mockIncidentStore{incident: makeIncident("i1", "")}
	lm := &mockLLM{enabled: true, summary: "new incident summary"}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "i1", false)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["summary"] != "new incident summary" {
		t.Errorf("got %v", body["summary"])
	}
	if body["incident_id"] != "i1" {
		t.Errorf("incident_id mismatch: %v", body["incident_id"])
	}
	if lm.incCalls != 1 {
		t.Fatalf("LLM should be called once, got %d", lm.incCalls)
	}
}

func TestSummariseIncident_LLMError(t *testing.T) {
	st := &mockIncidentStore{incident: makeIncident("i1", "")}
	lm := &mockLLM{enabled: true, llmErr: errors.New("upstream error")}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "i1", false)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", w.Code)
	}
	if st.storedSummary != "" {
		t.Errorf("nothing should be stored on LLM error")
	}
}

func TestSummariseIncident_ResponseFieldsPresent(t *testing.T) {
	st := &mockIncidentStore{incident: makeIncident("inc-abc", "")}
	lm := &mockLLM{enabled: true, summary: "incident summary"}
	w := doIncidentSummarise(newIncidentRouter(st, lm), "inc-abc", false)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := decodeBody(t, w)
	for _, field := range []string{"incident_id", "summary", "cached", "model", "provider"} {
		if _, ok := body[field]; !ok {
			t.Errorf("response missing field %q", field)
		}
	}
}
