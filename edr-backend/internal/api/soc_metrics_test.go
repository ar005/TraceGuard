package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/models"
)

func init() { gin.SetMode(gin.TestMode) }

/* ── Mock ───────────────────────────────────────────────────────── */

type mockSOCQuerier struct {
	metrics *models.SOCMetrics
	err     error
}

func (m *mockSOCQuerier) GetSOCMetrics(_ context.Context) (*models.SOCMetrics, error) {
	return m.metrics, m.err
}

/* ── Helpers ─────────────────────────────────────────────────────── */

func buildSOCRouter(q socMetricsQuerier) *gin.Engine {
	r := gin.New()
	r.GET("/api/v1/metrics/soc", func(c *gin.Context) {
		handleSOCMetricsFrom(c, q)
	})
	return r
}

func doSOCRequest(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/soc", nil)
	r.ServeHTTP(w, req)
	return w
}

/* ── Tests ───────────────────────────────────────────────────────── */

func TestHandleSOCMetrics_Success(t *testing.T) {
	data := &models.SOCMetrics{
		MTTRHours:     2.5,
		OpenAlertAgeH: 1.3,
		ResolutionRate: 75.0,
		FPRate:        8.0,
		TotalAlerts7d: 42,
		AlertTrend: []models.AlertTrendDay{
			{Date: "2025-05-10", Critical: 3, High: 7},
			{Date: "2025-05-11", Medium: 5},
		},
		TopRules: []models.RuleFireCount{
			{RuleName: "Suspicious PowerShell", Count: 12},
		},
		AnalystWorkload: []models.AnalystLoad{
			{Assignee: "alice@corp.com", OpenCount: 5, Total7d: 18},
		},
		StatusFunnel: map[string]int64{"OPEN": 10, "CLOSED": 32},
	}

	w := doSOCRequest(buildSOCRouter(&mockSOCQuerier{metrics: data}))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var got models.SOCMetrics
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got.MTTRHours != data.MTTRHours {
		t.Errorf("mttr_hours: want %v got %v", data.MTTRHours, got.MTTRHours)
	}
	if got.TotalAlerts7d != data.TotalAlerts7d {
		t.Errorf("total_alerts_7d: want %d got %d", data.TotalAlerts7d, got.TotalAlerts7d)
	}
	if len(got.AlertTrend) != len(data.AlertTrend) {
		t.Errorf("alert_trend len: want %d got %d", len(data.AlertTrend), len(got.AlertTrend))
	}
	if len(got.TopRules) != 1 || got.TopRules[0].Count != 12 {
		t.Errorf("top_rules unexpected: %+v", got.TopRules)
	}
	if got.StatusFunnel["OPEN"] != 10 {
		t.Errorf("status_funnel OPEN: want 10 got %d", got.StatusFunnel["OPEN"])
	}
}

func TestHandleSOCMetrics_StoreError(t *testing.T) {
	w := doSOCRequest(buildSOCRouter(&mockSOCQuerier{err: errors.New("db connection failed")}))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error field in response body")
	}
}

func TestHandleSOCMetrics_EmptyData(t *testing.T) {
	empty := &models.SOCMetrics{
		AlertTrend:      []models.AlertTrendDay{},
		TopRules:        []models.RuleFireCount{},
		AnalystWorkload: []models.AnalystLoad{},
		StatusFunnel:    map[string]int64{},
	}

	w := doSOCRequest(buildSOCRouter(&mockSOCQuerier{metrics: empty}))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on empty data, got %d", w.Code)
	}

	var got models.SOCMetrics
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	// Empty slices must decode as slices, not null
	if got.AlertTrend == nil {
		t.Error("alert_trend should decode as empty slice, not null")
	}
	if got.TopRules == nil {
		t.Error("top_rules should decode as empty slice, not null")
	}
}

func TestHandleSOCMetrics_ContentType(t *testing.T) {
	w := doSOCRequest(buildSOCRouter(&mockSOCQuerier{metrics: &models.SOCMetrics{
		AlertTrend: []models.AlertTrendDay{}, TopRules: []models.RuleFireCount{},
		AnalystWorkload: []models.AnalystLoad{}, StatusFunnel: map[string]int64{},
	}}))

	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Error("Content-Type header missing")
	}
}

/* ── Rule Effectiveness Handler Tests ───────────────────────────── */

type mockRuleQuerier struct {
	rows []models.RuleEffectivenessRow
	err  error
}

func (m *mockRuleQuerier) GetRuleEffectiveness(_ context.Context) ([]models.RuleEffectivenessRow, error) {
	return m.rows, m.err
}

func buildRulesRouter(q ruleEffectivenessQuerier) *gin.Engine {
	r := gin.New()
	r.GET("/api/v1/metrics/rules", func(c *gin.Context) {
		handleRuleEffectivenessFrom(c, q)
	})
	return r
}

func doRulesRequest(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/rules", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestHandleRuleEffectiveness_Success(t *testing.T) {
	rows := []models.RuleEffectivenessRow{
		{RuleID: "rule-ps-exec", RuleName: "Suspicious PowerShell", Severity: 3, Enabled: true,
			TotalFires: 20, Fires7d: 5, ClosedCount: 16, FPCount: 1,
			AvgMTTRHours: 2.1, CloseRate: 80, FPRate: 6.25, Label: "effective"},
		{RuleID: "rule-noisy", RuleName: "Noisy Rule", Severity: 1, Enabled: true,
			TotalFires: 100, Fires7d: 30, ClosedCount: 15, FPCount: 10,
			AvgMTTRHours: 0, CloseRate: 15, FPRate: 66, Label: "noisy"},
		{RuleID: "rule-silent", RuleName: "Silent Rule", Severity: 2, Enabled: true,
			TotalFires: 0, Fires7d: 0, Label: "silent"},
	}

	w := doRulesRequest(buildRulesRouter(&mockRuleQuerier{rows: rows}))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Rules []models.RuleEffectivenessRow `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(body.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(body.Rules))
	}
	if body.Rules[0].Label != "effective" {
		t.Errorf("first rule label: want effective, got %s", body.Rules[0].Label)
	}
	if body.Rules[1].Label != "noisy" {
		t.Errorf("second rule label: want noisy, got %s", body.Rules[1].Label)
	}
	if body.Rules[2].TotalFires != 0 {
		t.Errorf("silent rule should have 0 fires")
	}
}

func TestHandleRuleEffectiveness_StoreError(t *testing.T) {
	w := doRulesRequest(buildRulesRouter(&mockRuleQuerier{err: errors.New("query failed")}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error in response")
	}
}

func TestHandleRuleEffectiveness_NilSlice(t *testing.T) {
	// nil from store should become empty array, not null
	w := doRulesRequest(buildRulesRouter(&mockRuleQuerier{rows: nil}))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body struct {
		Rules []models.RuleEffectivenessRow `json:"rules"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body.Rules == nil {
		t.Error("rules field should not be null when store returns nil")
	}
}
