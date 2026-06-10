// internal/api/ai.go — AI-powered SOC assistant endpoints.

package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/llm"
	"github.com/youredr/edr-backend/internal/models"
)

// ── Narrow interfaces for testability ────────────────────────────────────────

// alertSummariseStore is the subset of store.Store used by summariseAlertFrom.
type alertSummariseStore interface {
	GetAlert(ctx context.Context, id, tenantID string) (*models.Alert, error)
	GetAlertEvents(ctx context.Context, alertID, tenantID string) ([]models.Event, error)
	UpdateAlertAISummary(ctx context.Context, id, tenantID, summary string) error
}

// incidentSummariseStore is the subset of store.Store used by summariseIncidentFrom.
type incidentSummariseStore interface {
	GetIncident(ctx context.Context, id, tenantID string) (*models.Incident, error)
	GetIncidentAlerts(ctx context.Context, incidentID string) ([]models.Alert, error)
	UpdateIncidentAISummary(ctx context.Context, id, tenantID, summary string) error
}

// summariseLLM is the LLM capability surface used by both summarise handlers.
type summariseLLM interface {
	Enabled() bool
	ModelName() string
	ProviderName() string
	ExplainAlert(ctx context.Context, alert *models.Alert, events []models.Event) (string, error)
	SummariseIncident(ctx context.Context, inc *models.Incident, alerts []models.Alert) (string, error)
}

// ── Standalone logic functions (delegates from method handlers) ───────────────

// summariseAlertFrom is the pure handler logic for alert summarisation,
// decoupled from *Server so it can be unit-tested with mocks.
func summariseAlertFrom(c *gin.Context, st alertSummariseStore, lm summariseLLM, log zerolog.Logger) {
	if lm == nil || !lm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	ctx := c.Request.Context()
	tid := c.GetString("tenant_id")
	alert, err := st.GetAlert(ctx, c.Param("id"), tid)
	if err != nil {
		log.Error().Err(err).Str("path", c.Request.URL.Path).Msg("api error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Return cached summary unless caller forces regeneration.
	if alert.AISummary != "" && c.Query("force") != "1" {
		c.JSON(http.StatusOK, gin.H{
			"alert_id": alert.ID,
			"summary":  alert.AISummary,
			"cached":   true,
			"model":    lm.ModelName(),
			"provider": lm.ProviderName(),
		})
		return
	}

	events, _ := st.GetAlertEvents(ctx, alert.ID, tid)
	summary, err := lm.ExplainAlert(ctx, alert, events)
	if err != nil {
		log.Warn().Err(err).Str("alert", alert.ID).Msg("LLM summarise alert failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}

	if err := st.UpdateAlertAISummary(ctx, alert.ID, tid, summary); err != nil {
		log.Warn().Err(err).Str("alert", alert.ID).Msg("persist AI summary failed")
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_id": alert.ID,
		"summary":  summary,
		"cached":   false,
		"model":    lm.ModelName(),
		"provider": lm.ProviderName(),
	})
}

// summariseIncidentFrom is the pure handler logic for incident summarisation.
func summariseIncidentFrom(c *gin.Context, st incidentSummariseStore, lm summariseLLM, log zerolog.Logger) {
	if lm == nil || !lm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	ctx := c.Request.Context()
	tid := c.GetString("tenant_id")
	inc, err := st.GetIncident(ctx, c.Param("id"), tid)
	if err != nil {
		log.Error().Err(err).Str("path", c.Request.URL.Path).Msg("api error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if inc.AISummary != "" && c.Query("force") != "1" {
		c.JSON(http.StatusOK, gin.H{
			"incident_id": inc.ID,
			"summary":     inc.AISummary,
			"cached":      true,
			"model":       lm.ModelName(),
			"provider":    lm.ProviderName(),
		})
		return
	}

	alerts, _ := st.GetIncidentAlerts(ctx, inc.ID)
	summary, err := lm.SummariseIncident(ctx, inc, alerts)
	if err != nil {
		log.Warn().Err(err).Str("incident", inc.ID).Msg("LLM summarise incident failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}

	if err := st.UpdateIncidentAISummary(ctx, inc.ID, tid, summary); err != nil {
		log.Warn().Err(err).Str("incident", inc.ID).Msg("persist AI summary failed")
	}

	c.JSON(http.StatusOK, gin.H{
		"incident_id": inc.ID,
		"summary":     summary,
		"cached":      false,
		"model":       lm.ModelName(),
		"provider":    lm.ProviderName(),
	})
}

// ── Server method handlers (delegate to standalone functions) ─────────────────

// handleSummariseAlert generates and caches a plain-language AI summary for an alert.
// Accepts an optional ?force=1 query param to regenerate even if a cached summary exists.
func (s *Server) handleSummariseAlert(c *gin.Context) {
	var lm summariseLLM
	if s.llm != nil {
		lm = s.llm
	}
	summariseAlertFrom(c, s.store, lm, s.log)
}

// handleSummariseIncident generates and caches a plain-language AI summary for an incident.
func (s *Server) handleSummariseIncident(c *gin.Context) {
	var lm summariseLLM
	if s.llm != nil {
		lm = s.llm
	}
	summariseIncidentFrom(c, s.store, lm, s.log)
}

// handleTriageAlert runs AI triage on a specific alert and persists the result.
func (s *Server) handleTriageAlert(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	ctx := c.Request.Context()
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	alert, err := s.store.GetAlert(ctx, c.Param("id"), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	events, _ := s.store.GetAlertEvents(ctx, alert.ID, tid) // non-fatal

	result, err := s.llm.TriageAlert(ctx, alert, events)
	if err != nil {
		s.log.Warn().Err(err).Str("alert", alert.ID).Msg("LLM triage failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM triage failed: " + err.Error()})
		return
	}

	if err := s.store.UpdateAlertTriage(ctx, alert.ID, tid, result.Verdict, int16(result.Confidence), result.Reasoning); err != nil {
		s.log.Warn().Err(err).Str("alert", alert.ID).Msg("persist triage failed")
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_id": alert.ID,
		"triage":   result,
		"model":    s.llm.ModelName(),
		"provider": s.llm.ProviderName(),
	})
}

// handleGenerateHuntQuery converts natural language to a hunt query.
func (s *Server) handleGenerateHuntQuery(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	var body struct {
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "description required"})
		return
	}
	const maxDescBytes = 2 * 1024
	if len(body.Description) > maxDescBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "description exceeds 2 KB limit"})
		return
	}
	// Strip control characters to limit prompt-injection surface.
	var sb strings.Builder
	for _, r := range body.Description {
		if r >= 0x20 || r == '\t' {
			sb.WriteRune(r)
		}
	}
	description := sb.String()

	result, err := s.llm.GenerateHuntQuery(c.Request.Context(), description)
	if err != nil {
		s.log.Warn().Err(err).Msg("LLM hunt generate failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"query":       result.Query,
		"explanation": result.Explanation,
		"model":       s.llm.ModelName(),
		"provider":    s.llm.ProviderName(),
	})
}

// handleAlertChat runs a multi-turn AI chat session grounded in alert context.
func (s *Server) handleAlertChat(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	var body struct {
		Messages []llm.ChatMessage `json:"messages"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Messages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "messages required"})
		return
	}
	const maxMessages = 50
	const maxMsgBytes = 8 * 1024
	if len(body.Messages) > maxMessages {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many messages (max 50)"})
		return
	}
	for _, m := range body.Messages {
		if len(m.Content) > maxMsgBytes {
			c.JSON(http.StatusBadRequest, gin.H{"error": "message content exceeds 8 KB limit"})
			return
		}
	}
	ctx := c.Request.Context()
	tid := c.GetString("tenant_id")
	alert, err := s.store.GetAlert(ctx, c.Param("id"), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	events, _ := s.store.GetAlertEvents(ctx, alert.ID, tid)
	system := llm.AlertChatSystem(alert, events)
	reply, err := s.llm.Chat(ctx, system, body.Messages)
	if err != nil {
		s.log.Warn().Err(err).Str("alert", alert.ID).Msg("LLM chat failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"reply":    reply,
		"model":    s.llm.ModelName(),
		"provider": s.llm.ProviderName(),
	})
}

// handleIncidentChat runs a multi-turn AI chat session grounded in incident context.
func (s *Server) handleIncidentChat(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	var body struct {
		Messages []llm.ChatMessage `json:"messages"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Messages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "messages required"})
		return
	}
	ctx := c.Request.Context()
	tid := c.GetString("tenant_id")
	inc, err := s.store.GetIncident(ctx, c.Param("id"), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	alerts, _ := s.store.GetIncidentAlerts(ctx, inc.ID)
	system := llm.IncidentChatSystem(inc, alerts)
	reply, err := s.llm.Chat(ctx, system, body.Messages)
	if err != nil {
		s.log.Warn().Err(err).Str("incident", inc.ID).Msg("LLM chat failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"reply":    reply,
		"model":    s.llm.ModelName(),
		"provider": s.llm.ProviderName(),
	})
}

// handleSummariseCase generates an AI narrative for a case.
func (s *Server) handleSummariseCase(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	ctx := c.Request.Context()
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	cs, err := s.store.GetCase(ctx, c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	alerts, _ := s.store.ListCaseAlerts(ctx, cs.ID, tid)
	notes, _ := s.store.ListCaseNotes(ctx, cs.ID, tid)

	narrative, err := s.llm.SummariseCase(ctx, cs, alerts, notes)
	if err != nil {
		s.log.Warn().Err(err).Str("case", cs.ID).Msg("LLM case summary failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"case_id":   cs.ID,
		"narrative": narrative,
		"model":     s.llm.ModelName(),
		"provider":  s.llm.ProviderName(),
	})
}
