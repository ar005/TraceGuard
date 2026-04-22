// internal/api/ai.go — AI-powered SOC assistant endpoints.

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

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
	events, _ := s.store.GetAlertEvents(ctx, alert.ID) // non-fatal

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
		"alert_id":    alert.ID,
		"triage":      result,
		"model":       s.llm.ModelName(),
		"provider":    s.llm.ProviderName(),
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

	result, err := s.llm.GenerateHuntQuery(c.Request.Context(), body.Description)
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

// handleSummariseCase generates an AI narrative for a case.
func (s *Server) handleSummariseCase(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AI not enabled — configure a provider in Settings"})
		return
	}
	ctx := c.Request.Context()
	cs, err := s.store.GetCase(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	alerts, _ := s.store.ListCaseAlerts(ctx, cs.ID)
	notes, _ := s.store.ListCaseNotes(ctx, cs.ID)

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
