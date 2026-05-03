// internal/api/dns_canary_dlp.go
// Handlers for Feature A (DNS Intelligence), Feature B (Canary Tokens),
// and Feature E (DLP / Exfil Signals).

package api

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/youredr/edr-backend/internal/models"
)

// ── Feature A: DNS Intelligence ───────────────────────────────────────────────

func (s *Server) handleDNSEvents(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	agentID := c.Query("agent_id")
	domain := c.Query("domain")
	limit := intQuery(c, "limit", 100)
	if limit > 500 {
		limit = 500
	}
	offset := intQuery(c, "offset", 0)

	evs, total, err := s.store.QueryDNSEvents(c.Request.Context(), tenantID, agentID, domain, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	if evs == nil {
		evs = []models.Event{}
	}
	c.JSON(http.StatusOK, gin.H{"events": evs, "total": total})
}

func (s *Server) handleDNSStats(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	hours := intQuery(c, "hours", 24)
	if hours > 168 {
		hours = 168
	}
	if hours <= 0 {
		hours = 24
	}

	stats, err := s.store.DNSTopDomains(c.Request.Context(), tenantID, hours, 50)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"top_domains": stats, "hours": hours})
}

// ── Feature B: Canary Tokens ──────────────────────────────────────────────────

func (s *Server) handleListCanaryTokens(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	tokens, err := s.store.ListCanaryTokens(c.Request.Context(), tenantID)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	if tokens == nil {
		tokens = []models.CanaryToken{}
	}
	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

var canaryTypeAllowlist = map[string]bool{
	"credential": true,
	"file":       true,
	"url":        true,
	"dns":        true,
}

func (s *Server) handleCreateCanaryToken(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	var req struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		DeployedTo  string `json:"deployed_to"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if !canaryTypeAllowlist[req.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be one of: credential, file, url, dns"})
		return
	}
	if len(req.Name) == 0 || len(req.Name) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name must be 1-100 characters"})
		return
	}
	if len(req.DeployedTo) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deployed_to must be <= 200 characters"})
		return
	}
	if len(req.Description) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "description must be <= 500 characters"})
		return
	}

	ct := &models.CanaryToken{
		ID:          "canary-" + uuid.New().String(),
		TenantID:    tenantID,
		Name:        req.Name,
		Type:        req.Type,
		Token:       uuid.New().String(),
		DeployedTo:  req.DeployedTo,
		Description: req.Description,
	}

	if err := s.store.CreateCanaryToken(c.Request.Context(), ct); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusCreated, ct)
}

func (s *Server) handleDeleteCanaryToken(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	id := c.Param("id")
	if err := s.store.DeleteCanaryToken(c.Request.Context(), id, tenantID); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleCanaryTrigger is registered WITHOUT JWT auth. It receives webhook
// callbacks from deployed canaries.
func (s *Server) handleCanaryTrigger(c *gin.Context) {
	// Consume body up to 64 KB and discard — the caller may send context.
	_, _ = io.LimitReader(c.Request.Body, 64*1024).Read(make([]byte, 64*1024))

	token := c.Param("token")

	ct, err := s.store.GetCanaryTokenByToken(c.Request.Context(), token)
	if err != nil || ct == nil {
		// Silently return 200 — don't reveal existence.
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}

	_ = s.store.RecordCanaryTrigger(c.Request.Context(), token)

	alert := &models.Alert{
		ID:          "alert-" + uuid.New().String(),
		TenantID:    ct.TenantID,
		Title:       "Canary Token Triggered: " + ct.Name,
		Description: "Canary token '" + ct.Name + "' (type: " + ct.Type + ") deployed to '" + ct.DeployedTo + "' was accessed. This indicates credential theft or unauthorized access.",
		Severity:    5,
		Status:      "OPEN",
		RuleID:      "rule-canary-trigger",
		RuleName:    "Canary Token Triggered",
		MitreIDs:    []string{"T1078", "T1555"},
		SourceTypes: []string{"deception"},
	}
	_ = s.store.InsertAlert(c.Request.Context(), alert)

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Feature E: DLP / Exfil Signals ───────────────────────────────────────────

func (s *Server) handleDLPEvents(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	agentID := c.Query("agent_id")
	limit := intQuery(c, "limit", 100)
	offset := intQuery(c, "offset", 0)

	sigs, total, err := s.store.QueryExfilSignals(c.Request.Context(), tenantID, agentID, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	if sigs == nil {
		sigs = []models.ExfilSignal{}
	}
	c.JSON(http.StatusOK, gin.H{"signals": sigs, "total": total})
}

func (s *Server) handleDLPStats(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	hours := intQuery(c, "hours", 24)
	if hours <= 0 {
		hours = 24
	}

	stats, err := s.store.ExfilAgentStats(c.Request.Context(), tenantID, hours)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": stats, "hours": hours})
}
