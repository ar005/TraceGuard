// internal/api/playbooks.go — SOAR playbook + export destination REST handlers.

package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/users"
)

// ── Playbooks ─────────────────────────────────────────────────────────────────

func (s *Server) handleListPlaybooks(c *gin.Context) {
	tid := c.GetString("tenant_id")
	rows, err := s.store.ListPlaybooks(c.Request.Context(), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"playbooks": rows})
}

func (s *Server) handleGetPlaybook(c *gin.Context) {
	pb, err := s.store.GetPlaybook(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found"})
		return
	}
	c.JSON(http.StatusOK, pb)
}

func (s *Server) handleCreatePlaybook(c *gin.Context) {
	var pb models.Playbook
	if err := c.ShouldBindJSON(&pb); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if pb.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if pb.TriggerType == "" {
		pb.TriggerType = "alert"
	}
	if len(pb.TriggerFilter) == 0 {
		pb.TriggerFilter = []byte("{}")
	}
	if len(pb.Actions) == 0 {
		pb.Actions = []byte("[]")
	}
	pb.TenantID = c.GetString("tenant_id")
	if raw, ok := c.Get(string(ctxClaims)); ok {
		if claims, ok := raw.(*users.Claims); ok {
			pb.CreatedBy = claims.Subject
		}
	}
	if err := s.store.CreatePlaybook(c.Request.Context(), &pb); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusCreated, pb)
}

func (s *Server) handleUpdatePlaybook(c *gin.Context) {
	pb, err := s.store.GetPlaybook(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found"})
		return
	}
	if err := c.ShouldBindJSON(pb); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pb.ID = c.Param("id")
	pb.TenantID = c.GetString("tenant_id")
	if err := s.store.UpdatePlaybook(c.Request.Context(), pb); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, pb)
}

func (s *Server) handleDeletePlaybook(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeletePlaybook(c.Request.Context(), c.Param("id"), tid); err != nil {
		s.jsonError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) handleListPlaybookRuns(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	runs, err := s.store.ListPlaybookRuns(c.Request.Context(), c.Param("id"), limit)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs})
}

func (s *Server) handleListAllPlaybookRuns(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	runs, err := s.store.ListPlaybookRuns(c.Request.Context(), "", limit)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs})
}

// handleTestPlaybook manually fires a playbook with a dummy alert context.
func (s *Server) handleTestPlaybook(c *gin.Context) {
	if s.playbookRunner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "playbook runner not configured"})
		return
	}
	pb, err := s.store.GetPlaybook(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found"})
		return
	}
	dummyAlert := &models.Alert{
		ID:       "test-" + uuid.New().String(),
		Title:    "Test execution from API",
		RuleName: "manual-test",
		Hostname: "test-host",
		Severity: 2,
		Status:   "OPEN",
		TenantID: c.GetString("tenant_id"),
	}
	go s.playbookRunner.OnAlert(c.Request.Context(), dummyAlert)
	c.JSON(http.StatusAccepted, gin.H{"message": "playbook test triggered", "playbook": pb.Name})
}

// ── Agent Groups ──────────────────────────────────────────────────────────────

func (s *Server) handleListAgentGroups(c *gin.Context) {
	tid := c.GetString("tenant_id")
	groups, err := s.store.ListAgentGroups(c.Request.Context(), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

func (s *Server) handleGetAgentGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	g, err := s.store.GetAgentGroup(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.JSON(http.StatusOK, g)
}

func (s *Server) handleCreateAgentGroup(c *gin.Context) {
	var g models.AgentGroup
	if err := c.ShouldBindJSON(&g); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if g.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	g.TenantID = c.GetString("tenant_id")
	created, err := s.store.CreateAgentGroup(c.Request.Context(), &g)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (s *Server) handleUpdateAgentGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	existing, err := s.store.GetAgentGroup(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	if err := c.ShouldBindJSON(existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing.ID = c.Param("id")
	existing.TenantID = tid
	if err := s.store.UpdateAgentGroup(c.Request.Context(), existing); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, existing)
}

func (s *Server) handleDeleteAgentGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteAgentGroup(c.Request.Context(), c.Param("id"), tid); err != nil {
		s.jsonError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) handleListAgentGroupMembers(c *gin.Context) {
	tid := c.GetString("tenant_id")
	agents, err := s.store.ListAgentGroupMembers(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

// ── Response Actions ──────────────────────────────────────────────────────────

func (s *Server) handleListResponseActions(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	actions, err := s.store.ListResponseActions(c.Request.Context(), limit)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"actions": actions})
}

// ── Export Destinations ───────────────────────────────────────────────────────

func (s *Server) handleListExportDests(c *gin.Context) {
	rows, err := s.store.ListExportDestinations(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"destinations": rows})
}

func (s *Server) handleUpsertExportDest(c *gin.Context) {
	var d models.ExportDestination
	if err := c.ShouldBindJSON(&d); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if id := c.Param("id"); id != "" {
		d.ID = id
	}
	if d.Name == "" || d.DestType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and dest_type required"})
		return
	}
	if len(d.Config) == 0 {
		d.Config = []byte("{}")
	}
	if err := s.store.UpsertExportDestination(c.Request.Context(), &d); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, d)
}

func (s *Server) handleDeleteExportDest(c *gin.Context) {
	if err := s.store.DeleteExportDestination(c.Request.Context(), c.Param("id")); err != nil {
		s.jsonError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
