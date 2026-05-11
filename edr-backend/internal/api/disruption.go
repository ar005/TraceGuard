// internal/api/disruption.go — REST handlers for autonomous disruption policies and containments.

package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"github.com/youredr/edr-backend/internal/models"
)

// GET /api/v1/disruption/policies
func (s *Server) handleListDisruptionPolicies(c *gin.Context) {
	tid := c.GetString("tenant_id")
	policies, err := s.store.ListDisruptionPolicies(c.Request.Context(), tid)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// POST /api/v1/disruption/policies
func (s *Server) handleCreateDisruptionPolicy(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name             string   `json:"name"`
		Description      string   `json:"description"`
		Enabled          bool     `json:"enabled"`
		MinSeverity      int16    `json:"min_severity"`
		RuleIDs          []string `json:"rule_ids"`
		HostGroups       []string `json:"host_groups"`
		Action           string   `json:"action"`
		AutoReleaseHours int      `json:"auto_release_hours"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.MinSeverity < 1 || body.MinSeverity > 4 {
		body.MinSeverity = 4
	}
	if body.Action == "" {
		body.Action = "isolate"
	}
	p := &models.DisruptionPolicy{
		TenantID:         tid,
		Name:             body.Name,
		Description:      body.Description,
		Enabled:          body.Enabled,
		MinSeverity:      body.MinSeverity,
		RuleIDs:          pq.StringArray(body.RuleIDs),
		HostGroups:       pq.StringArray(body.HostGroups),
		Action:           body.Action,
		AutoReleaseHours: body.AutoReleaseHours,
	}
	if err := s.store.CreateDisruptionPolicy(c.Request.Context(), p); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusCreated, p)
}

// PUT /api/v1/disruption/policies/:id
func (s *Server) handleUpdateDisruptionPolicy(c *gin.Context) {
	tid := c.GetString("tenant_id")
	id := c.Param("id")
	var body struct {
		Name             string   `json:"name"`
		Description      string   `json:"description"`
		Enabled          bool     `json:"enabled"`
		MinSeverity      int16    `json:"min_severity"`
		RuleIDs          []string `json:"rule_ids"`
		HostGroups       []string `json:"host_groups"`
		Action           string   `json:"action"`
		AutoReleaseHours int      `json:"auto_release_hours"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.MinSeverity < 1 || body.MinSeverity > 4 {
		body.MinSeverity = 4
	}
	if body.Action == "" {
		body.Action = "isolate"
	}
	p := &models.DisruptionPolicy{
		ID:               id,
		TenantID:         tid,
		Name:             body.Name,
		Description:      body.Description,
		Enabled:          body.Enabled,
		MinSeverity:      body.MinSeverity,
		RuleIDs:          pq.StringArray(body.RuleIDs),
		HostGroups:       pq.StringArray(body.HostGroups),
		Action:           body.Action,
		AutoReleaseHours: body.AutoReleaseHours,
	}
	if err := s.store.UpdateDisruptionPolicy(c.Request.Context(), p); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// DELETE /api/v1/disruption/policies/:id
func (s *Server) handleDeleteDisruptionPolicy(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteDisruptionPolicy(c.Request.Context(), c.Param("id"), tid); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GET /api/v1/disruption/containments?status=active&limit=50&offset=0
func (s *Server) handleListContainments(c *gin.Context) {
	tid := c.GetString("tenant_id")
	status := c.DefaultQuery("status", "")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	cs, err := s.store.ListContainments(c.Request.Context(), tid, status, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"containments": cs})
}

// POST /api/v1/disruption/containments/:id/release
func (s *Server) handleReleaseContainment(c *gin.Context) {
	tid := c.GetString("tenant_id")
	id := c.Param("id")

	var body struct {
		Note string `json:"note"`
	}
	_ = c.ShouldBindJSON(&body)

	// Fetch containment to get agent_id for live-response release.
	con, err := s.store.GetContainment(c.Request.Context(), id, tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "containment not found"})
		return
	}
	if con.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "containment is not active"})
		return
	}

	// Fire live-response release (best-effort — mark released regardless).
	if s.lr != nil {
		rctx := c.Request.Context()
		_, lrErr := s.lr.SendCommand(rctx, con.AgentID, "release", nil, 30)
		if lrErr != nil {
			s.log.Warn().Err(lrErr).Str("agent", con.AgentID).Msg("manual release LR command failed")
		}
	}

	analyst := c.GetString("username")
	if analyst == "" {
		analyst = "analyst"
	}
	note := body.Note
	if note == "" {
		note = "manually released by analyst"
	}

	if err := s.store.ReleaseContainment(c.Request.Context(), id, tid, analyst, note); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
