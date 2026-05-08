package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/mispfeed"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/stix"
)

// GET /api/v1/intel/sharing-groups
func (s *Server) handleListSharingGroups(c *gin.Context) {
	tid := c.GetString("tenant_id")
	groups, err := s.store.ListSharingGroups(c.Request.Context(), tid)
	if err != nil {
		s.log.Error().Err(err).Msg("list sharing groups")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"groups": groups, "total": len(groups)})
}

// POST /api/v1/intel/sharing-groups
func (s *Server) handleCreateSharingGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name        string          `json:"name" binding:"required"`
		Description string          `json:"description"`
		PushTargets json.RawMessage `json:"push_targets"`
		TLPFloor    string          `json:"tlp_floor"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validTLP(body.TLPFloor) {
		body.TLPFloor = "AMBER"
	}
	if len(body.PushTargets) == 0 {
		body.PushTargets = json.RawMessage("[]")
	}
	g := &models.SharingGroup{
		TenantID:    tid,
		Name:        body.Name,
		Description: body.Description,
		PushTargets: body.PushTargets,
		TLPFloor:    body.TLPFloor,
	}
	if err := s.store.CreateSharingGroup(c.Request.Context(), g); err != nil {
		s.log.Error().Err(err).Msg("create sharing group")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusCreated, g)
}

// PUT /api/v1/intel/sharing-groups/:id
func (s *Server) handleUpdateSharingGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	id := c.Param("id")
	g, err := s.store.GetSharingGroup(c.Request.Context(), id, tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var body struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		PushTargets json.RawMessage `json:"push_targets"`
		TLPFloor    string          `json:"tlp_floor"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name != "" {
		g.Name = body.Name
	}
	g.Description = body.Description
	if len(body.PushTargets) > 0 {
		g.PushTargets = body.PushTargets
	}
	if validTLP(body.TLPFloor) {
		g.TLPFloor = body.TLPFloor
	}
	if err := s.store.UpdateSharingGroup(c.Request.Context(), g); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, g)
}

// DELETE /api/v1/intel/sharing-groups/:id
func (s *Server) handleDeleteSharingGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteSharingGroup(c.Request.Context(), c.Param("id"), tid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}

// POST /api/v1/intel/sharing-groups/:id/push
func (s *Server) handlePushSharingGroup(c *gin.Context) {
	tid := c.GetString("tenant_id")
	g, err := s.store.GetSharingGroup(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	run := &models.SharingRun{GroupID: g.ID}
	if err := s.store.CreateSharingRun(c.Request.Context(), run); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Parse push targets.
	var targets []models.PushTarget
	_ = json.Unmarshal(g.PushTargets, &targets)

	// Fetch eligible IOCs (last 30 days, at or below TLP floor).
	iocs, err := s.store.GetIOCsForExport(c.Request.Context(), tid, g.TLPFloor, 30)
	if err != nil {
		s.store.FinishSharingRun(c.Request.Context(), run.ID, 0, err.Error()) //nolint:errcheck
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch IOCs"})
		return
	}

	totalPushed := 0
	var pushErr string
	for _, target := range targets {
		if target.Type != "misp" || target.URL == "" {
			continue
		}
		pusher := mispfeed.NewPusher(target.URL, target.Key)
		n, err := pusher.PushIOCs(c.Request.Context(), iocs)
		totalPushed += n
		if err != nil {
			pushErr = fmt.Sprintf("misp %s: %v", target.URL, err)
			break
		}
	}

	s.store.FinishSharingRun(c.Request.Context(), run.ID, totalPushed, pushErr) //nolint:errcheck
	if pushErr != "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": pushErr, "exported": totalPushed})
		return
	}
	c.JSON(http.StatusOK, gin.H{"exported": totalPushed, "run_id": run.ID})
}

// GET /api/v1/intel/sharing-groups/:id/runs
func (s *Server) handleListSharingRuns(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if _, err := s.store.GetSharingGroup(c.Request.Context(), c.Param("id"), tid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	runs, err := s.store.ListSharingRuns(c.Request.Context(), c.Param("id"), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs, "total": len(runs)})
}

// GET /api/v1/intel/export/stix
func (s *Server) handleExportSTIX(c *gin.Context) {
	tid := c.GetString("tenant_id")
	tlp := c.DefaultQuery("tlp", "AMBER")
	if !validTLP(tlp) {
		tlp = "AMBER"
	}
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days <= 0 || days > 365 {
		days = 30
	}

	iocs, err := s.store.GetIOCsForExport(c.Request.Context(), tid, tlp, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	bundle, err := stix.ExportBundle(iocs, tlp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build STIX bundle"})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=\"traceguard-intel.stix.json\"")
	c.Data(http.StatusOK, "application/json", bundle)
}

func validTLP(s string) bool {
	return s == "WHITE" || s == "GREEN" || s == "AMBER" || s == "RED"
}
