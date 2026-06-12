// internal/api/sla.go — SLA policy management and breach log endpoints.

package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/youredr/edr-backend/internal/models"
)

// slaStore is the narrow interface needed by the SLA handlers.
type slaStore interface {
	ListSLAPolicies(ctx context.Context, tenantID string) ([]models.SLAPolicy, error)
	CreateSLAPolicy(ctx context.Context, p *models.SLAPolicy) error
	UpdateSLAPolicy(ctx context.Context, p *models.SLAPolicy) error
	DeleteSLAPolicy(ctx context.Context, id, tenantID string) error
	ListSLABreaches(ctx context.Context, tenantID string, limit int) ([]models.SLABreach, error)
}

// GET /api/v1/sla/policies
func (s *Server) handleListSLAPolicies(c *gin.Context) {
	tid := getTenantID(c)
	policies, err := s.store.ListSLAPolicies(c.Request.Context(), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if policies == nil {
		policies = []models.SLAPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// POST /api/v1/sla/policies
func (s *Server) handleCreateSLAPolicy(c *gin.Context) {
	tid := getTenantID(c)
	var req struct {
		Name               string   `json:"name"`
		Severity           *int16   `json:"severity"`
		TargetMTTDMinutes  *int     `json:"target_mttd_minutes"`
		TargetMTTAMinutes  *int     `json:"target_mtta_minutes"`
		TargetMTTRHours    *float64 `json:"target_mttr_hours"`
		Enabled            *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	p := &models.SLAPolicy{
		ID:                uuid.New().String(),
		TenantID:          tid,
		Name:              req.Name,
		Severity:          req.Severity,
		TargetMTTDMinutes: req.TargetMTTDMinutes,
		TargetMTTAMinutes: req.TargetMTTAMinutes,
		TargetMTTRHours:   req.TargetMTTRHours,
		Enabled:           enabled,
	}
	if err := s.store.CreateSLAPolicy(c.Request.Context(), p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, p)
}

// PUT /api/v1/sla/policies/:id
func (s *Server) handleUpdateSLAPolicy(c *gin.Context) {
	tid := getTenantID(c)
	id := c.Param("id")
	var req struct {
		Name               string   `json:"name"`
		Severity           *int16   `json:"severity"`
		TargetMTTDMinutes  *int     `json:"target_mttd_minutes"`
		TargetMTTAMinutes  *int     `json:"target_mtta_minutes"`
		TargetMTTRHours    *float64 `json:"target_mttr_hours"`
		Enabled            bool     `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	p := &models.SLAPolicy{
		ID:                id,
		TenantID:          tid,
		Name:              req.Name,
		Severity:          req.Severity,
		TargetMTTDMinutes: req.TargetMTTDMinutes,
		TargetMTTAMinutes: req.TargetMTTAMinutes,
		TargetMTTRHours:   req.TargetMTTRHours,
		Enabled:           req.Enabled,
	}
	if err := s.store.UpdateSLAPolicy(c.Request.Context(), p); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// DELETE /api/v1/sla/policies/:id
func (s *Server) handleDeleteSLAPolicy(c *gin.Context) {
	tid := getTenantID(c)
	id := c.Param("id")
	if err := s.store.DeleteSLAPolicy(c.Request.Context(), id, tid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

// GET /api/v1/sla/breaches?limit=50
func (s *Server) handleListSLABreaches(c *gin.Context) {
	tid := getTenantID(c)
	limit := 50
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	breaches, err := s.store.ListSLABreaches(c.Request.Context(), tid, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if breaches == nil {
		breaches = []models.SLABreach{}
	}
	c.JSON(http.StatusOK, gin.H{"breaches": breaches})
}
