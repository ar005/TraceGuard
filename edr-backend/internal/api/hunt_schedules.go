package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/huntscheduler"
	"github.com/youredr/edr-backend/internal/models"
)

// GET /api/v1/intel/hunt-schedules
func (s *Server) handleListHuntSchedules(c *gin.Context) {
	tid := c.GetString("tenant_id")
	rows, err := s.store.ListHuntSchedules(c.Request.Context(), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, rows)
}

// GET /api/v1/intel/hunt-schedules/:id
func (s *Server) handleGetHuntSchedule(c *gin.Context) {
	tid := c.GetString("tenant_id")
	hs, err := s.store.GetHuntSchedule(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, hs)
}

// GET /api/v1/intel/hunt-schedules/:id/runs
func (s *Server) handleListHuntScheduleRuns(c *gin.Context) {
	tid := c.GetString("tenant_id")
	runs, err := s.store.ListHuntScheduleRuns(c.Request.Context(), c.Param("id"), tid, 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, runs)
}

// POST /api/v1/intel/hunt-schedules
func (s *Server) handleCreateHuntSchedule(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		SavedHuntID string `json:"saved_hunt_id" binding:"required"`
		Name        string `json:"name"          binding:"required"`
		CronExpr    string `json:"cron_expr"     binding:"required"`
		Enabled     *bool  `json:"enabled"`
		AlertOnHit  *bool  `json:"alert_on_hit"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := s.store.GetSavedHunt(c.Request.Context(), body.SavedHuntID, tid); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "saved hunt not found"})
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	alertOnHit := true
	if body.AlertOnHit != nil {
		alertOnHit = *body.AlertOnHit
	}
	next := huntscheduler.NextCronTime(body.CronExpr, time.Now())
	hs := &models.HuntSchedule{
		TenantID:    tid,
		SavedHuntID: body.SavedHuntID,
		Name:        body.Name,
		CronExpr:    body.CronExpr,
		Enabled:     enabled,
		AlertOnHit:  alertOnHit,
		NextRunAt:   &next,
	}
	if err := s.store.CreateHuntSchedule(c.Request.Context(), hs); err != nil {
		s.log.Error().Err(err).Msg("create hunt schedule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusCreated, hs)
}

// PUT /api/v1/intel/hunt-schedules/:id
func (s *Server) handleUpdateHuntSchedule(c *gin.Context) {
	tid := c.GetString("tenant_id")
	hs, err := s.store.GetHuntSchedule(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var body struct {
		Name       string `json:"name"`
		CronExpr   string `json:"cron_expr"`
		Enabled    *bool  `json:"enabled"`
		AlertOnHit *bool  `json:"alert_on_hit"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name != "" {
		hs.Name = body.Name
	}
	if body.CronExpr != "" {
		hs.CronExpr = body.CronExpr
		next := huntscheduler.NextCronTime(hs.CronExpr, time.Now())
		hs.NextRunAt = &next
	}
	if body.Enabled != nil {
		hs.Enabled = *body.Enabled
	}
	if body.AlertOnHit != nil {
		hs.AlertOnHit = *body.AlertOnHit
	}
	if err := s.store.UpdateHuntSchedule(c.Request.Context(), hs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, hs)
}

// DELETE /api/v1/intel/hunt-schedules/:id
func (s *Server) handleDeleteHuntSchedule(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteHuntSchedule(c.Request.Context(), c.Param("id"), tid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}
