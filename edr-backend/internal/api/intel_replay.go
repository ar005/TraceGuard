package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/lib/pq"
)

// POST /api/v1/intel/replay
func (s *Server) handleCreateReplayJob(c *gin.Context) {
	tid := c.GetString("tenant_id")
	actorID, actorName := currentUser(c)

	var body struct {
		IOCIDs       []string `json:"ioc_ids"`
		LookbackDays int16    `json:"lookback_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.LookbackDays <= 0 {
		body.LookbackDays = 30
	}
	if body.LookbackDays > 90 {
		body.LookbackDays = 90
	}

	job := &models.ReplayJob{
		TenantID:     tid,
		TriggeredBy:  actorName,
		IOCIDs:       pq.StringArray(body.IOCIDs),
		LookbackDays: body.LookbackDays,
	}
	if err := s.store.CreateReplayJob(c.Request.Context(), job); err != nil {
		s.log.Error().Err(err).Msg("create replay job")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	s.al.Log(c.Request.Context(), actorID, actorName, "replay_job_create", "intel_replay", job.ID, "",
		c.ClientIP(), "")
	c.JSON(http.StatusCreated, job)
}

// GET /api/v1/intel/replay
func (s *Server) handleListReplayJobs(c *gin.Context) {
	tid := c.GetString("tenant_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	jobs, err := s.store.ListReplayJobs(c.Request.Context(), tid, limit)
	if err != nil {
		s.log.Error().Err(err).Msg("list replay jobs")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs, "total": len(jobs)})
}

// GET /api/v1/intel/replay/:id
func (s *Server) handleGetReplayJob(c *gin.Context) {
	tid := c.GetString("tenant_id")
	job, err := s.store.GetReplayJob(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, job)
}
