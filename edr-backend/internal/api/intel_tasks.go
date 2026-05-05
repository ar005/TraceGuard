package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/models"
)

// GET /api/v1/intel/tasks
func (s *Server) handleListIntelTasks(c *gin.Context) {
	tid := c.GetString("tenant_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	tasks, err := s.store.ListIntelTasks(c.Request.Context(), tid, limit)
	if err != nil {
		s.log.Error().Err(err).Msg("list intel tasks")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks, "total": len(tasks)})
}

// GET /api/v1/intel/tasks/:id
func (s *Server) handleGetIntelTask(c *gin.Context) {
	tid := c.GetString("tenant_id")
	task, err := s.store.GetIntelTask(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, task)
}

// POST /api/v1/intel/tasks (manual enqueue, admin only)
func (s *Server) handleCreateIntelTask(c *gin.Context) {
	tid := c.GetString("tenant_id")
	_, actorName := currentUser(c)
	var body struct {
		Name       string `json:"name" binding:"required"`
		TaskType   string `json:"task_type" binding:"required"`
		SourceType string `json:"source_type"`
		SourceID   string `json:"source_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task := &models.IntelTask{
		TenantID:   tid,
		Name:       body.Name,
		TaskType:   body.TaskType,
		SourceType: body.SourceType,
		SourceID:   body.SourceID,
		CreatedBy:  actorName,
	}
	if err := s.store.CreateIntelTask(c.Request.Context(), task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusCreated, task)
}

// GET /api/v1/intel/saved-hunts
func (s *Server) handleListSavedHunts(c *gin.Context) {
	tid := c.GetString("tenant_id")
	hunts, err := s.store.ListSavedHunts(c.Request.Context(), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"hunts": hunts, "total": len(hunts)})
}

// GET /api/v1/intel/saved-hunts/:id
func (s *Server) handleGetSavedHunt(c *gin.Context) {
	tid := c.GetString("tenant_id")
	hunt, err := s.store.GetSavedHunt(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, hunt)
}

// DELETE /api/v1/intel/saved-hunts/:id (admin only)
func (s *Server) handleDeleteSavedHunt(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteSavedHunt(c.Request.Context(), c.Param("id"), tid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}
