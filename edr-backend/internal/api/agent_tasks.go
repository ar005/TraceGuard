package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/youredr/edr-backend/internal/models"
)

// GET /api/v1/agents/:id/tasks
func (s *Server) handleListAgentTasks(c *gin.Context) {
	tid := c.GetString("tenant_id")
	agentID := c.Param("id")
	status := c.Query("status")
	tasks, err := s.store.ListAgentTasks(c.Request.Context(), tid, agentID, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks, "total": len(tasks)})
}

// POST /api/v1/agents/:id/tasks  (admin only)
func (s *Server) handleCreateAgentTask(c *gin.Context) {
	tid := c.GetString("tenant_id")
	agentID := c.Param("id")
	actor := c.GetString("username")
	var body struct {
		Name     string          `json:"name" binding:"required"`
		Type     string          `json:"type" binding:"required"`
		Schedule string          `json:"schedule"`
		Payload  json.RawMessage `json:"payload"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.Name) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name too long"})
		return
	}
	payload := body.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	task := &models.AgentTask{
		ID:       uuid.NewString(),
		TenantID: tid,
		AgentID:  agentID,
		Name:     body.Name,
		Type:     body.Type,
		Schedule: body.Schedule,
		Payload:  payload,
	}
	if err := s.store.CreateAgentTask(c.Request.Context(), task, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusCreated, task)
}

// PUT /api/v1/agents/:id/tasks/:tid  (admin only)
func (s *Server) handleUpdateAgentTask(c *gin.Context) {
	tid := c.GetString("tenant_id")
	taskID := c.Param("tid")
	actor := c.GetString("username")
	var body struct {
		Name     string          `json:"name"`
		Schedule string          `json:"schedule"`
		Status   string          `json:"status"`
		Payload  json.RawMessage `json:"payload"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	allowed := map[string]bool{"active": true, "paused": true, "completed": true, "": true}
	if !allowed[body.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	payload := body.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	task, err := s.store.UpdateAgentTask(c.Request.Context(), taskID, tid, actor, body.Name, body.Schedule, body.Status, payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, task)
}

// DELETE /api/v1/agents/:id/tasks/:tid  (admin only)
func (s *Server) handleDeleteAgentTask(c *gin.Context) {
	tid := c.GetString("tenant_id")
	taskID := c.Param("tid")
	actor := c.GetString("username")
	if err := s.store.DeleteAgentTask(c.Request.Context(), taskID, tid, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// POST /api/v1/agents/:id/tasks/:tid/run — on-demand execution trigger
func (s *Server) handleRunAgentTask(c *gin.Context) {
	tid := c.GetString("tenant_id")
	taskID := c.Param("tid")
	actor := c.GetString("username")
	task, err := s.store.GetAgentTask(c.Request.Context(), taskID, tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if task.Status == "deleted" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot run a deleted task"})
		return
	}
	// Set next_run_at = NOW() so the task is claimed on the agent's next heartbeat.
	if err := s.store.TriggerAgentTaskNow(c.Request.Context(), taskID, tid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	_ = s.store.LogTaskRunEvent(c.Request.Context(), task, actor)
	c.JSON(http.StatusAccepted, gin.H{"message": "task queued for execution", "task_id": taskID})
}

// GET /api/v1/agents/:id/tasks/history
func (s *Server) handleListAgentTaskHistory(c *gin.Context) {
	tid := c.GetString("tenant_id")
	agentID := c.Param("id")
	taskID := c.Query("task_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	events, total, err := s.store.ListTaskEvents(c.Request.Context(), tid, agentID, taskID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": total})
}

// GET /api/v1/tasks  — global view across all agents
func (s *Server) handleListAllTasks(c *gin.Context) {
	tid := c.GetString("tenant_id")
	status := c.Query("status")
	tasks, err := s.store.ListAgentTasks(c.Request.Context(), tid, "", status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks, "total": len(tasks)})
}

// GET /api/v1/tasks/history — global history across all agents
func (s *Server) handleListAllTaskHistory(c *gin.Context) {
	tid := c.GetString("tenant_id")
	taskID := c.Query("task_id")
	agentID := c.Query("agent_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	events, total, err := s.store.ListTaskEvents(c.Request.Context(), tid, agentID, taskID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": total})
}
