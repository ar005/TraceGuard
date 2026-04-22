// internal/api/cases.go — Case management REST handlers.

package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/users"
)

// ── Cases ─────────────────────────────────────────────────────────────────────

func (s *Server) handleListCases(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	status := c.Query("status")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	cases, total, err := s.store.ListCases(c.Request.Context(), tid, status, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if cases == nil {
		cases = []models.Case{}
	}
	c.JSON(http.StatusOK, gin.H{"cases": cases, "total": total})
}

func (s *Server) handleGetCase(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	cs, err := s.store.GetCase(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	notes, _ := s.store.ListCaseNotes(c.Request.Context(), cs.ID, tid)
	alerts, _ := s.store.ListCaseAlerts(c.Request.Context(), cs.ID, tid)
	if notes == nil {
		notes = []models.CaseNote{}
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	c.JSON(http.StatusOK, gin.H{"case": cs, "notes": notes, "alerts": alerts})
}

func (s *Server) handleCreateCase(c *gin.Context) {
	var cs models.Case
	if err := c.ShouldBindJSON(&cs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if cs.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"})
		return
	}
	if cs.Tags == nil {
		cs.Tags = []string{}
	}
	if cs.MitreIDs == nil {
		cs.MitreIDs = []string{}
	}
	if raw, ok := c.Get(string(ctxClaims)); ok {
		if claims, ok := raw.(*users.Claims); ok {
			cs.CreatedBy = claims.Subject
			if cs.Assignee == "" {
				cs.Assignee = claims.Subject
			}
			if claims.TenantID != "" {
				cs.TenantID = claims.TenantID
			}
		}
	}
	if err := s.store.CreateCase(c.Request.Context(), &cs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, cs)
}

func (s *Server) handleUpdateCase(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	cs, err := s.store.GetCase(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	// Only the case creator or an admin may overwrite a case.
	if raw, ok := c.Get(string(ctxClaims)); ok {
		if claims, ok := raw.(*users.Claims); ok {
			if claims.Role != users.RoleAdmin && claims.Subject != cs.CreatedBy {
				c.JSON(http.StatusForbidden, gin.H{"error": "only the case creator or an admin may update this case"})
				return
			}
		}
	}
	if err := c.ShouldBindJSON(cs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cs.ID = c.Param("id")
	if err := s.store.UpdateCase(c.Request.Context(), cs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cs)
}

func (s *Server) handleDeleteCase(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	if err := s.store.DeleteCase(c.Request.Context(), c.Param("id"), tid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ── Case Alerts ───────────────────────────────────────────────────────────────

func (s *Server) handleListCaseAlerts(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	alerts, err := s.store.ListCaseAlerts(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

func (s *Server) handleLinkAlert(c *gin.Context) {
	var body struct {
		AlertID string `json:"alert_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.AlertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "alert_id required"})
		return
	}
	actor := ""
	if raw, ok := c.Get(string(ctxClaims)); ok {
		if claims, ok := raw.(*users.Claims); ok {
			actor = claims.Subject
		}
	}
	if err := s.store.LinkAlertToCase(c.Request.Context(), c.Param("id"), body.AlertID, actor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) handleUnlinkAlert(c *gin.Context) {
	if err := s.store.UnlinkAlertFromCase(c.Request.Context(), c.Param("id"), c.Param("alert_id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ── Case Notes ────────────────────────────────────────────────────────────────

func (s *Server) handleListCaseNotes(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	notes, err := s.store.ListCaseNotes(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if notes == nil {
		notes = []models.CaseNote{}
	}
	c.JSON(http.StatusOK, gin.H{"notes": notes})
}

func (s *Server) handleAddCaseNote(c *gin.Context) {
	var note models.CaseNote
	if err := c.ShouldBindJSON(&note); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if note.Body == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body required"})
		return
	}
	note.CaseID = c.Param("id")
	if raw, ok := c.Get(string(ctxClaims)); ok {
		if claims, ok := raw.(*users.Claims); ok {
			note.Author = claims.Subject
		}
	}
	if err := s.store.AddCaseNote(c.Request.Context(), &note); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, note)
}

func (s *Server) handleUpdateCaseNote(c *gin.Context) {
	var body struct {
		Body string `json:"body"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Body == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body required"})
		return
	}
	if err := s.store.UpdateCaseNote(c.Request.Context(), c.Param("note_id"), body.Body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) handleDeleteCaseNote(c *gin.Context) {
	if err := s.store.DeleteCaseNote(c.Request.Context(), c.Param("note_id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}
