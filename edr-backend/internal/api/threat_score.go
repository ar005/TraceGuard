package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/xdr/threat-score?days=30
func (s *Server) handleGetOrgThreatScore(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))

	result, err := s.store.GetOrgThreatScore(c.Request.Context(), tid, days)
	if err != nil {
		s.log.Error().Err(err).Msg("get org threat score")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GET /api/v1/xdr/threat-score/history?entity_id=&entity_type=agent|user&days=30
func (s *Server) handleGetEntityRiskHistory(c *gin.Context) {
	entityID := c.Query("entity_id")
	entityType := c.DefaultQuery("entity_type", "agent")
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))

	if entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity_id required"})
		return
	}
	if entityType != "agent" && entityType != "user" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity_type must be 'agent' or 'user'"})
		return
	}

	points, err := s.store.GetEntityRiskHistory(c.Request.Context(), entityID, entityType, days)
	if err != nil {
		s.log.Error().Err(err).Msg("get entity risk history")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"history": points, "entity_id": entityID, "entity_type": entityType})
}
