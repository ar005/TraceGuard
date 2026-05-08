package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/xdr/anomalies?active_only=true&limit=50&offset=0
func (s *Server) handleListAnomalies(c *gin.Context) {
	tid := c.GetString("tenant_id")
	activeOnly := c.Query("active_only") != "false"
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	rows, err := s.store.ListAnomalies(c.Request.Context(), tid, activeOnly, limit, offset)
	if err != nil {
		s.log.Error().Err(err).Msg("list anomalies")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"anomalies": rows, "total": len(rows)})
}

// GET /api/v1/identity/:uid/anomalies?days=7
func (s *Server) handleGetEntityAnomalies(c *gin.Context) {
	uid := c.Param("uid")
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))

	rows, err := s.store.GetEntityAnomalies(c.Request.Context(), uid, days)
	if err != nil {
		s.log.Error().Err(err).Str("uid", uid).Msg("get entity anomalies")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"entity_id": uid, "anomalies": rows})
}
