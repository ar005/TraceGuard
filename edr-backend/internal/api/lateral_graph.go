package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/xdr/lateral-graph?hours=24&min_connections=1
func (s *Server) handleLateralGraph(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	minConn, _ := strconv.Atoi(c.DefaultQuery("min_connections", "1"))

	graph, err := s.store.GetLateralGraph(c.Request.Context(), hours, minConn)
	if err != nil {
		s.log.Error().Err(err).Msg("lateral graph query")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, graph)
}
