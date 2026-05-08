// internal/api/containers.go — Container & Kubernetes inventory endpoints.

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/store"
)

// handleListContainers returns a paginated container inventory.
func (s *Server) handleListContainers(c *gin.Context) {
	p := store.ListContainersParams{
		AgentID:   c.Query("agent_id"),
		Runtime:   c.Query("runtime"),
		Namespace: c.Query("namespace"),
		Search:    c.Query("search"),
		Limit:     intQuery(c, "limit", 50),
		Offset:    intQuery(c, "offset", 0),
	}
	records, total, err := s.store.ListContainers(c.Request.Context(), p)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"containers": records,
		"total":      total,
		"limit":      p.Limit,
		"offset":     p.Offset,
	})
}

// handleGetContainerStats returns aggregate container inventory stats.
func (s *Server) handleGetContainerStats(c *gin.Context) {
	stats, err := s.store.GetContainerStats(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, stats)
}

// handleGetContainerEvents returns paginated events for a specific container.
// Route: GET /containers/:id/events?agent_id=&limit=&offset=
func (s *Server) handleGetContainerEvents(c *gin.Context) {
	containerID := c.Param("id")
	limit := intQuery(c, "limit", 50)
	offset := intQuery(c, "offset", 0)

	events, total, err := s.store.GetContainerEvents(c.Request.Context(), containerID, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
