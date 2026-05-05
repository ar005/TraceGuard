package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// POST /api/v1/iocs/:id/enrich
func (s *Server) handleEnrichIOC(c *gin.Context) {
	id := c.Param("id")
	ioc, err := s.store.GetIOC(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IOC not found"})
		return
	}

	if s.iocPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrichment pipeline not configured"})
		return
	}

	if err := s.iocPipeline.EnrichOne(c.Request.Context(), ioc); err != nil {
		s.log.Warn().Err(err).Str("ioc", id).Msg("force-enrich IOC")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "enrichment failed"})
		return
	}

	// Return the updated IOC.
	updated, err := s.store.GetIOC(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "enriched"})
		return
	}
	c.JSON(http.StatusOK, updated)
}
