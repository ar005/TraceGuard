package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/store"
)

// GET /api/v1/incidents/:id/forensic-timeline
func (s *Server) handleIncidentForensicTimeline(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	incidentID := c.Param("id")

	opts := parseFTOpts(c)
	result, err := s.store.GetIncidentForensicTimeline(c.Request.Context(), incidentID, tid, opts)
	if err != nil {
		s.log.Error().Err(err).Str("incident", incidentID).Msg("incident forensic timeline")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GET /api/v1/agents/:id/forensic-timeline
func (s *Server) handleAgentForensicTimeline(c *gin.Context) {
	agentID := c.Param("id")

	opts := parseFTOpts(c)
	result, err := s.store.GetAgentForensicTimeline(c.Request.Context(), agentID, opts)
	if err != nil {
		s.log.Error().Err(err).Str("agent", agentID).Msg("agent forensic timeline")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func parseFTOpts(c *gin.Context) store.ForensicOpts {
	opts := store.ForensicOpts{}
	if v := c.Query("after"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.After = &t
		}
	}
	if v := c.Query("before"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.Before = &t
		}
	}
	if types := c.QueryArray("types[]"); len(types) > 0 {
		opts.Types = types
	}
	opts.Limit, _ = strconv.Atoi(c.DefaultQuery("limit", "200"))
	opts.Offset, _ = strconv.Atoi(c.DefaultQuery("offset", "0"))
	return opts
}
