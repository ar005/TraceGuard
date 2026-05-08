package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/intel/dashboard
func (s *Server) handleIntelDashboard(c *gin.Context) {
	tid := c.GetString("tenant_id")
	ctx := c.Request.Context()

	stats, err := s.store.GetIntelDashboardStats(ctx, tid)
	if err != nil {
		s.log.Error().Err(err).Msg("intel dashboard stats")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Recent replay jobs (last 5).
	replayJobs, _ := s.store.ListReplayJobs(ctx, tid, 5)

	// Recent intel tasks (last 10).
	tasks, _ := s.store.ListIntelTasks(ctx, tid, 10)

	// Custom feeds with quality scores.
	feeds, _ := s.store.ListCustomIOCFeeds(ctx, tid)

	// Sharing groups.
	sharingGroups, _ := s.store.ListSharingGroups(ctx, tid)

	c.JSON(http.StatusOK, gin.H{
		"stats":          stats,
		"recent_replay":  replayJobs,
		"recent_tasks":   tasks,
		"feeds":          feeds,
		"sharing_groups": sharingGroups,
	})
}
