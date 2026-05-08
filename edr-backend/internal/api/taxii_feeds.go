package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/taxii"
)

// GET /api/v1/intel/taxii-feeds
func (s *Server) handleListTAXIIFeeds(c *gin.Context) {
	tid := c.GetString("tenant_id")
	feeds, err := s.store.ListTAXIIFeeds(c.Request.Context(), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, feeds)
}

// GET /api/v1/intel/taxii-feeds/:id
func (s *Server) handleGetTAXIIFeed(c *gin.Context) {
	tid := c.GetString("tenant_id")
	f, err := s.store.GetTAXIIFeed(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, f)
}

// GET /api/v1/intel/taxii-feeds/:id/runs
func (s *Server) handleListTAXIIPollRuns(c *gin.Context) {
	tid := c.GetString("tenant_id")
	runs, err := s.store.ListTAXIIPollRuns(c.Request.Context(), c.Param("id"), tid, 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, runs)
}

// POST /api/v1/intel/taxii-feeds  (admin)
func (s *Server) handleCreateTAXIIFeed(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name         string `json:"name"           binding:"required"`
		DiscoveryURL string `json:"discovery_url"  binding:"required"`
		APIRoot      string `json:"api_root"`
		CollectionID string `json:"collection_id"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		PollInterval int    `json:"poll_interval"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pollInterval := 3600
	if body.PollInterval > 0 {
		pollInterval = body.PollInterval
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	next := time.Now()
	f := &models.TAXIIFeed{
		TenantID:     tid,
		Name:         body.Name,
		DiscoveryURL: body.DiscoveryURL,
		APIRoot:      body.APIRoot,
		CollectionID: body.CollectionID,
		Username:     body.Username,
		PasswordEnc:  body.Password,
		PollInterval: pollInterval,
		Enabled:      enabled,
		NextPollAt:   &next,
	}
	if err := s.store.CreateTAXIIFeed(c.Request.Context(), f); err != nil {
		s.log.Error().Err(err).Msg("create taxii feed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusCreated, f)
}

// PUT /api/v1/intel/taxii-feeds/:id  (admin)
func (s *Server) handleUpdateTAXIIFeed(c *gin.Context) {
	tid := c.GetString("tenant_id")
	f, err := s.store.GetTAXIIFeed(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var body struct {
		Name         string `json:"name"`
		DiscoveryURL string `json:"discovery_url"`
		APIRoot      string `json:"api_root"`
		CollectionID string `json:"collection_id"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		PollInterval int    `json:"poll_interval"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name != "" {
		f.Name = body.Name
	}
	if body.DiscoveryURL != "" {
		f.DiscoveryURL = body.DiscoveryURL
	}
	if body.APIRoot != "" {
		f.APIRoot = body.APIRoot
	}
	if body.CollectionID != "" {
		f.CollectionID = body.CollectionID
	}
	if body.Username != "" {
		f.Username = body.Username
	}
	if body.Password != "" {
		f.PasswordEnc = body.Password
	}
	if body.PollInterval > 0 {
		f.PollInterval = body.PollInterval
	}
	if body.Enabled != nil {
		f.Enabled = *body.Enabled
	}
	if err := s.store.UpdateTAXIIFeed(c.Request.Context(), f); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, f)
}

// DELETE /api/v1/intel/taxii-feeds/:id  (admin)
func (s *Server) handleDeleteTAXIIFeed(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteTAXIIFeed(c.Request.Context(), c.Param("id"), tid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// POST /api/v1/intel/taxii-feeds/:id/poll  (admin) — trigger immediate poll
func (s *Server) handlePollTAXIIFeed(c *gin.Context) {
	if s.taxiiPoller == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "taxii poller not configured"})
		return
	}
	tid := c.GetString("tenant_id")
	f, err := s.store.GetTAXIIFeed(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	go s.taxiiPoller.PollFeed(c.Request.Context(), *f)
	c.JSON(http.StatusAccepted, gin.H{"status": "poll queued"})
}

// GET /api/v1/intel/taxii-feeds/:id/collections — discover collections on the server
func (s *Server) handleListTAXIICollections(c *gin.Context) {
	tid := c.GetString("tenant_id")
	f, err := s.store.GetTAXIIFeed(c.Request.Context(), c.Param("id"), tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	client := taxii.New(f.DiscoveryURL, f.Username, f.PasswordEnc)
	cols, err := client.ListCollections(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cols)
}
