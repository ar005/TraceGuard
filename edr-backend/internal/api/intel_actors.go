package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"github.com/youredr/edr-backend/internal/models"
)

// ─── Threat Actors ─────────────────────────────────────────────────────────

// GET /api/v1/intel/actors
func (s *Server) handleListActors(c *gin.Context) {
	tid := c.GetString("tenant_id")
	actors, err := s.store.ListThreatActors(c.Request.Context(), tid)
	if err != nil {
		s.log.Error().Err(err).Msg("list threat actors")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"actors": actors, "total": len(actors)})
}

// GET /api/v1/intel/actors/:id
func (s *Server) handleGetActor(c *gin.Context) {
	tid := c.GetString("tenant_id")
	actor, err := s.store.GetThreatActor(c.Request.Context(), c.Param("id"), tid)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		s.log.Error().Err(err).Msg("get threat actor")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	iocs, _ := s.store.GetActorIOCs(c.Request.Context(), actor.ID, tid, 200)
	campaigns, _ := s.store.ListCampaigns(c.Request.Context(), tid, actor.ID)
	c.JSON(http.StatusOK, gin.H{"actor": actor, "iocs": iocs, "campaigns": campaigns})
}

// POST /api/v1/intel/actors
func (s *Server) handleCreateActor(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name        string   `json:"name" binding:"required"`
		Aliases     []string `json:"aliases"`
		Country     string   `json:"country"`
		Motivation  string   `json:"motivation"`
		Description string   `json:"description"`
		MitreGroups []string `json:"mitre_groups"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	actor := &models.ThreatActor{
		TenantID:    tid,
		Name:        body.Name,
		Aliases:     pq.StringArray(body.Aliases),
		Country:     body.Country,
		Motivation:  orDefault(body.Motivation, "unknown"),
		Description: body.Description,
		MitreGroups: pq.StringArray(body.MitreGroups),
	}
	if err := s.store.CreateThreatActor(c.Request.Context(), actor); err != nil {
		s.log.Error().Err(err).Msg("create threat actor")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if s.intelGen != nil {
		go s.intelGen.EnqueueForActor(context.Background(), actor.ID)
	}
	c.JSON(http.StatusCreated, actor)
}

// PUT /api/v1/intel/actors/:id
func (s *Server) handleUpdateActor(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name        string   `json:"name" binding:"required"`
		Aliases     []string `json:"aliases"`
		Country     string   `json:"country"`
		Motivation  string   `json:"motivation"`
		Description string   `json:"description"`
		MitreGroups []string `json:"mitre_groups"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	actor := &models.ThreatActor{
		ID:          c.Param("id"),
		TenantID:    tid,
		Name:        body.Name,
		Aliases:     pq.StringArray(body.Aliases),
		Country:     body.Country,
		Motivation:  orDefault(body.Motivation, "unknown"),
		Description: body.Description,
		MitreGroups: pq.StringArray(body.MitreGroups),
	}
	if err := s.store.UpdateThreatActor(c.Request.Context(), actor); err != nil {
		s.log.Error().Err(err).Msg("update threat actor")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, actor)
}

// DELETE /api/v1/intel/actors/:id
func (s *Server) handleDeleteActor(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteThreatActor(c.Request.Context(), c.Param("id"), tid); err != nil {
		s.log.Error().Err(err).Msg("delete threat actor")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── Campaigns ─────────────────────────────────────────────────────────────

// GET /api/v1/intel/campaigns
func (s *Server) handleListCampaigns(c *gin.Context) {
	tid := c.GetString("tenant_id")
	actorID := c.Query("actor_id")
	campaigns, err := s.store.ListCampaigns(c.Request.Context(), tid, actorID)
	if err != nil {
		s.log.Error().Err(err).Msg("list campaigns")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": campaigns, "total": len(campaigns)})
}

// GET /api/v1/intel/campaigns/:id
func (s *Server) handleGetCampaign(c *gin.Context) {
	tid := c.GetString("tenant_id")
	campaign, err := s.store.GetCampaign(c.Request.Context(), c.Param("id"), tid)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		s.log.Error().Err(err).Msg("get campaign")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	iocs, _ := s.store.GetCampaignIOCs(c.Request.Context(), campaign.ID, tid, 200)
	c.JSON(http.StatusOK, gin.H{"campaign": campaign, "iocs": iocs})
}

// POST /api/v1/intel/campaigns
func (s *Server) handleCreateCampaign(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name        string   `json:"name" binding:"required"`
		ActorID     *string  `json:"actor_id"`
		StartDate   *string  `json:"start_date"`
		EndDate     *string  `json:"end_date"`
		Targets     []string `json:"targets"`
		Techniques  []string `json:"techniques"`
		Description string   `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	camp := &models.Campaign{
		TenantID:    tid,
		Name:        body.Name,
		ActorID:     body.ActorID,
		Targets:     pq.StringArray(body.Targets),
		Techniques:  pq.StringArray(body.Techniques),
		Description: body.Description,
	}
	camp.StartDate = parseDate(body.StartDate)
	camp.EndDate = parseDate(body.EndDate)
	if err := s.store.CreateCampaign(c.Request.Context(), camp); err != nil {
		s.log.Error().Err(err).Msg("create campaign")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusCreated, camp)
}

// PUT /api/v1/intel/campaigns/:id
func (s *Server) handleUpdateCampaign(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		Name        string   `json:"name" binding:"required"`
		ActorID     *string  `json:"actor_id"`
		StartDate   *string  `json:"start_date"`
		EndDate     *string  `json:"end_date"`
		Targets     []string `json:"targets"`
		Techniques  []string `json:"techniques"`
		Description string   `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	camp := &models.Campaign{
		ID:          c.Param("id"),
		TenantID:    tid,
		Name:        body.Name,
		ActorID:     body.ActorID,
		Targets:     pq.StringArray(body.Targets),
		Techniques:  pq.StringArray(body.Techniques),
		Description: body.Description,
	}
	camp.StartDate = parseDate(body.StartDate)
	camp.EndDate = parseDate(body.EndDate)
	if err := s.store.UpdateCampaign(c.Request.Context(), camp); err != nil {
		s.log.Error().Err(err).Msg("update campaign")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, camp)
}

// DELETE /api/v1/intel/campaigns/:id
func (s *Server) handleDeleteCampaign(c *gin.Context) {
	tid := c.GetString("tenant_id")
	if err := s.store.DeleteCampaign(c.Request.Context(), c.Param("id"), tid); err != nil {
		s.log.Error().Err(err).Msg("delete campaign")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── IOC linking ────────────────────────────────────────────────────────────

// POST /api/v1/iocs/:id/actor   body: {actor_id}
func (s *Server) handleLinkIOCToActor(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		ActorID string `json:"actor_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.store.LinkIOCToActor(c.Request.Context(), c.Param("id"), body.ActorID, tid); err != nil {
		s.log.Error().Err(err).Msg("link ioc to actor")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}

// POST /api/v1/iocs/:id/campaign   body: {campaign_id}
func (s *Server) handleLinkIOCToCampaign(c *gin.Context) {
	tid := c.GetString("tenant_id")
	var body struct {
		CampaignID string `json:"campaign_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.store.LinkIOCToCampaign(c.Request.Context(), c.Param("id"), body.CampaignID, tid); err != nil {
		s.log.Error().Err(err).Msg("link ioc to campaign")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── helpers ────────────────────────────────────────────────────────────────

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func parseDate(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", *s)
	if err != nil {
		return nil
	}
	return &t
}
