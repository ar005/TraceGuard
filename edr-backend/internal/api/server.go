// internal/api/server.go
// REST API for the EDR backend.
// All endpoints return JSON. Authentication via Bearer token (dev: any token).

package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Server is the REST API server.
type Server struct {
	store  *store.Store
	engine *detection.Engine
	log    zerolog.Logger
	router *gin.Engine
	http   *http.Server
	apiKey string
}

// New creates the API server and registers all routes.
func New(st *store.Store, eng *detection.Engine, log zerolog.Logger, apiKey string) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(ginLogger(log), gin.Recovery())

	s := &Server{
		store:  st,
		engine: eng,
		log:    log.With().Str("component", "api").Logger(),
		router: r,
		apiKey: apiKey,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	r := s.router

	// Health / status (no auth)
	r.GET("/health",  s.handleHealth)
	r.GET("/metrics", s.handleMetrics)

	// Authenticated routes
	v1 := r.Group("/api/v1", s.authMiddleware())
	{
		// ── Dashboard ──────────────────────────────────────────────────────
		v1.GET("/dashboard", s.handleDashboard)

		// ── Agents ─────────────────────────────────────────────────────────
		v1.GET("/agents",     s.handleListAgents)
		v1.GET("/agents/:id", s.handleGetAgent)

		// ── Events ─────────────────────────────────────────────────────────
		v1.GET("/events",     s.handleListEvents)
		v1.GET("/events/:id", s.handleGetEvent)

		// ── Alerts ─────────────────────────────────────────────────────────
		v1.GET("/alerts",           s.handleListAlerts)
		v1.GET("/alerts/:id",       s.handleGetAlert)
		v1.PATCH("/alerts/:id",     s.handleUpdateAlert)

		// ── Rules ──────────────────────────────────────────────────────────
		v1.GET("/rules",        s.handleListRules)
		v1.GET("/rules/:id",    s.handleGetRule)
		v1.POST("/rules",       s.handleCreateRule)
		v1.PUT("/rules/:id",    s.handleUpdateRule)
		v1.DELETE("/rules/:id", s.handleDeleteRule)
		v1.POST("/rules/reload", s.handleReloadRules)
	}
}

// Listen starts the HTTP server on addr.
func (s *Server) Listen(addr string) error {
	s.http = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	s.log.Info().Str("addr", addr).Msg("REST API listening")
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.apiKey == "" {
			// No key configured → open (dev mode)
			c.Next()
			return
		}
		token := c.GetHeader("Authorization")
		if token == "Bearer "+s.apiKey {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

// ─── Health ───────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
}

func (s *Server) handleMetrics(c *gin.Context) {
	agents, _ := s.store.ListAgents(c.Request.Context())
	online := 0
	for _, a := range agents {
		if a.IsOnline {
			online++
		}
	}
	alertStats, _ := s.store.AlertStats(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"agents_total":  len(agents),
		"agents_online": online,
		"alert_stats":   alertStats,
	})
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

func (s *Server) handleDashboard(c *gin.Context) {
	ctx := c.Request.Context()

	agents, _ := s.store.ListAgents(ctx)
	online := 0
	for _, a := range agents {
		if a.IsOnline {
			online++
		}
	}

	alertStats, _ := s.store.AlertStats(ctx)

	// Recent critical/high alerts
	recentAlerts, _ := s.store.QueryAlerts(ctx, store.QueryAlertsParams{
		Status: "OPEN", Severity: 3, Limit: 10,
	})

	// Events last 24h
	since24h := time.Now().Add(-24 * time.Hour)
	eventCount, _ := s.store.CountEvents(ctx, "", since24h)

	c.JSON(http.StatusOK, gin.H{
		"agents_total":   len(agents),
		"agents_online":  online,
		"events_24h":     eventCount,
		"alert_stats":    alertStats,
		"recent_alerts":  recentAlerts,
	})
}

// ─── Agents ───────────────────────────────────────────────────────────────────

func (s *Server) handleListAgents(c *gin.Context) {
	agents, err := s.store.ListAgents(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents, "total": len(agents)})
}

func (s *Server) handleGetAgent(c *gin.Context) {
	agent, err := s.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, agent)
}

// ─── Events ───────────────────────────────────────────────────────────────────

func (s *Server) handleListEvents(c *gin.Context) {
	p := store.QueryEventsParams{
		AgentID: c.Query("agent_id"),
		Search:  c.Query("q"),
		Limit:   intQuery(c, "limit", 50),
		Offset:  intQuery(c, "offset", 0),
	}
	if t := c.Query("event_type"); t != "" {
		p.EventTypes = []string{t}
	}
	if s := c.Query("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err == nil {
			p.Since = &t
		}
	}
	if u := c.Query("until"); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err == nil {
			p.Until = &t
		}
	}

	// PID correlation — fetch events from same process for drawer process tree.
	if pid := c.Query("pid"); pid != "" {
		p.PID = pid
	}
	if hn := c.Query("hostname"); hn != "" {
		p.Hostname = hn
	}

	events, err := s.store.QueryEvents(c.Request.Context(), p)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
}

func (s *Server) handleGetEvent(c *gin.Context) {
	ev, err := s.store.GetEvent(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, ev)
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (s *Server) handleListAlerts(c *gin.Context) {
	p := store.QueryAlertsParams{
		AgentID: c.Query("agent_id"),
		Status:  c.Query("status"),
		RuleID:  c.Query("rule_id"),
		Limit:   intQuery(c, "limit", 50),
		Offset:  intQuery(c, "offset", 0),
	}
	if sv := c.Query("min_severity"); sv != "" {
		n, err := strconv.Atoi(sv)
		if err == nil {
			p.Severity = int16(n)
		}
	}

	alerts, err := s.store.QueryAlerts(c.Request.Context(), p)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts, "total": len(alerts)})
}

func (s *Server) handleGetAlert(c *gin.Context) {
	alert, err := s.store.GetAlert(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, alert)
}

func (s *Server) handleUpdateAlert(c *gin.Context) {
	var body struct {
		Status   string `json:"status"`
		Assignee string `json:"assignee"`
		Notes    string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.store.UpdateAlertStatus(c.Request.Context(),
		c.Param("id"), body.Status, body.Assignee, body.Notes,
	); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (s *Server) handleListRules(c *gin.Context) {
	rules, err := s.store.ListRules(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

func (s *Server) handleGetRule(c *gin.Context) {
	rule, err := s.store.GetRule(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (s *Server) handleCreateRule(c *gin.Context) {
	var body struct {
		Name        string   `json:"name"        binding:"required"`
		Description string   `json:"description"`
		Enabled     bool     `json:"enabled"`
		Severity    int16    `json:"severity"`
		EventTypes  []string `json:"event_types" binding:"required"`
		Conditions  interface{} `json:"conditions"`
		MitreIDs    []string `json:"mitre_ids"`
		Author      string   `json:"author"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	import_json, _ := marshalToRaw(body.Conditions)
	rule := &models.Rule{
		ID:          "rule-" + uuid.New().String(),
		Name:        body.Name,
		Description: body.Description,
		Enabled:     body.Enabled,
		Severity:    body.Severity,
		EventTypes:  pq.StringArray(body.EventTypes),
		Conditions:  import_json,
		MitreIDs:    pq.StringArray(body.MitreIDs),
		Author:      body.Author,
	}
	if rule.Author == "" {
		rule.Author = "api"
	}
	if err := s.store.UpsertRule(c.Request.Context(), rule); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) handleUpdateRule(c *gin.Context) {
	existing, err := s.store.GetRule(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}

	var body struct {
		Name        *string      `json:"name"`
		Description *string      `json:"description"`
		Enabled     *bool        `json:"enabled"`
		Severity    *int16       `json:"severity"`
		EventTypes  []string     `json:"event_types"`
		Conditions  interface{}  `json:"conditions"`
		MitreIDs    []string     `json:"mitre_ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Name        != nil { existing.Name        = *body.Name }
	if body.Description != nil { existing.Description = *body.Description }
	if body.Enabled     != nil { existing.Enabled     = *body.Enabled }
	if body.Severity    != nil { existing.Severity    = *body.Severity }
	if body.EventTypes  != nil { existing.EventTypes  = pq.StringArray(body.EventTypes) }
	if body.MitreIDs    != nil { existing.MitreIDs    = pq.StringArray(body.MitreIDs) }
	if body.Conditions  != nil {
		if raw, err := marshalToRaw(body.Conditions); err == nil {
			existing.Conditions = raw
		}
	}

	if err := s.store.UpsertRule(c.Request.Context(), existing); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	c.JSON(http.StatusOK, existing)
}

func (s *Server) handleDeleteRule(c *gin.Context) {
	if err := s.store.DeleteRule(c.Request.Context(), c.Param("id")); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) handleReloadRules(c *gin.Context) {
	if err := s.engine.Reload(c.Request.Context()); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (s *Server) jsonError(c *gin.Context, err error) {
	s.log.Error().Err(err).Str("path", c.Request.URL.Path).Msg("api error")
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func intQuery(c *gin.Context, key string, def int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func marshalToRaw(v interface{}) ([]byte, error) {
	import_json, err := jsonMarshal(v)
	if err != nil {
		return []byte("[]"), err
	}
	return import_json, nil
}

// ginLogger returns a gin middleware that logs via zerolog.
func ginLogger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info().
			Int("status",  c.Writer.Status()).
			Str("method",  c.Request.Method).
			Str("path",    c.Request.URL.Path).
			Dur("latency", time.Since(start)).
			Str("ip",      c.ClientIP()).
			Msg("http")
	}
}
