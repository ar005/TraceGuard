// internal/api/server.go
// REST API for the EDR backend.
// Auth: Bearer JWT (issued by POST /api/v1/auth/login) or Bearer API key.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/apikeys"
	"github.com/youredr/edr-backend/internal/configver"
	"github.com/youredr/edr-backend/internal/cvecache"
	"github.com/youredr/edr-backend/internal/llm"
	"github.com/youredr/edr-backend/internal/metrics"
	"github.com/youredr/edr-backend/internal/liveresponse"
	"github.com/youredr/edr-backend/internal/sse"
	"github.com/youredr/edr-backend/internal/audit"
	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/iocfeed"
	"github.com/youredr/edr-backend/internal/migrate"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
	"github.com/youredr/edr-backend/internal/users"
)

// Server is the REST API server.
type Server struct {
	store    *store.Store
	engine   *detection.Engine
	keys     *apikeys.Manager
	um       *users.Manager
	al       *audit.Logger
	llm      *llm.Client
	lr       *liveresponse.Manager
	iocSync  *iocfeed.Syncer
	sse      *sse.Broker
	log      zerolog.Logger
	router   *gin.Engine
	http     *http.Server
	apiKey     string // legacy single-key fallback
	rateLimit  RateLimitConfig
	cveFetcher *cvecache.Fetcher
}

// New creates the API server and registers all routes.
func New(st *store.Store, eng *detection.Engine, km *apikeys.Manager,
	um *users.Manager, al *audit.Logger,
	lc *llm.Client, lr *liveresponse.Manager, is *iocfeed.Syncer, sb *sse.Broker,
	log zerolog.Logger, apiKey string, rlCfg ...RateLimitConfig) *Server {

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(ginLogger(log), gin.Recovery())
	r.Use(TraceGuardMiddleware())

	rl := DefaultRateLimitConfig()
	if len(rlCfg) > 0 {
		rl = rlCfg[0]
	}

	// Apply rate limiting middleware globally.
	r.Use(rateLimitMiddleware(rl))

	s := &Server{
		store:     st,
		engine:    eng,
		keys:      km,
		um:        um,
		al:        al,
		llm:       lc,
		lr:        lr,
		iocSync:   is,
		sse:       sb,
		log:       log.With().Str("component", "api").Logger(),
		router:    r,
		apiKey:    apiKey,
		rateLimit: rl,
	}
	s.registerRoutes()

	if rl.Enabled {
		log.Info().
			Float64("rps", rl.RequestsPerSecond).
			Int("burst", rl.Burst).
			Msg("API rate limiting enabled")
	}

	return s
}

func (s *Server) registerRoutes() {
	r := s.router

	// Prometheus metrics middleware (must be before routes).
	r.Use(prometheusMiddleware())

	// Health / status (no auth)
	r.GET("/health",  s.handleHealth)
	r.GET("/metrics", s.handleMetrics)
	r.GET("/metrics/prometheus", gin.WrapH(promhttp.Handler()))

	// ── Setup endpoints (no auth — only work when no users exist) ───────────
	// NOTE: intentionally under /api/v1/setup, NOT /api/v1/admin,
	// to avoid collision with the authenticated admin group below.
	setupGrp := r.Group("/api/v1/setup")
	{
		setupGrp.GET("/status",  s.handleSetupStatus)
		setupGrp.POST("",        s.handleSetup)
	}

	// ── Public auth endpoints ──────────────────────────────────────────────
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/login",              s.handleLogin)
		auth.POST("/refresh",            s.handleRefresh)
		auth.POST("/totp/verify-login",  s.handleTOTPVerifyLogin)
	}

	// ── Authenticated routes (JWT or API key) ─────────────────────────────
	v1 := r.Group("/api/v1", s.authMiddleware())
	{
		v1.GET("/dashboard", s.handleDashboard)
		v1.GET("/me",        s.handleMe)

		// Agents
		v1.GET("/agents",          s.handleListAgents)
		v1.GET("/agents/:id",      s.handleGetAgent)
		v1.PATCH("/agents/:id",    s.handleUpdateAgent)

		// Events
		v1.GET("/events",         s.handleListEvents)
		v1.GET("/events/:id",     s.handleGetEvent)
		v1.POST("/events/inject", s.handleInjectEvent)
		v1.GET("/events/stream",  s.handleEventStream)

		// Process tree
		v1.GET("/processes/:pid/tree", s.handleGetProcessTree)

		// Browser navigation tree
		v1.GET("/browser/tree", s.handleGetBrowserTree)
		v1.GET("/browser/tabs", s.handleListBrowserTabs)

		// Alerts
		v1.GET("/alerts",             s.handleListAlerts)
		v1.GET("/alerts/:id",         s.handleGetAlert)
		v1.GET("/alerts/:id/events",   s.handleGetAlertEvents)
		v1.GET("/alerts/:id/timeline", s.handleGetAlertTimeline)
		v1.POST("/alerts/:id/explain",  s.handleExplainAlert)
		v1.PATCH("/alerts/:id",        s.handleUpdateAlert)

		// Live Response
		v1.GET("/liveresponse/agents",          s.handleLRAgents)
		v1.POST("/liveresponse/command",        s.handleLRCommand)

		// Incidents
		v1.GET("/incidents",             s.handleListIncidents)
		v1.GET("/incidents/:id",         s.handleGetIncident)
		v1.PATCH("/incidents/:id",       s.handleUpdateIncident)
		v1.GET("/incidents/:id/alerts",  s.handleGetIncidentAlerts)

		// Rules
		v1.GET("/rules",              s.handleListRules)
		v1.GET("/rules/:id",          s.handleGetRule)
		v1.POST("/rules",             s.handleCreateRule)
		v1.PUT("/rules/:id",          s.handleUpdateRule)
		v1.DELETE("/rules/:id",       s.handleDeleteRule)
		v1.POST("/rules/reload",      s.handleReloadRules)
		v1.POST("/rules/:id/backtest", s.handleBacktestRule)

		// Suppression rules
		v1.GET("/suppressions",        s.handleListSuppressions)
		v1.POST("/suppressions",       s.handleCreateSuppression)
		v1.PUT("/suppressions/:id",    s.handleUpdateSuppression)
		v1.DELETE("/suppressions/:id", s.handleDeleteSuppression)

		// Package inventory & vulnerabilities
		v1.GET("/agents/:id/packages",        s.handleListAgentPackages)
		v1.POST("/agents/:id/scan-packages",  s.handleScanPackages)
		v1.GET("/agents/:id/vulnerabilities", s.handleListAgentVulns)
		v1.GET("/vulnerabilities",            s.handleListVulnerabilities)
		v1.GET("/cve/:id",                    s.handleGetCVE)

		// IOC / Threat Intelligence
		v1.GET("/iocs",           s.handleListIOCs)
		v1.GET("/iocs/stats",     s.handleIOCStats)
		v1.GET("/iocs/:id",       s.handleGetIOC)
		v1.POST("/iocs",          s.handleCreateIOC)
		v1.POST("/iocs/bulk",     s.handleBulkImportIOCs)
		v1.DELETE("/iocs/:id",    s.handleDeleteIOC)
		v1.DELETE("/iocs/source/:source", s.handleDeleteIOCsBySource)
		v1.GET("/iocs/feeds",            s.handleListFeeds)
		v1.POST("/iocs/feeds/sync",      s.handleSyncFeeds)
		v1.GET("/iocs/sources",          s.handleIOCSourceStats)

		// Threat Hunting
		v1.POST("/hunt", s.handleHunt)

		// Settings / Retention
		v1.GET("/settings/retention",   s.handleGetRetention)
		v1.POST("/settings/retention",  s.handleSetRetention)

		// LLM / AI settings
		v1.GET("/settings/llm",        s.handleGetLLMSettings)
		v1.POST("/settings/llm",       s.handleSetLLMSettings)
		v1.POST("/settings/llm/test",  s.handleTestLLM)

		// Migration
		mig := v1.Group("/migrate")
		{
			mig.POST("/export", s.handleMigrateExport)
			mig.POST("/import", s.handleMigrateImport)
		}

		// API key management (admin only)
		kg := v1.Group("/keys", s.adminOnly())
		{
			kg.GET("",             s.handleListKeys)
			kg.POST("",            s.handleCreateKey)
			kg.POST("/:id/revoke", s.handleRevokeKey)
			kg.DELETE("/:id",      s.handleDeleteKey)
		}
	}

	// ── Admin-only routes (user management, audit log) ─────────────────────
	adm := r.Group("/api/v1/admin", s.authMiddleware(), s.adminOnly())
	{
		// Users
		adm.GET("/users",                  s.handleAdminListUsers)
		adm.POST("/users",                 s.handleAdminCreateUser)
		adm.GET("/users/:id",              s.handleAdminGetUser)
		adm.PATCH("/users/:id",            s.handleAdminUpdateUser)
		adm.DELETE("/users/:id",              s.handleAdminDeleteUser)
		adm.POST("/users/:id/reset-password", s.handleAdminResetPassword)
		adm.DELETE("/reset-all-users",        s.handleSetupReset)

		// TOTP / MFA management
		adm.POST("/users/:id/totp/setup",    s.handleTOTPSetup)
		adm.POST("/users/:id/totp/confirm",  s.handleTOTPConfirm)
		adm.DELETE("/users/:id/totp",         s.handleTOTPDisable)

		// API Keys (also available under /keys above, duplicated for admin portal convenience)
		adm.GET("/keys",             s.handleListKeys)
		adm.POST("/keys",            s.handleCreateKey)
		adm.POST("/keys/:id/revoke", s.handleRevokeKey)
		adm.DELETE("/keys/:id",      s.handleDeleteKey)

		// Audit log
		adm.GET("/audit", s.handleAuditLog)
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

// ─── Context keys ─────────────────────────────────────────────────────────────

type ctxKey string

const (
	ctxClaims ctxKey = "claims"
	ctxApiKey ctxKey = "apikey"
)

// ─── Middleware ───────────────────────────────────────────────────────────────

// authMiddleware accepts a Bearer JWT (from login) OR a Bearer API key.
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		// SSE clients cannot set headers, so also accept ?token= query param.
		if raw == "" {
			raw = c.Query("token")
		}

		// ── Try JWT first ──────────────────────────────────────────────────
		if s.um != nil && raw != "" {
			if claims, err := s.um.ValidateToken(raw); err == nil {
				c.Set(string(ctxClaims), claims)
				c.Next()
				return
			}
		}

		// ── Try DB API key ─────────────────────────────────────────────────
		if s.keys != nil && raw != "" {
			if key, err := s.keys.Validate(c.Request.Context(), raw); err == nil {
				c.Set(string(ctxApiKey), key)
				c.Next()
				return
			}
		}

		// ── Legacy plain-text key from config ──────────────────────────────
		if s.apiKey != "" && raw == s.apiKey {
			c.Next()
			return
		}

		// ── Dev mode: no keys anywhere → open ──────────────────────────────
		if raw == "" && s.apiKey == "" {
			if s.keys != nil {
				if ks, _ := s.keys.List(c.Request.Context()); len(ks) > 0 {
					c.AbortWithStatusJSON(http.StatusUnauthorized,
						gin.H{"error": "unauthorized"})
					return
				}
			}
			if s.um != nil {
				if us, _ := s.um.List(c.Request.Context()); len(us) > 0 {
					c.AbortWithStatusJSON(http.StatusUnauthorized,
						gin.H{"error": "unauthorized"})
					return
				}
			}
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

// adminOnly blocks non-admin JWT callers. API key callers are treated as admin
// for backward compatibility (keys are managed by admins anyway).
func (s *Server) adminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's a JWT, enforce role
		if raw, exists := c.Get(string(ctxClaims)); exists {
			if claims, ok := raw.(*users.Claims); ok {
				if claims.Role != users.RoleAdmin {
					c.AbortWithStatusJSON(http.StatusForbidden,
						gin.H{"error": "admin role required"})
					return
				}
			}
		}
		// API keys and legacy key pass through
		c.Next()
	}
}

// currentUser extracts actor info from the request context for audit logging.
func currentUser(c *gin.Context) (id, name string) {
	if raw, exists := c.Get(string(ctxClaims)); exists {
		if claims, ok := raw.(*users.Claims); ok {
			return claims.Subject, claims.Username
		}
	}
	return "api-key", "api-key"
}

// handleSetupReset wipes ALL users from the database.
// Requires a valid admin JWT (Authorization: Bearer <token>).
// Registered under the authenticated admin group, so auth is enforced by middleware.
// Used by the admin portal CLI to force a re-setup.
func (s *Server) handleSetupReset(c *gin.Context) {
	us, err := s.um.List(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}

	deleted := []string{}
	for _, u := range us {
		if err := s.um.Delete(c.Request.Context(), u.ID); err != nil {
			s.log.Error().Err(err).Str("user", u.Username).Msg("reset: delete user failed")
		} else {
			deleted = append(deleted, u.Username)
		}
	}

	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "reset_all_users", "system", "", "",
		c.ClientIP(), fmt.Sprintf("deleted %d users: %v", len(deleted), deleted))
	s.log.Warn().Strs("deleted", deleted).Msg("ALL USERS DELETED via setup reset")

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"deleted": deleted,
		"count":   len(deleted),
	})
}

// ─── Auth handlers ────────────────────────────────────────────────────────────

// POST /api/v1/auth/login
// Body: {"username":"admin","password":"..."}
// Returns: {"token":"<jwt>","user":{...},"expires_at":"..."}
func (s *Server) handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := s.um.Authenticate(c.Request.Context(), body.Username, body.Password)
	if err != nil {
		s.al.Log(c.Request.Context(), "", body.Username, "login_fail", "user", "", body.Username, c.ClientIP(), err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// If TOTP is required, return a partial response with an MFA token.
	if result.MFARequired {
		s.al.Log(c.Request.Context(), result.User.ID, result.User.Username, "login_mfa_pending", "user", result.User.ID, result.User.Username, c.ClientIP(), "")
		c.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"mfa_token":    result.MFAToken,
		})
		return
	}

	s.al.Log(c.Request.Context(), result.User.ID, result.User.Username, "login", "user", result.User.ID, result.User.Username, c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{
		"token":      result.Token,
		"expires_at": time.Now().Add(12 * time.Hour),
		"user":       result.User,
	})
}

// POST /api/v1/auth/refresh — re-issue JWT without re-entering password.
func (s *Server) handleRefresh(c *gin.Context) {
	raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	claims, err := s.um.ValidateToken(raw)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	u, err := s.um.Get(c.Request.Context(), claims.Subject)
	if err != nil || !u.Enabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found or disabled"})
		return
	}
	// Issue token directly since we already validated via JWT.
	token, err := s.um.IssueToken(u)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": time.Now().Add(12 * time.Hour),
	})
}

// ─── TOTP / MFA handlers ─────────────────────────────────────────────────────

// POST /api/v1/auth/totp/verify-login — complete login with TOTP code.
func (s *Server) handleTOTPVerifyLogin(c *gin.Context) {
	var body struct {
		MFAToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code"      binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	u, token, err := s.um.VerifyTOTPLogin(c.Request.Context(), body.MFAToken, body.Code)
	if err != nil {
		s.al.Log(c.Request.Context(), "", "", "totp_verify_fail", "user", "", "", c.ClientIP(), err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid TOTP code"})
		return
	}

	s.al.Log(c.Request.Context(), u.ID, u.Username, "login", "user", u.ID, u.Username, c.ClientIP(), "totp verified")
	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": time.Now().Add(12 * time.Hour),
		"user":       u,
	})
}

// POST /api/v1/admin/users/:id/totp/setup — start TOTP enrollment for a user.
func (s *Server) handleTOTPSetup(c *gin.Context) {
	userID := c.Param("id")
	result, err := s.um.SetupTOTP(c.Request.Context(), userID)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	s.al.Log(c.Request.Context(), s.currentUserID(c), s.currentUsername(c),
		"totp_setup", "user", userID, "", c.ClientIP(), "")
	c.JSON(http.StatusOK, result)
}

// POST /api/v1/admin/users/:id/totp/confirm — verify code and enable TOTP.
func (s *Server) handleTOTPConfirm(c *gin.Context) {
	userID := c.Param("id")
	var body struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.um.ConfirmTOTP(c.Request.Context(), userID, body.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.al.Log(c.Request.Context(), s.currentUserID(c), s.currentUsername(c),
		"totp_enabled", "user", userID, "", c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{"status": "totp enabled"})
}

// DELETE /api/v1/admin/users/:id/totp — disable TOTP for a user.
func (s *Server) handleTOTPDisable(c *gin.Context) {
	userID := c.Param("id")
	if err := s.um.DisableTOTP(c.Request.Context(), userID); err != nil {
		s.jsonError(c, err)
		return
	}
	s.al.Log(c.Request.Context(), s.currentUserID(c), s.currentUsername(c),
		"totp_disabled", "user", userID, "", c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{"status": "totp disabled"})
}

// currentUserID extracts the user ID from the JWT claims in the context.
func (s *Server) currentUserID(c *gin.Context) string {
	if v, ok := c.Get("user_id"); ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// currentUsername extracts the username from the JWT claims in the context.
func (s *Server) currentUsername(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// GET /api/v1/me — returns current user info.
// ─── Setup handlers ──────────────────────────────────────────────────────────

// GET /api/v1/setup/status — no auth required.
// Returns {"setup_needed": true} when no users exist in the DB.
// Used by the admin portal to detect first-run state.
func (s *Server) handleSetupStatus(c *gin.Context) {
	us, err := s.um.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"setup_needed": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"setup_needed": len(us) == 0,
		"user_count":   len(us),
	})
}

// POST /api/v1/setup — no auth required, only works when no users exist.
// Body: {"username":"admin","password":"..."}
// Creates the first admin user and returns a JWT so the portal can log in immediately.
func (s *Server) handleSetup(c *gin.Context) {
	// Guard: refuse if any users already exist
	us, err := s.um.List(c.Request.Context())
	if err == nil && len(us) > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "setup already completed"})
		return
	}

	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	u, err := s.um.Create(ctx, body.Username, body.Password, "", users.RoleAdmin, "setup")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.al.Log(ctx, u.ID, u.Username, "setup_complete", "user", u.ID, u.Username, c.ClientIP(), "first admin created")
	s.log.Info().Str("username", u.Username).Msg("initial admin account created via setup portal")

	c.JSON(http.StatusCreated, gin.H{"ok": true, "user": u})
}

func (s *Server) handleMe(c *gin.Context) {
	if raw, exists := c.Get(string(ctxClaims)); exists {
		if claims, ok := raw.(*users.Claims); ok {
			u, err := s.um.Get(c.Request.Context(), claims.Subject)
			if err == nil {
				c.JSON(http.StatusOK, u)
				return
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"username": "api-key", "role": "admin"})
}

// ─── Admin: User management ───────────────────────────────────────────────────

// GET /api/v1/admin/users
func (s *Server) handleAdminListUsers(c *gin.Context) {
	us, err := s.um.List(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": us, "total": len(us)})
}

// POST /api/v1/admin/users
// Body: {"username":"alice","password":"...","email":"...","role":"analyst"}
func (s *Server) handleAdminCreateUser(c *gin.Context) {
	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Email    string `json:"email"`
		Role     string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID, actorName := currentUser(c)
	u, err := s.um.Create(c.Request.Context(), body.Username, body.Password, body.Email, body.Role, actorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.al.Log(c.Request.Context(), actorID, actorName, "create_user", "user", u.ID, u.Username, c.ClientIP(), "role="+body.Role)
	c.JSON(http.StatusCreated, u)
}

// GET /api/v1/admin/users/:id
func (s *Server) handleAdminGetUser(c *gin.Context) {
	u, err := s.um.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, u)
}

// PATCH /api/v1/admin/users/:id
// Body: {"email":"...","role":"...","enabled":true}
func (s *Server) handleAdminUpdateUser(c *gin.Context) {
	u, err := s.um.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}

	var body struct {
		Email   *string `json:"email"`
		Role    *string `json:"role"`
		Enabled *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := u.Email
	role := u.Role
	enabled := u.Enabled
	if body.Email != nil   { email   = *body.Email   }
	if body.Role != nil    { role    = *body.Role    }
	if body.Enabled != nil { enabled = *body.Enabled }

	if err := s.um.Update(c.Request.Context(), u.ID, email, role, enabled); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "update_user", "user", u.ID, u.Username, c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/v1/admin/users/:id
func (s *Server) handleAdminDeleteUser(c *gin.Context) {
	id := c.Param("id")

	// Prevent self-deletion
	actorID, actorName := currentUser(c)
	if actorID == id {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete your own account"})
		return
	}

	u, err := s.um.Get(c.Request.Context(), id)
	if err != nil {
		s.jsonError(c, err)
		return
	}

	if err := s.um.Delete(c.Request.Context(), id); err != nil {
		s.jsonError(c, err)
		return
	}

	s.al.Log(c.Request.Context(), actorID, actorName, "delete_user", "user", id, u.Username, c.ClientIP(), "")
	c.Status(http.StatusNoContent)
}

// POST /api/v1/admin/users/:id/reset-password
// Body: {"password":"new-password"}
func (s *Server) handleAdminResetPassword(c *gin.Context) {
	var body struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := c.Param("id")
	u, err := s.um.Get(c.Request.Context(), id)
	if err != nil {
		s.jsonError(c, err)
		return
	}

	if err := s.um.ChangePassword(c.Request.Context(), id, body.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "reset_password", "user", id, u.Username, c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Admin: Audit log ─────────────────────────────────────────────────────────

// GET /api/v1/admin/audit?limit=100
func (s *Server) handleAuditLog(c *gin.Context) {
	limit := intQuery(c, "limit", 100)
	entries, err := s.al.List(c.Request.Context(), limit)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries, "total": len(entries)})
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

	// ?range=1h|6h|24h|7d — default 24h
	sinceDur := parseDashRange(c.Query("range"))
	sinceTime := time.Now().Add(-sinceDur)

	agents, _ := s.store.ListAgents(ctx)
	online := 0
	for _, a := range agents {
		if a.IsOnline {
			online++
		}
	}

	alertStats, _ := s.store.AlertStats(ctx)
	recentAlerts, _ := s.store.QueryAlerts(ctx, store.QueryAlertsParams{
		Status: "OPEN", Severity: 3, Limit: 10,
	})
	since24h := sinceTime
	eventCount, _ := s.store.CountEvents(ctx, "", since24h)

	c.JSON(http.StatusOK, gin.H{
		"agents_total":  len(agents),
		"agents_online": online,
		"events_24h":    eventCount,
		"alert_stats":   alertStats,
		"recent_alerts": recentAlerts,
		"range":         c.Query("range"),
		"since":         sinceTime,
	})
}

// parseDashRange converts a range query param to a time.Duration.
func parseDashRange(r string) time.Duration {
	switch r {
	case "1h":  return time.Hour
	case "6h":  return 6 * time.Hour
	case "7d":  return 7 * 24 * time.Hour
	default:    return 24 * time.Hour // "24h" or empty
	}
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

// PATCH /api/v1/agents/:id — update tags, env label, notes
func (s *Server) handleUpdateAgent(c *gin.Context) {
	var body struct {
		Tags  []string `json:"tags"`
		Env   string   `json:"env"`
		Notes string   `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.store.UpdateAgentTags(c.Request.Context(),
		c.Param("id"), body.Env, body.Notes, body.Tags); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
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
	if pid := c.Query("pid"); pid != "" {
		p.PID = pid
	}
	if hn := c.Query("hostname"); hn != "" {
		p.Hostname = hn
	}
	if aid := c.Query("alert_id"); aid != "" {
		p.AlertID = aid
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

// ─── Threat Hunting ───────────────────────────────────────────────────────────

func (s *Server) handleHunt(c *gin.Context) {
	var body struct {
		Query string `json:"query" binding:"required"`
		Limit int    `json:"limit"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Limit <= 0 || body.Limit > 1000 {
		body.Limit = 100
	}
	events, total, err := s.store.HuntQuery(c.Request.Context(), body.Query, body.Limit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": total, "query": body.Query})
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

func (s *Server) handleGetAlertEvents(c *gin.Context) {
	events, err := s.store.GetAlertEvents(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
}

func (s *Server) handleInjectEvent(c *gin.Context) {
	var body struct {
		EventType string      `json:"event_type" binding:"required"`
		Payload   interface{} `json:"payload"    binding:"required"`
		Hostname  string      `json:"hostname"`
		AgentID   string      `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payloadBytes, err := json.Marshal(body.Payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload: " + err.Error()})
		return
	}

	hostname := body.Hostname
	if hostname == "" { hostname = "test-injection" }
	agentID  := body.AgentID
	if agentID  == "" { agentID  = "test-injection" }

	ev := &models.Event{
		ID:        "evt-inject-" + uuid.New().String(),
		AgentID:   agentID,
		Hostname:  hostname,
		EventType: body.EventType,
		Timestamp: time.Now(),
		Payload:   json.RawMessage(payloadBytes),
	}

	ctx := c.Request.Context()
	if err := s.store.InsertEvent(ctx, ev); err != nil {
		s.jsonError(c, err)
		return
	}

	firedAlerts := s.engine.EvaluateAndCollect(ctx, ev)
	for _, alert := range firedAlerts {
		_ = s.store.InsertAlert(ctx, alert)
	}

	c.JSON(http.StatusOK, gin.H{
		"event":        ev,
		"alerts_fired": firedAlerts,
		"matched":      len(firedAlerts) > 0,
	})
}

// handleGetAlertTimeline returns all events from the alert's agent in
// the window_minutes before/after the alert's first_seen timestamp.
//   GET /api/v1/alerts/:id/timeline?window_minutes=30
func (s *Server) handleGetAlertTimeline(c *gin.Context) {
	ctx := c.Request.Context()
	alert, err := s.store.GetAlert(ctx, c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	window := time.Duration(intQuery(c, "window_minutes", 30)) * time.Minute
	before := alert.FirstSeen.Add(-window)
	after  := alert.FirstSeen.Add(+window)
	events, err := s.store.QueryEvents(ctx, store.QueryEventsParams{
		AgentID: alert.AgentID, Since: &before, Until: &after, Limit: 500,
	})
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"alert":        alert,
		"events":       events,
		"total":        len(events),
		"window_start": before,
		"window_end":   after,
	})
}

// ─── SSE Event Stream ─────────────────────────────────────────────────────────

// GET /api/v1/events/stream — real-time SSE feed of all incoming events.
// Optional filters: ?event_type=NET_CONNECT  ?agent_id=<id>
func (s *Server) handleEventStream(c *gin.Context) {
	if s.sse == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "SSE broker not initialised"})
		return
	}
	s.sse.Handler()(c)
}

// ─── Suppression Rules ───────────────────────────────────────────────────────

// GET /api/v1/suppressions
func (s *Server) handleListSuppressions(c *gin.Context) {
	sups, err := s.store.ListSuppressions(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"suppressions": sups, "total": len(sups)})
}

// POST /api/v1/suppressions
func (s *Server) handleCreateSuppression(c *gin.Context) {
	var body struct {
		Name        string      `json:"name"        binding:"required"`
		Description string      `json:"description"`
		Enabled     bool        `json:"enabled"`
		EventTypes  []string    `json:"event_types" binding:"required"`
		Conditions  interface{} `json:"conditions"`
		Author      string      `json:"author"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	raw, _ := marshalToRaw(body.Conditions)
	r := &models.SuppressionRule{
		ID:          "sup-" + uuid.New().String(),
		Name:        body.Name,
		Description: body.Description,
		Enabled:     body.Enabled,
		EventTypes:  pq.StringArray(body.EventTypes),
		Conditions:  raw,
		Author:      body.Author,
	}
	if r.Author == "" {
		r.Author = "api"
	}
	if err := s.store.UpsertSuppression(c.Request.Context(), r); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	configver.Bump()
	c.JSON(http.StatusCreated, r)
}

// PUT /api/v1/suppressions/:id
func (s *Server) handleUpdateSuppression(c *gin.Context) {
	existing, err := s.store.GetSuppression(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	var body struct {
		Name        *string     `json:"name"`
		Description *string     `json:"description"`
		Enabled     *bool       `json:"enabled"`
		EventTypes  []string    `json:"event_types"`
		Conditions  interface{} `json:"conditions"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name        != nil { existing.Name        = *body.Name }
	if body.Description != nil { existing.Description = *body.Description }
	if body.Enabled     != nil { existing.Enabled     = *body.Enabled }
	if body.EventTypes  != nil { existing.EventTypes  = pq.StringArray(body.EventTypes) }
	if body.Conditions  != nil {
		if raw, err := marshalToRaw(body.Conditions); err == nil {
			existing.Conditions = raw
		}
	}
	if err := s.store.UpsertSuppression(c.Request.Context(), existing); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	configver.Bump()
	c.JSON(http.StatusOK, existing)
}

// DELETE /api/v1/suppressions/:id
func (s *Server) handleDeleteSuppression(c *gin.Context) {
	if err := s.store.DeleteSuppression(c.Request.Context(), c.Param("id")); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	configver.Bump()
	c.Status(http.StatusNoContent)
}

// ─── Rule backtest ────────────────────────────────────────────────────────────

// POST /api/v1/rules/:id/backtest?window_hours=168
// Runs the rule's conditions against up to 10k historical events and returns
// match count, match rate, and up to 5 sample matches.
func (s *Server) handleBacktestRule(c *gin.Context) {
	ctx := c.Request.Context()
	rule, err := s.store.GetRule(ctx, c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	window := intQuery(c, "window_hours", 168)

	total, events, err := s.store.BacktestRule(ctx, store.BacktestParams{
		EventTypes:  []string(rule.EventTypes),
		Conditions:  rule.Conditions,
		WindowHours: window,
	})
	if err != nil {
		s.jsonError(c, err)
		return
	}

	// Run conditions client-side (reuse engine logic via a mini eval loop)
	matched := 0
	var samples []models.Event
	for _, ev := range events {
		var payload map[string]interface{}
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			continue
		}
		dst := make(map[string]interface{})
		for k, v := range payload { dst[k] = v }
		flattenForBacktest(payload, "", dst)

		var conds []models.RuleCondition
		if err := json.Unmarshal(rule.Conditions, &conds); err != nil {
			continue
		}
		if backTestMatchAll(dst, conds) {
			matched++
			if len(samples) < 5 {
				samples = append(samples, ev)
			}
		}
	}

	matchRate := 0.0
	if total > 0 {
		matchRate = float64(matched) / float64(total) * 100
	}

	c.JSON(http.StatusOK, models.BacktestResult{
		RuleID:       rule.ID,
		TotalScanned: total,
		Matched:      matched,
		MatchRate:    matchRate,
		WindowHours:  window,
		Samples:      samples,
	})
}

// flattenForBacktest is a standalone flatten used in the backtest handler.
func flattenForBacktest(src map[string]interface{}, prefix string, dst map[string]interface{}) {
	for k, v := range src {
		key := k
		if prefix != "" { key = prefix + "." + k }
		switch val := v.(type) {
		case map[string]interface{}:
			flattenForBacktest(val, key, dst)
		default:
			dst[key] = val
		}
	}
}

// backTestMatchAll checks all conditions against a flattened payload map.
func backTestMatchAll(payload map[string]interface{}, conds []models.RuleCondition) bool {
	for _, c := range conds {
		act, ok := payload[c.Field]
		if !ok { return false }
		switch c.Op {
		case "eq":       if fmt.Sprintf("%v", act) != fmt.Sprintf("%v", c.Value) { return false }
		case "ne":       if fmt.Sprintf("%v", act) == fmt.Sprintf("%v", c.Value) { return false }
		case "contains": if !strings.Contains(fmt.Sprintf("%v", act), fmt.Sprintf("%v", c.Value)) { return false }
		case "startswith": if !strings.HasPrefix(fmt.Sprintf("%v", act), fmt.Sprintf("%v", c.Value)) { return false }
		case "in":
			var vals []string
			switch v := c.Value.(type) {
			case []interface{}: for _, s := range v { vals = append(vals, fmt.Sprintf("%v", s)) }
			case []string: vals = v
			}
			found := false
			for _, v := range vals { if v == fmt.Sprintf("%v", act) { found = true; break } }
			if !found { return false }
		case "regex":
			if matched, err := regexp.MatchString(fmt.Sprintf("%v", c.Value), fmt.Sprintf("%v", act)); err != nil || !matched { return false }
		default: return false
		}
	}
	return true
}

// ─── LLM Alert Explanation ───────────────────────────────────────────────────

// POST /api/v1/alerts/:id/explain
// Sends the alert + triggering events to Ollama and returns a plain-English explanation.
// Response is cached in the alert notes field if it was empty.
func (s *Server) handleExplainAlert(c *gin.Context) {
	if s.llm == nil || !s.llm.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "AI not enabled — configure an AI provider in Settings",
		})
		return
	}
	ctx := c.Request.Context()
	alert, err := s.store.GetAlert(ctx, c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	events, err := s.store.GetAlertEvents(ctx, c.Param("id"))
	if err != nil {
		events = nil // non-fatal
	}
	explanation, err := s.llm.ExplainAlert(ctx, alert, events)
	if err != nil {
		s.log.Warn().Err(err).Str("alert", alert.ID).Msg("LLM explain failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "LLM request failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"alert_id":    alert.ID,
		"explanation": explanation,
		"model":       s.llm.ModelName(),
		"provider":    s.llm.ProviderName(),
	})
}

// ─── Live Response ────────────────────────────────────────────────────────────

func (s *Server) handleLRAgents(c *gin.Context) {
	agents := s.lr.ConnectedAgents()
	c.JSON(http.StatusOK, gin.H{"agents": agents, "total": len(agents)})
}

func (s *Server) handleLRCommand(c *gin.Context) {
	var body struct {
		AgentID string   `json:"agent_id" binding:"required"`
		Action  string   `json:"action" binding:"required"`
		Args    []string `json:"args"`
		Timeout int      `json:"timeout"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !s.lr.IsConnected(body.AgentID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not connected for live response"})
		return
	}
	result, err := s.lr.SendCommand(c.Request.Context(), body.AgentID, body.Action, body.Args, body.Timeout)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (s *Server) handleListIncidents(c *gin.Context) {
	sev, _ := strconv.Atoi(c.Query("min_severity"))
	incidents, err := s.store.QueryIncidents(c.Request.Context(), store.QueryIncidentsParams{
		Status:   c.Query("status"),
		Severity: int16(sev),
		AgentID:  c.Query("agent_id"),
		Limit:    intQuery(c, "limit", 50),
		Offset:   intQuery(c, "offset", 0),
	})
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"incidents": incidents, "total": len(incidents)})
}

func (s *Server) handleGetIncident(c *gin.Context) {
	inc, err := s.store.GetIncident(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, inc)
}

func (s *Server) handleUpdateIncident(c *gin.Context) {
	var body struct {
		Status   string `json:"status"`
		Assignee string `json:"assignee"`
		Notes    string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.store.UpdateIncident(c.Request.Context(),
		c.Param("id"), body.Status, body.Assignee, body.Notes,
	); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) handleGetIncidentAlerts(c *gin.Context) {
	alerts, err := s.store.GetIncidentAlerts(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts, "total": len(alerts)})
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
		Name             string      `json:"name"              binding:"required"`
		Description      string      `json:"description"`
		Enabled          bool        `json:"enabled"`
		Severity         int16       `json:"severity"`
		EventTypes       []string    `json:"event_types"       binding:"required"`
		Conditions       interface{} `json:"conditions"`
		MitreIDs         []string    `json:"mitre_ids"`
		Author           string      `json:"author"`
		RuleType         string      `json:"rule_type"`
		ThresholdCount   int         `json:"threshold_count"`
		ThresholdWindowS int         `json:"threshold_window_s"`
		GroupBy          string      `json:"group_by"`
		SequenceSteps    interface{} `json:"sequence_steps"`
		SequenceWindowS  int         `json:"sequence_window_s"`
		SequenceBy       string      `json:"sequence_by"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	import_json, _ := marshalToRaw(body.Conditions)
	seqStepsJSON, _ := marshalToRaw(body.SequenceSteps)
	if seqStepsJSON == nil { seqStepsJSON = json.RawMessage("[]") }
	if body.RuleType == "" { body.RuleType = "match" }
	if body.GroupBy  == "" { body.GroupBy  = "agent_id" }
	if body.SequenceBy == "" { body.SequenceBy = "agent_id" }
	rule := &models.Rule{
		ID:               "rule-" + uuid.New().String(),
		Name:             body.Name,
		Description:      body.Description,
		Enabled:          body.Enabled,
		Severity:         body.Severity,
		EventTypes:       pq.StringArray(body.EventTypes),
		Conditions:       import_json,
		MitreIDs:         pq.StringArray(body.MitreIDs),
		Author:           body.Author,
		RuleType:         body.RuleType,
		ThresholdCount:   body.ThresholdCount,
		ThresholdWindowS: body.ThresholdWindowS,
		GroupBy:          body.GroupBy,
		SequenceSteps:    seqStepsJSON,
		SequenceWindowS:  body.SequenceWindowS,
		SequenceBy:       body.SequenceBy,
	}
	if rule.Author == "" {
		rule.Author = "api"
	}
	if err := s.store.UpsertRule(c.Request.Context(), rule); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	configver.Bump()
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) handleUpdateRule(c *gin.Context) {
	existing, err := s.store.GetRule(c.Request.Context(), c.Param("id"))
	if err != nil {
		s.jsonError(c, err)
		return
	}

	var body struct {
		Name             *string     `json:"name"`
		Description      *string     `json:"description"`
		Enabled          *bool       `json:"enabled"`
		Severity         *int16      `json:"severity"`
		EventTypes       []string    `json:"event_types"`
		Conditions       interface{} `json:"conditions"`
		MitreIDs         []string    `json:"mitre_ids"`
		RuleType         *string     `json:"rule_type"`
		ThresholdCount   *int        `json:"threshold_count"`
		ThresholdWindowS *int        `json:"threshold_window_s"`
		GroupBy          *string     `json:"group_by"`
		SequenceSteps    interface{} `json:"sequence_steps"`
		SequenceWindowS  *int        `json:"sequence_window_s"`
		SequenceBy       *string     `json:"sequence_by"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Name             != nil { existing.Name             = *body.Name             }
	if body.Description      != nil { existing.Description      = *body.Description      }
	if body.Enabled          != nil { existing.Enabled          = *body.Enabled          }
	if body.Severity         != nil { existing.Severity         = *body.Severity         }
	if body.EventTypes       != nil { existing.EventTypes       = pq.StringArray(body.EventTypes) }
	if body.MitreIDs         != nil { existing.MitreIDs         = pq.StringArray(body.MitreIDs) }
	if body.RuleType         != nil { existing.RuleType         = *body.RuleType         }
	if body.ThresholdCount   != nil { existing.ThresholdCount   = *body.ThresholdCount   }
	if body.ThresholdWindowS != nil { existing.ThresholdWindowS = *body.ThresholdWindowS }
	if body.GroupBy          != nil { existing.GroupBy          = *body.GroupBy          }
	if body.SequenceWindowS  != nil { existing.SequenceWindowS  = *body.SequenceWindowS  }
	if body.SequenceBy       != nil { existing.SequenceBy       = *body.SequenceBy       }
	if body.Conditions       != nil {
		if raw, err := marshalToRaw(body.Conditions); err == nil {
			existing.Conditions = raw
		}
	}
	if body.SequenceSteps != nil {
		if raw, err := marshalToRaw(body.SequenceSteps); err == nil {
			existing.SequenceSteps = raw
		}
	}

	if err := s.store.UpsertRule(c.Request.Context(), existing); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	configver.Bump()
	c.JSON(http.StatusOK, existing)
}

func (s *Server) handleDeleteRule(c *gin.Context) {
	if err := s.store.DeleteRule(c.Request.Context(), c.Param("id")); err != nil {
		s.jsonError(c, err)
		return
	}
	_ = s.engine.Reload(c.Request.Context())
	configver.Bump()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) handleReloadRules(c *gin.Context) {
	if err := s.engine.Reload(c.Request.Context()); err != nil {
		s.jsonError(c, err)
		return
	}
	configver.Bump()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Migration ────────────────────────────────────────────────────────────────

func (s *Server) handleMigrateExport(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", `attachment; filename="edr-export.json"`)
	c.Status(http.StatusOK)
	if err := migrate.Export(c.Request.Context(), s.store.DB(), c.Writer, s.log); err != nil {
		s.log.Error().Err(err).Msg("migrate export failed mid-stream")
	}
}

func (s *Server) handleMigrateImport(c *gin.Context) {
	result, err := migrate.Import(c.Request.Context(), s.store.DB(), c.Request.Body, s.log)
	if err != nil {
		s.log.Error().Err(err).Msg("migrate import failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "result": result})
}

// ─── Settings / Retention ────────────────────────────────────────────────────

// GET /api/v1/settings/retention
func (s *Server) handleGetRetention(c *gin.Context) {
	evtDays, alrtDays := s.store.GetRetentionDays(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"events_days": evtDays,
		"alerts_days": alrtDays,
	})
}

// POST /api/v1/settings/retention
// Body: {"events_days": 30, "alerts_days": 90}
func (s *Server) handleSetRetention(c *gin.Context) {
	var body struct {
		EventsDays int `json:"events_days"`
		AlertsDays int `json:"alerts_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	if body.EventsDays > 0 {
		if err := s.store.SetSetting(ctx, "retention_events_days",
			strconv.Itoa(body.EventsDays)); err != nil {
			s.jsonError(c, err); return
		}
	}
	if body.AlertsDays > 0 {
		if err := s.store.SetSetting(ctx, "retention_alerts_days",
			strconv.Itoa(body.AlertsDays)); err != nil {
			s.jsonError(c, err); return
		}
	}
	actorID, actorName := currentUser(c)
	s.al.Log(ctx, actorID, actorName, "update_retention", "settings", "", "",
		c.ClientIP(), fmt.Sprintf("events=%dd alerts=%dd", body.EventsDays, body.AlertsDays))
	c.JSON(http.StatusOK, gin.H{"ok": true,
		"events_days": body.EventsDays, "alerts_days": body.AlertsDays})
}

// ─── API key handlers ─────────────────────────────────────────────────────────

func (s *Server) handleListKeys(c *gin.Context) {
	keys, err := s.keys.List(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

func (s *Server) handleCreateKey(c *gin.Context) {
	var body struct {
		Name      string  `json:"name"       binding:"required"`
		ExpiresAt *string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var expiresAt *time.Time
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *body.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be RFC3339"})
			return
		}
		expiresAt = &t
	}

	actorID, actorName := currentUser(c)
	result, err := s.keys.Create(c.Request.Context(), body.Name, actorID, expiresAt)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	s.al.Log(c.Request.Context(), actorID, actorName, "create_key", "api_key", result.Key.ID, body.Name, c.ClientIP(), "")
	c.JSON(http.StatusCreated, result)
}

func (s *Server) handleRevokeKey(c *gin.Context) {
	id := c.Param("id")
	if err := s.keys.Revoke(c.Request.Context(), id); err != nil {
		s.jsonError(c, err)
		return
	}
	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "revoke_key", "api_key", id, "", c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) handleDeleteKey(c *gin.Context) {
	id := c.Param("id")
	if err := s.keys.Delete(c.Request.Context(), id); err != nil {
		s.jsonError(c, err)
		return
	}
	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "delete_key", "api_key", id, "", c.ClientIP(), "")
	c.Status(http.StatusNoContent)
}

// ─── Process Tree ─────────────────────────────────────────────────────────────

// GET /api/v1/processes/:pid/tree?agent_id=xxx&depth=5
func (s *Server) handleGetProcessTree(c *gin.Context) {
	pidStr := c.Param("pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pid"})
		return
	}
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}
	depth := intQuery(c, "depth", 5)
	if depth > 20 {
		depth = 20
	}

	tree, err := s.store.GetProcessTree(c.Request.Context(), agentID, pid, depth)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tree": tree, "pid": pid, "agent_id": agentID})
}

// ─── Browser Navigation Tree ──────────────────────────────────────────────────

// GET /api/v1/browser/tree?agent_id=X&since=Y&until=Z&tab_id=N
func (s *Server) handleGetBrowserTree(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	now := time.Now()
	since := now.Add(-1 * time.Hour)
	until := now

	if v := c.Query("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}
	if v := c.Query("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			until = t
		}
	}

	tabID := intQuery(c, "tab_id", 0)

	tree, err := s.store.GetBrowserTree(c.Request.Context(), agentID, since, until, tabID)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tree": tree, "agent_id": agentID})
}

// GET /api/v1/browser/tabs?agent_id=X&since=Y
func (s *Server) handleListBrowserTabs(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	if v := c.Query("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}

	tabs, err := s.store.GetBrowserTabs(c.Request.Context(), agentID, since)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tabs": tabs})
}

// ─── LLM / AI Settings ────────────────────────────────────────────────────────

// GET /api/v1/settings/llm
func (s *Server) handleGetLLMSettings(c *gin.Context) {
	cfg := s.llm.GetConfig()
	c.JSON(http.StatusOK, cfg)
}

// POST /api/v1/settings/llm
func (s *Server) handleSetLLMSettings(c *gin.Context) {
	var body struct {
		Provider string `json:"provider" binding:"required"` // ollama, openai, anthropic, gemini
		Model    string `json:"model"`
		BaseURL  string `json:"base_url"`
		APIKey   string `json:"api_key"`
		Enabled  bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate provider name
	validProviders := map[string]bool{"ollama": true, "openai": true, "anthropic": true, "gemini": true}
	if !validProviders[body.Provider] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider, must be: ollama, openai, anthropic, gemini"})
		return
	}

	// Save each setting to DB
	ctx := c.Request.Context()
	s.store.SetSetting(ctx, "llm_provider", body.Provider)
	s.store.SetSetting(ctx, "llm_model", body.Model)
	s.store.SetSetting(ctx, "llm_base_url", body.BaseURL)
	if body.APIKey != "" && body.APIKey != "••••" {
		s.store.SetSetting(ctx, "llm_api_key", body.APIKey)
	}
	if body.Enabled {
		s.store.SetSetting(ctx, "llm_enabled", "true")
	} else {
		s.store.SetSetting(ctx, "llm_enabled", "false")
	}

	// Reconfigure the LLM client with new settings
	s.llm.Configure(llm.Config{
		Provider: body.Provider,
		Model:    body.Model,
		BaseURL:  body.BaseURL,
		APIKey:   body.APIKey,
		Enabled:  body.Enabled,
	})

	// If API key wasn't sent (masked), reload from DB
	if body.APIKey == "" || body.APIKey == "••••" {
		apiKey := s.store.GetSetting(ctx, "llm_api_key", "")
		s.llm.Configure(llm.Config{
			Provider: body.Provider,
			Model:    body.Model,
			BaseURL:  body.BaseURL,
			APIKey:   apiKey,
			Enabled:  body.Enabled,
		})
	}

	// Audit log
	actorID, actorName := currentUser(c)
	s.al.Log(ctx, actorID, actorName, "update_llm_settings", "settings", "", "",
		c.ClientIP(), fmt.Sprintf("provider=%s model=%s", body.Provider, body.Model))

	c.JSON(http.StatusOK, gin.H{"ok": true, "provider": body.Provider, "model": body.Model})
}

// POST /api/v1/settings/llm/test
func (s *Server) handleTestLLM(c *gin.Context) {
	// TestConnection bypasses the Enabled flag so users can verify
	// connectivity before enabling the provider.
	explanation, err := s.llm.TestConnection(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"provider": s.llm.ProviderName(),
		"model":    s.llm.ModelName(),
		"response": explanation,
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

func TraceGuardMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

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

func prometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip the prometheus metrics endpoint itself to avoid recursion.
		if c.Request.URL.Path == "/metrics/prometheus" {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		path := c.FullPath() // use route pattern, not actual path, to avoid high cardinality
		if path == "" {
			path = "unmatched"
		}
		elapsed := time.Since(start).Seconds()

		metrics.APIRequestDuration.WithLabelValues(c.Request.Method, path, status).Observe(elapsed)
		metrics.APIRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
	}
}

// ─── Package Inventory & Vulnerability Handlers ───────────────────────────────

// GET /api/v1/agents/:id/packages
func (s *Server) handleListAgentPackages(c *gin.Context) {
	agentID := c.Param("id")
	limit := intQuery(c, "limit", 500)
	offset := intQuery(c, "offset", 0)

	pkgs, err := s.store.ListAgentPackages(c.Request.Context(), agentID, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"packages": pkgs, "total": len(pkgs)})
}

// POST /api/v1/agents/:id/scan-packages
func (s *Server) handleScanPackages(c *gin.Context) {
	agentID := c.Param("id")
	if s.lr == nil || !s.lr.IsConnected(agentID) {
		c.JSON(http.StatusOK, gin.H{"status": "agent not connected for live response", "agent_id": agentID, "packages": 0})
		return
	}

	// Send scan command and WAIT for the result (synchronous — up to 60s).
	result, err := s.lr.SendCommand(c.Request.Context(), agentID, "scan_packages", nil, 60)
	if err != nil {
		s.log.Warn().Err(err).Str("agent", agentID).Msg("package scan failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed: " + err.Error()})
		return
	}

	// Parse the tab-delimited output (name\tversion\tarch per line).
	output := ""
	if result != nil {
		output = result.Stdout
	}

	lines := strings.Split(output, "\n")
	var pkgs []models.AgentPackage
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		pkg := models.AgentPackage{
			AgentID: agentID,
			Name:    parts[0],
			Version: parts[1],
		}
		if len(parts) >= 3 {
			pkg.Arch = parts[2]
		}
		pkgs = append(pkgs, pkg)
	}

	if len(pkgs) > 0 {
		if err := s.store.UpsertAgentPackages(c.Request.Context(), agentID, pkgs); err != nil {
			s.log.Error().Err(err).Str("agent", agentID).Msg("failed to store scanned packages")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store packages"})
			return
		}
	}

	s.log.Info().Str("agent", agentID).Int("packages", len(pkgs)).Msg("on-demand package scan complete")
	c.JSON(http.StatusOK, gin.H{"status": "scan complete", "agent_id": agentID, "packages": len(pkgs)})
}

// GET /api/v1/agents/:id/vulnerabilities
func (s *Server) handleListAgentVulns(c *gin.Context) {
	agentID := c.Param("id")
	limit := intQuery(c, "limit", 50)
	offset := intQuery(c, "offset", 0)

	vulns, err := s.store.QueryVulnerabilities(c.Request.Context(), agentID, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}

	stats, err := s.store.GetVulnStats(c.Request.Context(), agentID)
	if err != nil {
		s.jsonError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"vulnerabilities": vulns,
		"total":           len(vulns),
		"stats":           stats,
	})
}

// GET /api/v1/vulnerabilities
func (s *Server) handleListVulnerabilities(c *gin.Context) {
	agentID := c.Query("agent_id")
	severity := c.Query("severity")
	limit := intQuery(c, "limit", 50)
	offset := intQuery(c, "offset", 0)

	vulns, err := s.store.QueryVulnerabilitiesFiltered(c.Request.Context(), agentID, severity, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"vulnerabilities": vulns, "total": len(vulns)})
}

// ─── CVE Cache ───────────────────────────────────────────────────────────────

// SetCVEFetcher injects the CVE cache fetcher after construction.
func (s *Server) SetCVEFetcher(f *cvecache.Fetcher) {
	s.cveFetcher = f
}

// GET /api/v1/cve/:id
func (s *Server) handleGetCVE(c *gin.Context) {
	cveID := strings.ToUpper(c.Param("id"))
	if !strings.HasPrefix(cveID, "CVE-") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CVE ID format"})
		return
	}
	if s.cveFetcher == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "CVE lookup not configured"})
		return
	}
	detail, err := s.cveFetcher.Lookup(c.Request.Context(), cveID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// ─── IOC Handlers ─────────────────────────────────────────────────────────────

// GET /api/v1/iocs
func (s *Server) handleListIOCs(c *gin.Context) {
	iocType := c.Query("type")
	source := c.Query("source")
	enabledOnly := c.Query("enabled") == "true"
	limit := intQuery(c, "limit", 100)
	offset := intQuery(c, "offset", 0)

	iocs, err := s.store.ListIOCs(c.Request.Context(), iocType, source, enabledOnly, limit, offset)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"iocs": iocs, "total": len(iocs)})
}

// GET /api/v1/iocs/stats
func (s *Server) handleIOCStats(c *gin.Context) {
	stats, err := s.store.IOCStats(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, stats)
}

// GET /api/v1/iocs/:id
func (s *Server) handleGetIOC(c *gin.Context) {
	id := c.Param("id")
	ioc, err := s.store.GetIOC(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IOC not found"})
		return
	}
	c.JSON(http.StatusOK, ioc)
}

// POST /api/v1/iocs
func (s *Server) handleCreateIOC(c *gin.Context) {
	var req struct {
		Type        string   `json:"type" binding:"required"`
		Value       string   `json:"value" binding:"required"`
		Source      string   `json:"source"`
		Severity    int16    `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate IOC type.
	validTypes := map[string]bool{"ip": true, "domain": true, "hash_sha256": true, "hash_md5": true}
	if !validTypes[req.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IOC type; must be ip, domain, hash_sha256, or hash_md5"})
		return
	}

	source := req.Source
	if source == "" {
		source = "manual"
	}
	sev := req.Severity
	if sev == 0 {
		sev = 3 // HIGH by default
	}

	ioc := &models.IOC{
		ID:          "ioc-" + uuid.New().String(),
		Type:        req.Type,
		Value:       strings.ToLower(strings.TrimSpace(req.Value)),
		Source:      source,
		Severity:    sev,
		Description: req.Description,
		Tags:        req.Tags,
		Enabled:     true,
		ExpiresAt:   req.ExpiresAt,
		CreatedAt:   time.Now(),
	}

	if err := s.store.InsertIOC(c.Request.Context(), ioc); err != nil {
		s.jsonError(c, err)
		return
	}

	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "ioc_create", "ioc", ioc.ID, ioc.Value, c.ClientIP(), fmt.Sprintf("type=%s source=%s", ioc.Type, ioc.Source))
	c.JSON(http.StatusCreated, ioc)
}

// POST /api/v1/iocs/bulk
func (s *Server) handleBulkImportIOCs(c *gin.Context) {
	var req struct {
		IOCs []struct {
			Type        string     `json:"type" binding:"required"`
			Value       string     `json:"value" binding:"required"`
			Source      string     `json:"source"`
			Severity    int16      `json:"severity"`
			Description string     `json:"description"`
			Tags        []string   `json:"tags"`
			ExpiresAt   *time.Time `json:"expires_at"`
		} `json:"iocs" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.IOCs) > 10000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 10000 IOCs per batch"})
		return
	}

	validTypes := map[string]bool{"ip": true, "domain": true, "hash_sha256": true, "hash_md5": true}
	iocs := make([]models.IOC, 0, len(req.IOCs))
	for _, r := range req.IOCs {
		if !validTypes[r.Type] {
			continue
		}
		source := r.Source
		if source == "" {
			source = "manual"
		}
		sev := r.Severity
		if sev == 0 {
			sev = 3
		}
		iocs = append(iocs, models.IOC{
			ID:          "ioc-" + uuid.New().String(),
			Type:        r.Type,
			Value:       strings.ToLower(strings.TrimSpace(r.Value)),
			Source:      source,
			Severity:    sev,
			Description: r.Description,
			Tags:        r.Tags,
			Enabled:     true,
			ExpiresAt:   r.ExpiresAt,
			CreatedAt:   time.Now(),
		})
	}

	count, err := s.store.InsertIOCBatch(c.Request.Context(), iocs)
	if err != nil {
		s.jsonError(c, err)
		return
	}

	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "ioc_bulk_import", "iocs", "", "", c.ClientIP(), fmt.Sprintf("imported %d IOCs", count))
	c.JSON(http.StatusOK, gin.H{"imported": count, "total_submitted": len(req.IOCs)})
}

// DELETE /api/v1/iocs/:id
func (s *Server) handleDeleteIOC(c *gin.Context) {
	id := c.Param("id")
	if err := s.store.DeleteIOC(c.Request.Context(), id); err != nil {
		s.jsonError(c, err)
		return
	}
	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "ioc_delete", "ioc", id, "", c.ClientIP(), "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// GET /api/v1/iocs/feeds
func (s *Server) handleListFeeds(c *gin.Context) {
	if s.iocSync == nil {
		c.JSON(http.StatusOK, gin.H{"feeds": []interface{}{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"feeds": s.iocSync.ListFeeds()})
}

// POST /api/v1/iocs/feeds/sync — trigger immediate sync of all feeds (or one by name)
func (s *Server) handleSyncFeeds(c *gin.Context) {
	if s.iocSync == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "IOC feed syncer not configured"})
		return
	}
	var req struct {
		Feed string `json:"feed"` // optional: sync only this feed
	}
	_ = c.ShouldBindJSON(&req)

	ctx := c.Request.Context()
	if req.Feed != "" {
		result, err := s.iocSync.SyncFeedByName(ctx, req.Feed)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"results": []interface{}{result}})
		return
	}

	results := s.iocSync.SyncAllNow(ctx)
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// GET /api/v1/iocs/sources — IOC counts grouped by source with time filter
func (s *Server) handleIOCSourceStats(c *gin.Context) {
	period := c.DefaultQuery("period", "all")
	var since time.Time
	switch period {
	case "day":
		since = time.Now().AddDate(0, 0, -1)
	case "week":
		since = time.Now().AddDate(0, 0, -7)
	case "month":
		since = time.Now().AddDate(0, -1, 0)
	default:
		since = time.Time{} // epoch — all data
	}

	stats, err := s.store.IOCStatsBySource(c.Request.Context(), since)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	overall, err := s.store.IOCStats(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sources": stats, "overall": overall, "period": period})
}

// DELETE /api/v1/iocs/source/:source
func (s *Server) handleDeleteIOCsBySource(c *gin.Context) {
	source := c.Param("source")
	count, err := s.store.DeleteIOCsBySource(c.Request.Context(), source)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	actorID, actorName := currentUser(c)
	s.al.Log(c.Request.Context(), actorID, actorName, "ioc_delete_source", "iocs", source, "", c.ClientIP(), fmt.Sprintf("deleted %d IOCs", count))
	c.JSON(http.StatusOK, gin.H{"deleted": count, "source": source})
}
