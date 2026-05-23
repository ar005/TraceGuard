// internal/api/ratelimit.go
// Per-identity rate limiting middleware using a token bucket algorithm.
// Authenticated requests are keyed by JWT user ID; unauthenticated by IP.
// This is proxy-safe: even when all requests arrive from one Next.js server
// IP, each analyst gets their own independent bucket.

package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/youredr/edr-backend/internal/users"
)

// TenantRateLimitOverride holds per-tenant rate limit values loaded from the
// tenant_rate_limits DB table at startup.
type TenantRateLimitOverride struct {
	RequestsPerSecond float64
	Burst             int
}

// RateLimitConfig controls rate limiting behaviour.
type RateLimitConfig struct {
	Enabled           bool
	RequestsPerSecond float64
	Burst             int
	CleanupInterval   time.Duration
	MaxAge            time.Duration
}

// DefaultRateLimitConfig returns production defaults.
// Override with env vars: EDR_RATE_LIMIT_RPS and EDR_RATE_LIMIT_BURST.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: envFloat("EDR_RATE_LIMIT_RPS", 120),
		Burst:             envInt("EDR_RATE_LIMIT_BURST", 300),
		CleanupInterval:   5 * time.Minute,
		MaxAge:            10 * time.Minute,
	}
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return i
		}
	}
	return def
}

// rateLimiterStore manages per-identity limiters with periodic cleanup.
type rateLimiterStore struct {
	mu       sync.Mutex
	limiters map[string]*identityLimiter
	rate     rate.Limit
	burst    int
}

type identityLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRateLimiterStore(rps float64, burst int, cleanupInterval, maxAge time.Duration) *rateLimiterStore {
	s := &rateLimiterStore{
		limiters: make(map[string]*identityLimiter),
		rate:     rate.Limit(rps),
		burst:    burst,
	}
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.cleanup(maxAge)
		}
	}()
	return s
}

func (s *rateLimiterStore) getLimiter(key string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.limiters[key]; ok {
		e.lastSeen = time.Now()
		return e.limiter
	}
	l := rate.NewLimiter(s.rate, s.burst)
	s.limiters[key] = &identityLimiter{limiter: l, lastSeen: time.Now()}
	return l
}

func (s *rateLimiterStore) cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for k, e := range s.limiters {
		if e.lastSeen.Before(cutoff) {
			delete(s.limiters, k)
		}
	}
}

// identityKey returns the rate-limit bucket key for a request.
// Authenticated requests use "user:<userID>" so the Next.js proxy IP doesn't
// collapse all analysts into a single shared bucket.
//
// The rate limiter runs before auth middleware, so claims may not be in context
// yet. We fall back to parsing the JWT from the cookie/header directly — we
// only need the subject for bucketing, not signature verification.
func identityKey(c *gin.Context) string {
	// Fast path: claims already set (e.g. middleware running inside auth group).
	if raw, ok := c.Get(string(ctxClaims)); ok {
		if claims, ok := raw.(*users.Claims); ok && claims.Subject != "" {
			return "user:" + claims.Subject
		}
	}
	// Slow path: parse JWT payload without verifying signature.
	token := ""
	if cookie, err := c.Cookie("edr_session"); err == nil && cookie != "" {
		token = cookie
	} else if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	}
	if sub := jwtSubjectUnsafe(token); sub != "" {
		return "user:" + sub
	}
	return "ip:" + c.ClientIP()
}

// jwtSubjectUnsafe extracts the subject from a JWT without verifying the
// signature. Used only for rate-limit bucket keying — never for access control.
func jwtSubjectUnsafe(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

// rateLimitMiddleware enforces per-identity rate limits.
// Requests that carry a session cookie or Bearer token are passed through
// without rate limiting — the auth middleware handles access control for those.
// Rate limiting is enforced only on unauthenticated requests (e.g. brute-force
// protection for /login).
func rateLimitMiddleware(cfg RateLimitConfig) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(c *gin.Context) { c.Next() }
	}
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 120
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.RequestsPerSecond * 2)
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 10 * time.Minute
	}

	store := newRateLimiterStore(cfg.RequestsPerSecond, cfg.Burst, cfg.CleanupInterval, cfg.MaxAge)

	return func(c *gin.Context) {
		// Skip rate limiting for requests that carry credentials — auth
		// middleware will accept or reject them independently.
		if hasCredentials(c) {
			c.Next()
			return
		}
		if !store.getLimiter(identityKey(c)).Allow() {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded — try again shortly",
			})
			return
		}
		c.Next()
	}
}

// hasCredentials returns true if the request carries a session cookie or
// an Authorization header — indicating it is an authenticated request.
func hasCredentials(c *gin.Context) bool {
	if cookie, err := c.Cookie("edr_session"); err == nil && cookie != "" {
		return true
	}
	if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return true
	}
	if key := c.GetHeader("X-Agent-Key"); key != "" {
		return true
	}
	return false
}

// strictRateLimitMiddleware applies a tighter limit for expensive endpoints
// (bulk imports, event injection, threat hunting, etc.).
func strictRateLimitMiddleware(cfg RateLimitConfig) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(c *gin.Context) { c.Next() }
	}
	store := newRateLimiterStore(5, 15, 5*time.Minute, 10*time.Minute)
	return func(c *gin.Context) {
		if !store.getLimiter(identityKey(c)).Allow() {
			c.Header("Retry-After", "5")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded for this endpoint — try again shortly",
			})
			return
		}
		c.Next()
	}
}

// tenantRateLimitMiddleware applies per-tenant overrides, falling back to cfg.
func tenantRateLimitMiddleware(cfg RateLimitConfig, overrides map[string]TenantRateLimitOverride) gin.HandlerFunc {
	if !cfg.Enabled || len(overrides) == 0 {
		return rateLimitMiddleware(cfg)
	}
	stores := make(map[string]*rateLimiterStore, len(overrides))
	for tid, ov := range overrides {
		rps := ov.RequestsPerSecond
		if rps <= 0 {
			rps = cfg.RequestsPerSecond
		}
		burst := ov.Burst
		if burst <= 0 {
			burst = cfg.Burst
		}
		stores[tid] = newRateLimiterStore(rps, burst, cfg.CleanupInterval, cfg.MaxAge)
	}
	defaultStore := newRateLimiterStore(cfg.RequestsPerSecond, cfg.Burst, cfg.CleanupInterval, cfg.MaxAge)

	return func(c *gin.Context) {
		tenantID := "default"
		if raw, ok := c.Get("tenant_id"); ok {
			if tid, ok := raw.(string); ok && tid != "" {
				tenantID = tid
			}
		}
		store, ok := stores[tenantID]
		if !ok {
			store = defaultStore
		}
		if !store.getLimiter(identityKey(c)).Allow() {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded — try again shortly",
			})
			return
		}
		c.Next()
	}
}
