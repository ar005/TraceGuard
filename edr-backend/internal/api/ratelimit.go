// internal/api/ratelimit.go
// Per-IP rate limiting middleware using a token bucket algorithm.
// Each client IP gets its own limiter; stale entries are pruned periodically.

package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// TenantRateLimitOverride holds per-tenant rate limit values loaded from the
// tenant_rate_limits DB table at startup.
type TenantRateLimitOverride struct {
	RequestsPerSecond float64
	Burst             int
}

// RateLimitConfig controls rate limiting behaviour.
type RateLimitConfig struct {
	// Enabled turns rate limiting on/off.
	Enabled bool

	// RequestsPerSecond is the sustained rate (token refill rate).
	// Default: 20 requests/second per IP.
	RequestsPerSecond float64

	// Burst is the maximum number of requests allowed in a single burst.
	// Default: 40.
	Burst int

	// CleanupInterval controls how often stale limiter entries are purged.
	// Default: 5 minutes.
	CleanupInterval time.Duration

	// MaxAge is how long an idle limiter lives before being cleaned up.
	// Default: 10 minutes.
	MaxAge time.Duration
}

// DefaultRateLimitConfig returns production defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 20,
		Burst:             40,
		CleanupInterval:   5 * time.Minute,
		MaxAge:            10 * time.Minute,
	}
}

// ipLimiter tracks a per-IP rate limiter and last-seen time.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiterStore manages per-IP limiters with periodic cleanup.
type rateLimiterStore struct {
	mu       sync.RWMutex
	limiters map[string]*ipLimiter
	rate     rate.Limit
	burst    int
}

func newRateLimiterStore(rps float64, burst int, cleanupInterval, maxAge time.Duration) *rateLimiterStore {
	s := &rateLimiterStore{
		limiters: make(map[string]*ipLimiter),
		rate:     rate.Limit(rps),
		burst:    burst,
	}

	// Background cleanup of stale entries.
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.cleanup(maxAge)
		}
	}()

	return s
}

// getLimiter returns the rate limiter for an IP, creating one if needed.
func (s *rateLimiterStore) getLimiter(ip string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.limiters[ip]; ok {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	limiter := rate.NewLimiter(s.rate, s.burst)
	s.limiters[ip] = &ipLimiter{limiter: limiter, lastSeen: time.Now()}
	return limiter
}

// cleanup removes entries that haven't been seen for maxAge.
func (s *rateLimiterStore) cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, entry := range s.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(s.limiters, ip)
		}
	}
}

// rateLimitMiddleware returns Gin middleware that enforces per-IP rate limits.
func rateLimitMiddleware(cfg RateLimitConfig) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(c *gin.Context) { c.Next() }
	}

	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 20
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
		ip := c.ClientIP()
		limiter := store.getLimiter(ip)

		if !limiter.Allow() {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded — try again shortly",
			})
			return
		}

		c.Next()
	}
}

// strictRateLimitMiddleware applies a much tighter per-IP limit for expensive
// or dangerous endpoints (bulk imports, event injection, threat hunting, etc.).
// Default: 2 requests/second, burst of 5.
func strictRateLimitMiddleware() gin.HandlerFunc {
	store := newRateLimiterStore(2, 5, 5*time.Minute, 10*time.Minute)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := store.getLimiter(ip)

		if !limiter.Allow() {
			c.Header("Retry-After", "5")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded for this endpoint — try again shortly",
			})
			return
		}
		c.Next()
	}
}

// tenantRateLimitMiddleware wraps rateLimitMiddleware but applies per-tenant
// overrides when the JWT tenant_id matches a loaded override. Falls back to the
// global config for unknown tenants.
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
		if !store.getLimiter(c.ClientIP()).Allow() {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded — try again shortly",
			})
			return
		}
		c.Next()
	}
}
