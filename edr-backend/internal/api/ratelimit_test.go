package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func setupRateLimitRouter(cfg RateLimitConfig) *gin.Engine {
	r := gin.New()
	r.Use(rateLimitMiddleware(cfg))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRateLimitAllowsNormalTraffic(t *testing.T) {
	r := setupRateLimitRouter(RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             10,
		CleanupInterval:   time.Minute,
		MaxAge:            time.Minute,
	})

	// 10 requests should all succeed (within burst).
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, w.Code)
		}
	}
}

func TestRateLimitBlocksExcessiveTraffic(t *testing.T) {
	r := setupRateLimitRouter(RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             3,
		CleanupInterval:   time.Minute,
		MaxAge:            time.Minute,
	})

	// First 3 should succeed (burst).
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:9999"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, w.Code)
		}
	}

	// Request 4 should be rate limited.
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}

	// Check Retry-After header.
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestRateLimitPerIPIsolation(t *testing.T) {
	r := setupRateLimitRouter(RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             2,
		CleanupInterval:   time.Minute,
		MaxAge:            time.Minute,
	})

	// Exhaust IP1's burst.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.1.1.1:1000"
		r.ServeHTTP(w, req)
	}

	// IP1 should be rate limited.
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.1.1.1:1000"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("IP1 expected 429, got %d", w.Code)
	}

	// IP2 should still work — separate limiter.
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "2.2.2.2:2000"
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("IP2 expected 200, got %d", w2.Code)
	}
}

func TestRateLimitDisabled(t *testing.T) {
	r := setupRateLimitRouter(RateLimitConfig{Enabled: false})

	// Should never block, even with many requests.
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:9999"
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 (disabled), got %d", i, w.Code)
		}
	}
}

func TestRateLimitStoreCleanup(t *testing.T) {
	store := newRateLimiterStore(10, 20, time.Hour, 50*time.Millisecond)

	// Create a limiter.
	store.getLimiter("192.168.1.1")

	store.mu.RLock()
	count := len(store.limiters)
	store.mu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 limiter, got %d", count)
	}

	// Wait for it to age out.
	time.Sleep(100 * time.Millisecond)
	store.cleanup(50 * time.Millisecond)

	store.mu.RLock()
	count = len(store.limiters)
	store.mu.RUnlock()
	if count != 0 {
		t.Fatalf("expected 0 limiters after cleanup, got %d", count)
	}
}
