// internal/api/sources.go
// XDR source CRUD and webhook ingest handlers.

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/youredr/edr-backend/internal/connectors"
	"github.com/youredr/edr-backend/internal/models"
)

// verifyHMACSignature returns true if HMAC-SHA256(secret, body) == sigHex.
func verifyHMACSignature(body []byte, secret, sigHex string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sigHex))
}

// handleListSources returns all xdr_sources rows.
func (s *Server) handleListSources(c *gin.Context) {
	sources, err := s.store.ListSources(c.Request.Context())
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sources": sources})
}

// handleGetSource returns one xdr_sources row.
func (s *Server) handleGetSource(c *gin.Context) {
	src, err := s.store.GetSource(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, src)
}

// handleCreateSource inserts a new xdr_sources row.
func (s *Server) handleCreateSource(c *gin.Context) {
	var in models.XdrSource
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.Config == nil {
		in.Config = json.RawMessage("{}")
	}
	created, err := s.store.CreateSource(c.Request.Context(), &in)
	if err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

// handleUpdateSource replaces mutable fields on a source.
func (s *Server) handleUpdateSource(c *gin.Context) {
	existing, err := s.store.GetSource(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := c.ShouldBindJSON(existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing.ID = c.Param("id")
	if err := s.store.UpdateSource(c.Request.Context(), existing); err != nil {
		s.jsonError(c, err)
		return
	}
	c.JSON(http.StatusOK, existing)
}

// handleDeleteSource removes a source row.
func (s *Server) handleDeleteSource(c *gin.Context) {
	if err := s.store.DeleteSource(c.Request.Context(), c.Param("id")); err != nil {
		s.jsonError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// handleGetSourceHealth returns the health of a running connector, if any.
func (s *Server) handleGetSourceHealth(c *gin.Context) {
	id := c.Param("id")
	src, err := s.store.GetSource(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	conn, buildErr := connectors.Build(src, s.log)
	if buildErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"id":     id,
			"status": "build_error",
			"error":  buildErr.Error(),
		})
		return
	}

	healthErr := conn.Health(c.Request.Context())
	status := "healthy"
	errMsg := ""
	if healthErr != nil {
		status = "unhealthy"
		errMsg = healthErr.Error()
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         id,
		"status":     status,
		"error":      errMsg,
		"error_state": src.ErrorState,
		"last_seen_at": src.LastSeenAt,
		"events_today": src.EventsToday,
	})
}

// handleWebhookIngest accepts POST payloads for a specific source_id.
// Authentication is done via per-source HMAC-SHA256 if the source config
// has a "secret" field; otherwise any POST is accepted.
func (s *Server) handleWebhookIngest(c *gin.Context) {
	sourceID := c.Param("source_id")
	src, err := s.store.GetSource(c.Request.Context(), sourceID)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	if src.Connector != "webhook" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source is not a webhook connector"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// Verify HMAC if secret is configured.
	var cfg struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(src.Config, &cfg) == nil && cfg.Secret != "" {
		sig := c.GetHeader("X-Webhook-Signature")
		if !verifyHMACSignature(body, cfg.Secret, sig) {
			c.Status(http.StatusUnauthorized)
			return
		}
	}

	// Touch stats regardless of pipeline availability.
	_ = s.store.TouchSource(c.Request.Context(), sourceID)

	// Forward to XDR pipeline if sink is wired up.
	if s.xdrSink != nil {
		ev := connectors.ParseWebhookEvent(body, sourceID)
		if err := s.xdrSink.Publish(ev); err != nil {
			s.log.Warn().Err(err).Str("source_id", sourceID).Msg("webhook sink publish failed")
		}
	}

	c.Status(http.StatusAccepted)
}

