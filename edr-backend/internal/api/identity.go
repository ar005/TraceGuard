// internal/api/identity.go — identity graph, asset inventory, and XDR event handlers.

package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ── Identity Graph ────────────────────────────────────────────────────────────

func (s *Server) handleListIdentities(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	rows, err := s.store.ListIdentities(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"identities": rows, "limit": limit, "offset": offset})
}

func (s *Server) handleTopRiskyIdentities(c *gin.Context) {
	n, _ := strconv.Atoi(c.DefaultQuery("n", "10"))
	rows, err := s.store.TopRiskyIdentities(c.Request.Context(), n)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"identities": rows})
}

func (s *Server) handleGetIdentity(c *gin.Context) {
	uid := c.Param("uid")
	rec, err := s.store.GetIdentityByUID(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity not found"})
		return
	}
	c.JSON(http.StatusOK, rec)
}

// ── Asset Inventory ───────────────────────────────────────────────────────────

func (s *Server) handleListAssets(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	assetType := c.Query("type")

	rows, err := s.store.ListAssets(c.Request.Context(), assetType, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	total, _ := s.store.AssetCount(c.Request.Context(), assetType)
	c.JSON(http.StatusOK, gin.H{"assets": rows, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) handleGetAsset(c *gin.Context) {
	id := c.Param("id")
	asset, err := s.store.GetAssetByAgentID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}
	c.JSON(http.StatusOK, asset)
}

// ── XDR Network Events ────────────────────────────────────────────────────────

func (s *Server) handleListXdrEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	sourceType := c.Query("source_type")
	sourceID := c.Query("source_id")
	eventType := c.Query("event_type")

	rows, err := s.store.ListXdrEvents(c.Request.Context(), sourceType, sourceID, eventType, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": rows, "limit": limit, "offset": offset})
}
