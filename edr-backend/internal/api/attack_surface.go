package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/store"
)

// GET /api/v1/agents/:id/attack-surface
func (s *Server) handleGetAgentAttackSurface(c *gin.Context) {
	agentID := c.Param("id")

	snap, err := s.store.GetAgentAttackSurface(c.Request.Context(), agentID)
	if errors.Is(err, sql.ErrNoRows) {
		// Return empty surface — scanner hasn't run yet or no events
		c.JSON(http.StatusOK, gin.H{
			"agent_id":      agentID,
			"open_ports":    json.RawMessage(`[]`),
			"exposed_vulns": json.RawMessage(`[]`),
			"risk_score":    0,
			"recommendations": []string{},
			"snapshot_at":   nil,
		})
		return
	}
	if err != nil {
		s.log.Error().Err(err).Str("agent", agentID).Msg("get agent attack surface")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Derive top-3 recommendations from exposed_vulns
	var vulns []store.ExposedVuln
	_ = json.Unmarshal(snap.ExposedVulns, &vulns)
	recommendations := buildRecommendations(vulns)

	c.JSON(http.StatusOK, gin.H{
		"agent_id":        snap.AgentID,
		"open_ports":      snap.OpenPorts,
		"exposed_vulns":   snap.ExposedVulns,
		"risk_score":      snap.RiskScore,
		"recommendations": recommendations,
		"snapshot_at":     snap.SnapshotAt,
	})
}

// GET /api/v1/xdr/attack-surface?internet_only=false
func (s *Server) handleGetOrgAttackSurface(c *gin.Context) {
	internetOnly := c.Query("internet_only") == "true"

	agents, err := s.store.GetOrgAttackSurface(c.Request.Context(), internetOnly)
	if err != nil {
		s.log.Error().Err(err).Msg("get org attack surface")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if agents == nil {
		agents = []store.OrgAttackSurfaceAgent{}
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents, "total": len(agents)})
}

var sevOrder = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

func buildRecommendations(vulns []store.ExposedVuln) []string {
	// Sort by severity descending, pick top 3 distinct CVEs
	seen := map[string]bool{}
	var recs []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		for _, v := range vulns {
			if v.Severity != sev || seen[v.CveID] {
				continue
			}
			seen[v.CveID] = true
			recs = append(recs, "Patch "+v.CveID+" ("+v.Severity+") in "+v.PackageName+" — exposed on port "+itoa(v.Port))
			if len(recs) >= 3 {
				return recs
			}
		}
	}
	return recs
}

func itoa(n int) string {
	if n == 0 {
		return "unknown"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
