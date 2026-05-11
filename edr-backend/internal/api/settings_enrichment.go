package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/youredr/edr-backend/internal/enrichment"
)

// GET /api/v1/settings/enrichment
func (s *Server) handleGetEnrichmentSettings(c *gin.Context) {
	ctx := c.Request.Context()
	vtKey := s.store.GetSecretSetting(ctx, "virustotal_api_key", "")
	abuseKey := s.store.GetSecretSetting(ctx, "abuseipdb_api_key", "")
	c.JSON(http.StatusOK, gin.H{
		"vt_key_set":    vtKey != "",
		"abuse_key_set": abuseKey != "",
	})
}

// POST /api/v1/settings/enrichment
// Body: { "virustotal_api_key": "...", "abuseipdb_api_key": "..." }
func (s *Server) handleSetEnrichmentSettings(c *gin.Context) {
	var body struct {
		VTKey    string `json:"virustotal_api_key"`
		AbuseKey string `json:"abuseipdb_api_key"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	if body.VTKey != "" {
		if err := s.store.SetSecretSetting(ctx, "virustotal_api_key", body.VTKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save vt key"})
			return
		}
	}
	if body.AbuseKey != "" {
		if err := s.store.SetSecretSetting(ctx, "abuseipdb_api_key", body.AbuseKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save abuseipdb key"})
			return
		}
	}

	// Hot-swap keys on the live enricher if wired.
	if s.enricher != nil {
		vtKey := s.store.GetSecretSetting(ctx, "virustotal_api_key", "")
		abuseKey := s.store.GetSecretSetting(ctx, "abuseipdb_api_key", "")
		s.enricher.Configure(vtKey, abuseKey)
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/v1/alerts/:id/enrich  — manual re-enrichment trigger.
func (s *Server) handleEnrichAlert(c *gin.Context) {
	if s.enricher == nil || !s.enricher.HasKeys() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrichment not configured"})
		return
	}
	tid := c.GetString("tenant_id")
	id := c.Param("id")

	alert, err := s.store.GetAlert(c.Request.Context(), id, tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}

	ctx := c.Request.Context()
	events, _ := s.store.GetAlertEvents(ctx, alert.ID, tid)

	seenIPs := map[string]bool{}
	seenHashes := map[string]bool{}
	seenDomains := map[string]bool{}
	var ips, hashes, domains []string

	addIP := func(ip string) {
		if ip != "" && !seenIPs[ip] {
			seenIPs[ip] = true
			ips = append(ips, ip)
		}
	}
	addHash := func(h string) {
		if len(h) == 32 || len(h) == 40 || len(h) == 64 {
			if !seenHashes[h] {
				seenHashes[h] = true
				hashes = append(hashes, h)
			}
		}
	}
	addDomain := func(d string) {
		if d != "" && !seenDomains[d] {
			seenDomains[d] = true
			domains = append(domains, d)
		}
	}

	addIP(alert.SrcIP)
	for _, ev := range events {
		if ev.SrcIP != nil {
			addIP(*ev.SrcIP)
		}
		if ev.DstIP != nil {
			addIP(*ev.DstIP)
		}
		if len(ev.Payload) > 0 {
			var p map[string]interface{}
			if err := json.Unmarshal(ev.Payload, &p); err == nil {
				for _, field := range []string{"exe_hash", "hash_after", "hash_before"} {
					if v, ok := p[field]; ok {
						if s, ok := v.(string); ok {
							addHash(s)
						}
					}
				}
				for _, field := range []string{"dns_query", "resolved_domain", "query", "domain"} {
					if v, ok := p[field]; ok {
						if s, ok := v.(string); ok {
							addDomain(s)
						}
					}
				}
			}
		}
	}

	var results []enrichment.ObservableEnrichment
	for _, ip := range ips {
		if ti, err := s.enricher.EnrichIP(ctx, ip); ti != nil && err == nil {
			results = append(results, enrichment.ObservableEnrichment{Indicator: ip, Type: "ip", TIResult: ti})
		}
	}
	for _, h := range hashes {
		if ti, err := s.enricher.EnrichHash(ctx, h); ti != nil && err == nil {
			results = append(results, enrichment.ObservableEnrichment{Indicator: h, Type: "hash", TIResult: ti})
		}
	}
	for _, d := range domains {
		if ti, err := s.enricher.EnrichDomain(ctx, d); ti != nil && err == nil {
			results = append(results, enrichment.ObservableEnrichment{Indicator: d, Type: "domain", TIResult: ti})
		}
	}

	if len(results) > 0 {
		merged, err := enrichment.MergeObservableEnrichments(alert.Enrichments, results)
		if err == nil {
			_ = s.store.UpdateAlertEnrichments(ctx, alert.ID, tid, merged)
			alert.Enrichments = merged
		}
	}

	c.JSON(http.StatusOK, gin.H{"alert_id": id, "enrichments": alert.Enrichments, "observables_enriched": len(results)})
}
