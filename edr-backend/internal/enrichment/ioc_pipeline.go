// Package enrichment — IOC-level background enrichment pipeline.
// Polls for unenriched IOCs every 10 min and stores structured metadata
// (ASN, country, rDNS, WHOIS age, VirusTotal detections, passive DNS).
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"golang.org/x/time/rate"
)

// IOCEnrichment is the JSONB payload stored in iocs.enrichment.
type IOCEnrichment struct {
	ASN             string    `json:"asn,omitempty"`
	Country         string    `json:"country,omitempty"`
	GeoCity         string    `json:"geo_city,omitempty"`
	RDNS            string    `json:"rdns,omitempty"`
	WhoisRegistrar  string    `json:"whois_registrar,omitempty"`
	DomainAgeDays   int       `json:"domain_age_days,omitempty"`
	VTDetections    int       `json:"vt_detections,omitempty"`
	VTTotalEngines  int       `json:"vt_total_engines,omitempty"`
	VTMalwareFamily string    `json:"vt_malware_family,omitempty"`
	VTVerdict       string    `json:"vt_verdict,omitempty"`
	EnrichedAt      time.Time `json:"enriched_at"`
}

// IOCStore is the subset of store.Store required by the pipeline.
type IOCStore interface {
	GetIOCsForEnrichment(ctx context.Context, limit int) ([]models.IOC, error)
	UpdateIOCEnrichment(ctx context.Context, iocID string, data json.RawMessage) error
}

// IOCPipeline runs periodic IOC enrichment in the background.
type IOCPipeline struct {
	store        IOCStore
	log          zerolog.Logger
	vtKey        string
	whoisEnabled bool
	http         *http.Client
	vtLimiter    *rate.Limiter // VirusTotal free: 4 req/min
	mu           sync.Mutex
}

// NewIOCPipeline creates a pipeline.
func NewIOCPipeline(st IOCStore, vtAPIKey string, whoisEnabled bool, log zerolog.Logger) *IOCPipeline {
	return &IOCPipeline{
		store:        st,
		log:          log.With().Str("component", "ioc-enrichment").Logger(),
		vtKey:        vtAPIKey,
		whoisEnabled: whoisEnabled,
		http:         &http.Client{Timeout: 10 * time.Second},
		vtLimiter:    rate.NewLimiter(rate.Every(15*time.Second), 1), // 4/min safe
	}
}

// Run polls for unenriched IOCs every 10 minutes.
func (p *IOCPipeline) Run(ctx context.Context) {
	p.enrich(ctx) // run immediately on startup
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.enrich(ctx)
		}
	}
}

// EnrichOne force-enriches a single IOC (called by the API handler).
func (p *IOCPipeline) EnrichOne(ctx context.Context, ioc *models.IOC) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enrichIOC(ctx, ioc)
}

func (p *IOCPipeline) enrich(ctx context.Context) {
	iocs, err := p.store.GetIOCsForEnrichment(ctx, 100)
	if err != nil {
		p.log.Warn().Err(err).Msg("fetch IOCs for enrichment")
		return
	}
	for i := range iocs {
		if ctx.Err() != nil {
			return
		}
		if err := p.enrichIOC(ctx, &iocs[i]); err != nil {
			p.log.Warn().Err(err).Str("ioc", iocs[i].ID).Msg("enrich IOC")
		}
	}
	if len(iocs) > 0 {
		p.log.Info().Int("count", len(iocs)).Msg("enrichment batch done")
	}
}

func (p *IOCPipeline) enrichIOC(ctx context.Context, ioc *models.IOC) error {
	e := IOCEnrichment{EnrichedAt: time.Now()}

	switch ioc.Type {
	case "ip":
		p.enrichIP(ctx, ioc.Value, &e)
	case "domain":
		p.enrichDomain(ctx, ioc.Value, &e)
	case "hash_sha256", "hash_md5":
		p.enrichHash(ctx, ioc.Value, &e)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return p.store.UpdateIOCEnrichment(ctx, ioc.ID, json.RawMessage(data))
}

// ── IP enrichment ─────────────────────────────────────────────────────────────

func (p *IOCPipeline) enrichIP(ctx context.Context, ip string, e *IOCEnrichment) {
	// rDNS
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		e.RDNS = strings.TrimSuffix(names[0], ".")
	}

	// VirusTotal
	if p.vtKey != "" {
		p.vtLimiter.Wait(ctx) //nolint:errcheck
		if vt, err := p.vtLookup(ctx, "ip_addresses", ip); err == nil && vt != nil {
			e.VTDetections = vt.Malicious
			e.VTTotalEngines = vt.Malicious + vt.Suspicious + vt.Harmless + vt.Undetected
			e.VTVerdict = vt.Verdict
		}
	}
}

// ── Domain enrichment ─────────────────────────────────────────────────────────

func (p *IOCPipeline) enrichDomain(ctx context.Context, domain string, e *IOCEnrichment) {
	// WHOIS via free whoisjson.com API
	if p.whoisEnabled {
		p.fetchWhois(ctx, domain, e)
	}

	// VirusTotal
	if p.vtKey != "" {
		p.vtLimiter.Wait(ctx) //nolint:errcheck
		if vt, err := p.vtLookup(ctx, "domains", domain); err == nil && vt != nil {
			e.VTDetections = vt.Malicious
			e.VTTotalEngines = vt.Malicious + vt.Suspicious + vt.Harmless + vt.Undetected
			e.VTVerdict = vt.Verdict
		}
	}
}

func (p *IOCPipeline) fetchWhois(ctx context.Context, domain string, e *IOCEnrichment) {
	url := fmt.Sprintf("https://www.whoisjsonapi.com/v1/%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := p.http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var body struct {
		Domain struct {
			Registrar  string `json:"registrar"`
			CreatedDate string `json:"created_date"`
		} `json:"domain"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil {
		return
	}
	e.WhoisRegistrar = body.Domain.Registrar
	if body.Domain.CreatedDate != "" {
		for _, layout := range []string{"2006-01-02", "2006-01-02T15:04:05Z", time.RFC3339} {
			if t, err := time.Parse(layout, body.Domain.CreatedDate); err == nil {
				e.DomainAgeDays = int(time.Since(t).Hours() / 24)
				break
			}
		}
	}
}

// ── Hash enrichment ───────────────────────────────────────────────────────────

func (p *IOCPipeline) enrichHash(ctx context.Context, hash string, e *IOCEnrichment) {
	if p.vtKey == "" {
		return
	}
	p.vtLimiter.Wait(ctx) //nolint:errcheck
	vt, err := p.vtLookup(ctx, "files", hash)
	if err != nil || vt == nil {
		return
	}
	e.VTDetections = vt.Malicious
	e.VTTotalEngines = vt.Malicious + vt.Suspicious + vt.Harmless + vt.Undetected
	e.VTVerdict = vt.Verdict
	e.VTMalwareFamily = vt.Family
}

// ── VirusTotal shared lookup ──────────────────────────────────────────────────

type vtResult struct {
	Malicious  int
	Suspicious int
	Harmless   int
	Undetected int
	Verdict    string
	Family     string
}

func (p *IOCPipeline) vtLookup(ctx context.Context, resource, id string) (*vtResult, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", resource, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", p.vtKey)

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &vtResult{Verdict: "unknown"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("virustotal %d: %s", resp.StatusCode, body)
	}

	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&body); err != nil {
		return nil, err
	}

	stats := body.Data.Attributes.LastAnalysisStats
	vt := &vtResult{
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Harmless:   stats.Harmless,
		Undetected: stats.Undetected,
		Family:     body.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
	}
	switch {
	case stats.Malicious >= 3:
		vt.Verdict = "malicious"
	case stats.Malicious > 0 || stats.Suspicious >= 3:
		vt.Verdict = "suspicious"
	case stats.Harmless > 0 || stats.Undetected > 0:
		vt.Verdict = "clean"
	default:
		vt.Verdict = "unknown"
	}
	return vt, nil
}
