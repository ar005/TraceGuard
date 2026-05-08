// internal/enrichment/enricher.go
//
// On-demand threat intelligence enrichment for alerts.
// Queries VirusTotal (hashes/IPs) and AbuseIPDB (IPs) and stores the results
// in alerts.enrichments JSONB. Both services are optional — if an API key is
// empty the respective lookup is skipped silently.

package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const httpTimeout = 8 * time.Second

// TIResult is stored under alerts.enrichments["threat_intel"].
type TIResult struct {
	VirusTotal *VTResult      `json:"virustotal,omitempty"`
	AbuseIPDB  *AbuseIPResult `json:"abuseipdb,omitempty"`
	EnrichedAt time.Time      `json:"enriched_at"`
}

type VTResult struct {
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Harmless   int    `json:"harmless"`
	Undetected int    `json:"undetected"`
	Verdict    string `json:"verdict"` // malicious | suspicious | clean | unknown
	Permalink  string `json:"permalink"`
}

type AbuseIPResult struct {
	AbuseConfidenceScore int    `json:"abuse_confidence_score"`
	CountryCode          string `json:"country_code"`
	ISP                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"total_reports"`
	LastReportedAt       string `json:"last_reported_at,omitempty"`
}

type Enricher struct {
	vtKey     string
	abuseKey  string
	http      *http.Client
	log       zerolog.Logger
}

func New(vtAPIKey, abuseIPDBKey string, log zerolog.Logger) *Enricher {
	return &Enricher{
		vtKey:    vtAPIKey,
		abuseKey: abuseIPDBKey,
		http:     &http.Client{Timeout: httpTimeout},
		log:      log.With().Str("component", "enrichment").Logger(),
	}
}

// EnrichIP runs VirusTotal + AbuseIPDB lookups for an IP address.
func (e *Enricher) EnrichIP(ctx context.Context, ip string) (*TIResult, error) {
	result := &TIResult{EnrichedAt: time.Now()}

	var vtErr, abuseErr error
	if e.vtKey != "" {
		result.VirusTotal, vtErr = e.vtLookupIP(ctx, ip)
		if vtErr != nil {
			e.log.Debug().Err(vtErr).Str("ip", ip).Msg("virustotal ip lookup failed")
		}
	}
	if e.abuseKey != "" {
		result.AbuseIPDB, abuseErr = e.abuseIPLookup(ctx, ip)
		if abuseErr != nil {
			e.log.Debug().Err(abuseErr).Str("ip", ip).Msg("abuseipdb lookup failed")
		}
	}
	if result.VirusTotal == nil && result.AbuseIPDB == nil {
		return nil, nil
	}
	return result, nil
}

// EnrichHash runs a VirusTotal hash lookup.
func (e *Enricher) EnrichHash(ctx context.Context, hash string) (*TIResult, error) {
	if e.vtKey == "" {
		return nil, nil
	}
	result := &TIResult{EnrichedAt: time.Now()}
	var err error
	result.VirusTotal, err = e.vtLookupHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ── VirusTotal ────────────────────────────────────────────────────────────────

func (e *Enricher) vtLookupIP(ctx context.Context, ip string) (*VTResult, error) {
	return e.vtLookup(ctx, "ip_addresses", ip)
}

func (e *Enricher) vtLookupHash(ctx context.Context, hash string) (*VTResult, error) {
	return e.vtLookup(ctx, "files", hash)
}

func (e *Enricher) vtLookup(ctx context.Context, resource, id string) (*VTResult, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", resource, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", e.vtKey)

	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &VTResult{Verdict: "unknown"}, nil
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
			} `json:"attributes"`
			Links struct {
				Self string `json:"self"`
			} `json:"links"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	stats := body.Data.Attributes.LastAnalysisStats
	vt := &VTResult{
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Harmless:   stats.Harmless,
		Undetected: stats.Undetected,
		Permalink:  body.Data.Links.Self,
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

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

func (e *Enricher) abuseIPLookup(ctx context.Context, ip string) (*AbuseIPResult, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", e.abuseKey)
	req.Header.Set("Accept", "application/json")

	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("abuseipdb %d: %s", resp.StatusCode, body)
	}

	var body struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	d := body.Data
	return &AbuseIPResult{
		AbuseConfidenceScore: d.AbuseConfidenceScore,
		CountryCode:          d.CountryCode,
		ISP:                  d.ISP,
		Domain:               d.Domain,
		TotalReports:         d.TotalReports,
		LastReportedAt:       d.LastReportedAt,
	}, nil
}

// MergeIntoEnrichments merges a TIResult into existing enrichments JSON.
func MergeIntoEnrichments(existing json.RawMessage, ti *TIResult) (json.RawMessage, error) {
	m := map[string]interface{}{}
	if len(existing) > 0 && strings.TrimSpace(string(existing)) != "{}" {
		if err := json.Unmarshal(existing, &m); err != nil {
			m = map[string]interface{}{}
		}
	}
	m["threat_intel"] = ti
	return json.Marshal(m)
}
