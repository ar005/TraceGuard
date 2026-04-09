package cvecache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Fetcher provides cached CVE lookups backed by NVD.
type Fetcher struct {
	store  *store.Store
	log    zerolog.Logger
	client *http.Client
}

// New creates a CVE cache fetcher.
func New(st *store.Store, log zerolog.Logger) *Fetcher {
	return &Fetcher{
		store:  st,
		log:    log.With().Str("component", "cvecache").Logger(),
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Lookup returns cached CVE data, or fetches from NVD if not cached (or stale > 7 days).
func (f *Fetcher) Lookup(ctx context.Context, cveID string) (*models.CVEDetail, error) {
	// Try cache first.
	cached, err := f.store.GetCVE(ctx, cveID)
	if err == nil && cached != nil && time.Since(cached.FetchedAt) < 7*24*time.Hour {
		return cached, nil
	}

	// Fetch from NVD.
	detail, fetchErr := f.fetchFromNVD(ctx, cveID)
	if fetchErr != nil {
		f.log.Warn().Err(fetchErr).Str("cve", cveID).Msg("NVD fetch failed")
		// Return stale cache if we have it.
		if err == nil && cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("CVE %s not found and NVD fetch failed: %w", cveID, fetchErr)
	}

	// Store in cache.
	if upsertErr := f.store.UpsertCVE(ctx, detail); upsertErr != nil {
		f.log.Warn().Err(upsertErr).Str("cve", cveID).Msg("cache upsert failed")
	}

	return detail, nil
}

func (f *Fetcher) fetchFromNVD(ctx context.Context, cveID string) (*models.CVEDetail, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OEDR-CVECache/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD returned status %d", resp.StatusCode)
	}

	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssV31 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssV2 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found in NVD", cveID)
	}

	cve := nvdResp.Vulnerabilities[0].CVE

	// Extract description (English preferred).
	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(cve.Descriptions) > 0 {
		desc = cve.Descriptions[0].Value
	}

	// Extract severity.
	severity := "UNKNOWN"
	if len(cve.Metrics.CvssV31) > 0 {
		severity = strings.ToUpper(cve.Metrics.CvssV31[0].CvssData.BaseSeverity)
	} else if len(cve.Metrics.CvssV2) > 0 {
		severity = strings.ToUpper(cve.Metrics.CvssV2[0].CvssData.BaseSeverity)
	}

	// Extract references (max 10).
	var refs []string
	for i, r := range cve.References {
		if i >= 10 {
			break
		}
		refs = append(refs, r.URL)
	}

	// Check for exploit availability.
	exploitAvailable := false
	for _, r := range refs {
		if strings.Contains(r, "exploit-db.com") || strings.Contains(r, "packetstorm") {
			exploitAvailable = true
			break
		}
	}

	// Parse published date.
	var pubDate *time.Time
	if cve.Published != "" {
		if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
			pubDate = &t
		}
	}

	return &models.CVEDetail{
		CVEID:            cveID,
		Severity:         severity,
		Description:      desc,
		PublishedDate:     pubDate,
		References:        pq.StringArray(refs),
		ExploitAvailable:  exploitAvailable,
		CisaKEV:           false,
		Source:            "nvd",
	}, nil
}
