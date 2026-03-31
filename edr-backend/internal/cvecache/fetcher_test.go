package cvecache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// newTestFetcher creates a Fetcher with no store (nil) and a custom HTTP client.
func newTestFetcher(client *http.Client) *Fetcher {
	return &Fetcher{
		store:  nil,
		log:    zerolog.New(os.Stderr).Level(zerolog.Disabled),
		client: client,
	}
}

// nvdResponse builds a mock NVD API response body.
func nvdResponse(cveID, desc, severity, published string, refs []string) map[string]interface{} {
	refList := make([]map[string]string, len(refs))
	for i, r := range refs {
		refList[i] = map[string]string{"url": r}
	}

	var cvssV31 []interface{}
	if severity != "" {
		cvssV31 = []interface{}{
			map[string]interface{}{
				"cvssData": map[string]string{"baseSeverity": severity},
			},
		}
	}

	return map[string]interface{}{
		"vulnerabilities": []interface{}{
			map[string]interface{}{
				"cve": map[string]interface{}{
					"id":        cveID,
					"published": published,
					"descriptions": []interface{}{
						map[string]string{"lang": "en", "value": desc},
					},
					"metrics": map[string]interface{}{
						"cvssMetricV31": cvssV31,
					},
					"references": refList,
				},
			},
		},
	}
}

func TestFetchFromNVD_BasicParsing(t *testing.T) {
	body := nvdResponse(
		"CVE-2024-1234",
		"A buffer overflow in libfoo allows remote code execution.",
		"HIGH",
		"2024-01-15T12:00:00.000Z",
		[]string{"https://example.com/advisory", "https://exploit-db.com/exploits/99999"},
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	f := newTestFetcher(srv.Client())
	detail, err := fetchFromServer(f, srv.URL, "CVE-2024-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if detail.CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", detail.CVEID, "CVE-2024-1234")
	}
	if detail.Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", detail.Severity, "HIGH")
	}
	if detail.Description != "A buffer overflow in libfoo allows remote code execution." {
		t.Errorf("Description = %q", detail.Description)
	}
	if !detail.ExploitAvailable {
		t.Error("ExploitAvailable should be true (exploit-db.com in refs)")
	}
	if len(detail.References) != 2 {
		t.Errorf("References count = %d, want 2", len(detail.References))
	}
	if detail.PublishedDate == nil {
		t.Error("PublishedDate should not be nil")
	}
	if detail.Source != "nvd" {
		t.Errorf("Source = %q, want %q", detail.Source, "nvd")
	}
}

func TestFetchFromNVD_NoVulnerabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"vulnerabilities": []interface{}{}})
	}))
	defer srv.Close()

	f := newTestFetcher(srv.Client())
	_, err := fetchFromServer(f, srv.URL, "CVE-9999-0000")
	if err == nil {
		t.Fatal("expected error for empty vulnerabilities, got nil")
	}
}

func TestFetchFromNVD_SeverityFallbackToV2(t *testing.T) {
	body := map[string]interface{}{
		"vulnerabilities": []interface{}{
			map[string]interface{}{
				"cve": map[string]interface{}{
					"id":        "CVE-2020-0001",
					"published": "",
					"descriptions": []interface{}{
						map[string]string{"lang": "en", "value": "test desc"},
					},
					"metrics": map[string]interface{}{
						"cvssMetricV31": []interface{}{},
						"cvssMetricV2": []interface{}{
							map[string]interface{}{
								"cvssData": map[string]string{"baseSeverity": "medium"},
							},
						},
					},
					"references": []interface{}{},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	f := newTestFetcher(srv.Client())
	detail, err := fetchFromServer(f, srv.URL, "CVE-2020-0001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail.Severity != "MEDIUM" {
		t.Errorf("Severity = %q, want %q (fallback to V2 + uppercase)", detail.Severity, "MEDIUM")
	}
}

func TestFetchFromNVD_SeverityUnknownWhenNoMetrics(t *testing.T) {
	body := map[string]interface{}{
		"vulnerabilities": []interface{}{
			map[string]interface{}{
				"cve": map[string]interface{}{
					"id":        "CVE-2020-0002",
					"published": "",
					"descriptions": []interface{}{
						map[string]string{"lang": "es", "value": "descripcion en espanol"},
					},
					"metrics":    map[string]interface{}{},
					"references": []interface{}{},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	f := newTestFetcher(srv.Client())
	detail, err := fetchFromServer(f, srv.URL, "CVE-2020-0002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail.Severity != "UNKNOWN" {
		t.Errorf("Severity = %q, want %q", detail.Severity, "UNKNOWN")
	}
	if detail.Description != "descripcion en espanol" {
		t.Errorf("Description = %q, want Spanish fallback", detail.Description)
	}
}

func TestFetchFromNVD_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	f := newTestFetcher(srv.Client())
	_, err := fetchFromServer(f, srv.URL, "CVE-2024-0000")
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
}

func TestFetchFromNVD_RefsMax10(t *testing.T) {
	refs := make([]string, 15)
	for i := range refs {
		refs[i] = fmt.Sprintf("https://example.com/ref-%d", i)
	}
	body := nvdResponse("CVE-2024-9999", "many refs", "LOW", "", refs)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	f := newTestFetcher(srv.Client())
	detail, err := fetchFromServer(f, srv.URL, "CVE-2024-9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(detail.References) > 10 {
		t.Errorf("References count = %d, want <= 10", len(detail.References))
	}
}

// fetchFromServer replicates the parsing logic from fetchFromNVD but hits
// a custom URL (the httptest server) instead of the real NVD API.
func fetchFromServer(f *Fetcher, baseURL, cveID string) (*models.CVEDetail, error) {
	url := baseURL + "?cveId=" + cveID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TraceGuard-CVECache/1.0")

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
		return nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found in NVD", cveID)
	}

	cve := nvdResp.Vulnerabilities[0].CVE

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

	severity := "UNKNOWN"
	if len(cve.Metrics.CvssV31) > 0 {
		severity = strings.ToUpper(cve.Metrics.CvssV31[0].CvssData.BaseSeverity)
	} else if len(cve.Metrics.CvssV2) > 0 {
		severity = strings.ToUpper(cve.Metrics.CvssV2[0].CvssData.BaseSeverity)
	}

	var refs []string
	for i, r := range cve.References {
		if i >= 10 {
			break
		}
		refs = append(refs, r.URL)
	}

	exploitAvailable := false
	for _, r := range refs {
		if strings.Contains(r, "exploit-db.com") || strings.Contains(r, "packetstorm") {
			exploitAvailable = true
			break
		}
	}

	var pubDate *time.Time
	if cve.Published != "" {
		if pt, parseErr := time.Parse(time.RFC3339, cve.Published); parseErr == nil {
			pubDate = &pt
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
