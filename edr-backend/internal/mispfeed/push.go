package mispfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/youredr/edr-backend/internal/models"
)

// Pusher pushes IOCs to a MISP instance.
type Pusher struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewPusher creates a Pusher for the given MISP instance.
func NewPusher(baseURL, apiKey string) *Pusher {
	return &Pusher{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// PushIOCs pushes a slice of IOCs to MISP and returns the count pushed.
// Already-existing attributes are skipped (idempotent by value+type lookup).
func (p *Pusher) PushIOCs(ctx context.Context, iocs []models.IOC) (int, error) {
	// Fetch existing attribute values to avoid duplicates.
	existing, err := p.fetchExistingValues(ctx)
	if err != nil {
		// Non-fatal — proceed without dedup.
		existing = map[string]bool{}
	}

	pushed := 0
	for _, ioc := range iocs {
		mispType := iocTypeToMISP(ioc.Type)
		if mispType == "" {
			continue
		}
		key := mispType + "|" + ioc.Value
		if existing[key] {
			continue
		}

		if err := p.addAttribute(ctx, ioc, mispType); err != nil {
			return pushed, fmt.Errorf("push IOC %s: %w", ioc.Value, err)
		}
		existing[key] = true
		pushed++
	}
	return pushed, nil
}

func (p *Pusher) addAttribute(ctx context.Context, ioc models.IOC, mispType string) error {
	body := map[string]interface{}{
		"type":     mispType,
		"value":    ioc.Value,
		"comment":  ioc.Description,
		"to_ids":   true,
		"category": mispCategory(ioc.Type),
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/attributes/add/1", bytes.NewReader(data))
	if err != nil {
		return err
	}
	p.setHeaders(req)

	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 300 {
		return fmt.Errorf("MISP returned %d", resp.StatusCode)
	}
	return nil
}

func (p *Pusher) fetchExistingValues(ctx context.Context) (map[string]bool, error) {
	body := map[string]interface{}{
		"returnFormat": "json",
		"limit":        10000,
		"page":         1,
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/attributes/restSearch", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	p.setHeaders(req)

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Response struct {
			Attribute []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&result); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(result.Response.Attribute))
	for _, a := range result.Response.Attribute {
		out[a.Type+"|"+a.Value] = true
	}
	return out, nil
}

func (p *Pusher) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

func iocTypeToMISP(t string) string {
	switch t {
	case "ip":
		return "ip-dst"
	case "domain":
		return "domain"
	case "hash_sha256":
		return "sha256"
	case "hash_md5":
		return "md5"
	}
	return ""
}

func mispCategory(iocType string) string {
	switch iocType {
	case "ip":
		return "Network activity"
	case "domain":
		return "Network activity"
	case "hash_sha256", "hash_md5":
		return "Payload delivery"
	}
	return "External analysis"
}
