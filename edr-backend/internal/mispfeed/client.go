// Package mispfeed pulls IOC attributes from a MISP instance.
package mispfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Attribute is a MISP attribute mapped to a TraceGuard IOC type.
type Attribute struct {
	Value   string
	IOCType string // ip | domain | hash_sha256 | hash_md5 | url
	Tags    []string
	Comment string
}

// Client fetches attributes from a MISP REST API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New creates a MISP client. baseURL is e.g. https://misp.example.com.
func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// FetchAttributes returns recent attributes (last 7 days) from MISP.
func (c *Client) FetchAttributes(ctx context.Context) ([]Attribute, error) {
	url := c.baseURL + "/attributes/restSearch"
	body := strings.NewReader(`{"returnFormat":"json","type":["ip-dst","ip-src","domain","md5","sha256","url"],"last":"7d","limit":5000}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("misp: create request: %w", err)
	}
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("misp: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("misp: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Response struct {
			Attribute []struct {
				Type    string `json:"type"`
				Value   string `json:"value"`
				Comment string `json:"comment"`
				Tag     []struct {
					Name string `json:"name"`
				} `json:"Tag"`
			} `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("misp: decode: %w", err)
	}

	attrs := make([]Attribute, 0, len(result.Response.Attribute))
	for _, a := range result.Response.Attribute {
		iocType := mispTypeToIOC(a.Type)
		if iocType == "" {
			continue
		}
		tags := make([]string, 0, len(a.Tag))
		for _, t := range a.Tag {
			tags = append(tags, t.Name)
		}
		attrs = append(attrs, Attribute{
			Value:   strings.ToLower(strings.TrimSpace(a.Value)),
			IOCType: iocType,
			Comment: a.Comment,
			Tags:    tags,
		})
	}
	return attrs, nil
}

func mispTypeToIOC(t string) string {
	switch t {
	case "ip-dst", "ip-src":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "md5":
		return "hash_md5"
	case "sha256":
		return "hash_sha256"
	case "url":
		return "url"
	}
	return ""
}
