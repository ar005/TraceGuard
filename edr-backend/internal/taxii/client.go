// Package taxii implements a TAXII 2.1 client for pulling STIX bundles.
package taxii

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Collection is a TAXII 2.1 collection descriptor.
type Collection struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CanRead     bool   `json:"can_read"`
}

// Client fetches STIX objects from a TAXII 2.1 server.
type Client struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

// New creates a TAXII client. baseURL should be the root TAXII URL (e.g. https://tip.example.com/taxii2/).
func New(baseURL, username, password string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

// ListCollections returns all readable collections on the server.
func (c *Client) ListCollections(ctx context.Context) ([]Collection, error) {
	var resp struct {
		Collections []Collection `json:"collections"`
	}
	if err := c.get(ctx, "/collections/", &resp); err != nil {
		return nil, err
	}
	return resp.Collections, nil
}

// FetchBundle fetches all indicator objects from the given collection as raw STIX bundle bytes.
func (c *Client) FetchBundle(ctx context.Context, collectionID string) (json.RawMessage, error) {
	path := fmt.Sprintf("/collections/%s/objects/?type=indicator", collectionID)
	var raw json.RawMessage
	if err := c.get(ctx, path, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("taxii: create request: %w", err)
	}
	req.Header.Set("Accept", "application/taxii+json;version=2.1")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("taxii: fetch %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("taxii: HTTP %d: %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("taxii: decode response: %w", err)
	}
	return nil
}
