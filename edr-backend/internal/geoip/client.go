// internal/geoip/client.go
//
// Lightweight GeoIP client backed by ip-api.com (free, no key required, ~45 req/min).
// Results are cached in-memory with a 24h TTL so each unique public IP is only
// resolved once per server restart.

package geoip

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	apiURL     = "http://ip-api.com/json/%s?fields=status,lat,lon,country,city,isp"
	cacheTTL   = 24 * time.Hour
	httpTimeout = 3 * time.Second
)

type Location struct {
	Lat     float64
	Lon     float64
	Country string
	City    string
	ISP     string
}

type cacheEntry struct {
	loc Location
	at  time.Time
}

type Client struct {
	mu    sync.Mutex
	cache map[string]cacheEntry
	http  *http.Client
}

func New() *Client {
	return &Client{
		cache: make(map[string]cacheEntry),
		http:  &http.Client{Timeout: httpTimeout},
	}
}

// Lookup returns the geographic location of a public IP address.
// Returns nil, nil for private/loopback IPs (no signal).
// Returns nil, err if the lookup fails.
func (c *Client) Lookup(ip net.IP) (*Location, error) {
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
		return nil, nil
	}
	key := ip.String()

	c.mu.Lock()
	if e, ok := c.cache[key]; ok && time.Since(e.at) < cacheTTL {
		c.mu.Unlock()
		return &e.loc, nil
	}
	c.mu.Unlock()

	resp, err := c.http.Get(fmt.Sprintf(apiURL, key))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status  string  `json:"status"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		Country string  `json:"country"`
		City    string  `json:"city"`
		ISP     string  `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Status != "success" {
		return nil, fmt.Errorf("geoip: lookup failed for %s", key)
	}

	loc := Location{
		Lat:     result.Lat,
		Lon:     result.Lon,
		Country: result.Country,
		City:    result.City,
		ISP:     result.ISP,
	}

	c.mu.Lock()
	c.cache[key] = cacheEntry{loc: loc, at: time.Now()}
	c.mu.Unlock()

	return &loc, nil
}
