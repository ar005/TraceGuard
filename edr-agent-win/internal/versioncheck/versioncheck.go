// internal/versioncheck/versioncheck.go
// Periodic version check against the backend's /api/v1/version endpoint.
// Logs a warning when the running agent is older than the backend's
// min_agent_version field. No forced shutdown — operators decide when to upgrade.

package versioncheck

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/version"
)

const checkInterval = 12 * time.Hour

type versionResponse struct {
	BackendVersion  string `json:"backend_version"`
	MinAgentVersion string `json:"min_agent_version"`
}

// Checker polls the backend for the minimum required agent version.
type Checker struct {
	backendURL string
	apiKey     string
	client     *http.Client
	log        zerolog.Logger
}

func New(backendURL, apiKey string, log zerolog.Logger) *Checker {
	return &Checker{
		backendURL: strings.TrimRight(backendURL, "/"),
		apiKey:     apiKey,
		client:     &http.Client{Timeout: 10 * time.Second},
		log:        log.With().Str("component", "versioncheck").Logger(),
	}
}

// Run polls every 12 hours. Call as a goroutine; returns when ctx is cancelled.
func (c *Checker) Run(ctx context.Context) {
	// Stagger first check by 30s so it doesn't compete with startup I/O.
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	c.check(ctx)

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.check(ctx)
		}
	}
}

func (c *Checker) check(ctx context.Context) {
	if c.backendURL == "" {
		return
	}

	url := c.backendURL + "/api/v1/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		c.log.Debug().Err(err).Msg("version check: build request failed")
		return
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.log.Debug().Err(err).Msg("version check: request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.log.Debug().Int("status", resp.StatusCode).Msg("version check: unexpected status")
		return
	}

	var vr versionResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		c.log.Debug().Err(err).Msg("version check: decode failed")
		return
	}

	c.log.Debug().
		Str("backend_version", vr.BackendVersion).
		Str("min_agent_version", vr.MinAgentVersion).
		Str("current", version.Version).
		Msg("version check ok")

	if vr.MinAgentVersion == "" {
		return
	}

	if semverLess(version.Version, vr.MinAgentVersion) {
		c.log.Warn().
			Str("current_version", version.Version).
			Str("min_required_version", vr.MinAgentVersion).
			Str("backend_version", vr.BackendVersion).
			Msg("agent version is outdated — please upgrade")
	}
}

// semverLess returns true when a < b using simple major.minor.patch comparison.
// Returns false (no warning) for non-release strings such as "dev" or "unknown".
func semverLess(a, b string) bool {
	aParts, ok1 := parseSemver(a)
	bParts, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return true
		}
		if aParts[i] > bParts[i] {
			return false
		}
	}
	return false
}

func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	// Drop pre-release / build metadata suffixes.
	s = strings.SplitN(s, "-", 2)[0]
	s = strings.SplitN(s, "+", 2)[0]
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 3 {
		return [3]int{}, false
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return [3]int{}, false
		}
		nums[i] = n
	}
	return nums, true
}
