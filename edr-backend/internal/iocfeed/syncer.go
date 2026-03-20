// internal/iocfeed/syncer.go
// Periodic IOC feed syncer — downloads indicators from free public threat
// intelligence feeds and upserts them into the IOC table for real-time matching.
//
// Supported feeds:
//   - Abuse.ch Feodo Tracker (C2 IPs)
//   - Abuse.ch URLhaus (malicious IPs + domains)
//   - Abuse.ch MalwareBazaar (SHA256 hashes of recent malware)
//   - Emerging Threats compromised IPs

package iocfeed

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Feed describes a single threat intelligence feed.
type Feed struct {
	Name   string // unique feed name used as IOC source
	URL    string
	Type   string // "ip", "domain", "hash_sha256" — ignored if parser sets IOCType
	Parser func(body io.Reader) []rawIOC
}

type rawIOC struct {
	Value       string
	IOCType     string // override feed-level Type if set (e.g., URLhaus yields both "ip" and "domain")
	Description string
	Tags        []string
}

// Config controls the feed syncer behaviour.
type Config struct {
	Enabled      bool          `mapstructure:"enabled"`
	SyncInterval time.Duration `mapstructure:"sync_interval"`
}

// Syncer periodically downloads IOC feeds and upserts them into the store.
type Syncer struct {
	store  *store.Store
	log    zerolog.Logger
	cfg    Config
	client *http.Client
	feeds  []Feed
}

// New creates a feed syncer with default public feeds.
func New(st *store.Store, log zerolog.Logger, cfg Config) *Syncer {
	s := &Syncer{
		store: st,
		log:   log.With().Str("component", "ioc-feed").Logger(),
		cfg:   cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
	s.feeds = defaultFeeds()
	return s
}

// FeedInfo describes a feed for the API/UI.
type FeedInfo struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
}

// FeedSyncResult is returned after a test sync.
type FeedSyncResult struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Type     string `json:"type"`
	Parsed   int    `json:"parsed"`
	Upserted int    `json:"upserted"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
}

// ListFeeds returns info about all configured feeds.
func (s *Syncer) ListFeeds() []FeedInfo {
	out := make([]FeedInfo, 0, len(s.feeds))
	for _, f := range s.feeds {
		out = append(out, FeedInfo{
			Name:    f.Name,
			URL:     f.URL,
			Type:    f.Type,
			Enabled: s.cfg.Enabled,
		})
	}
	return out
}

// SyncAllNow runs an immediate sync of all feeds and returns results.
func (s *Syncer) SyncAllNow(ctx context.Context) []FeedSyncResult {
	results := make([]FeedSyncResult, 0, len(s.feeds))
	for _, feed := range s.feeds {
		r := s.testFeed(ctx, feed)
		results = append(results, r)
	}
	return results
}

// SyncFeedByName syncs a single feed by name.
func (s *Syncer) SyncFeedByName(ctx context.Context, name string) (*FeedSyncResult, error) {
	for _, feed := range s.feeds {
		if feed.Name == name {
			r := s.testFeed(ctx, feed)
			return &r, nil
		}
	}
	return nil, fmt.Errorf("feed %q not found", name)
}

func (s *Syncer) testFeed(ctx context.Context, feed Feed) FeedSyncResult {
	start := time.Now()
	r := FeedSyncResult{Name: feed.Name, URL: feed.URL, Type: feed.Type}

	err := s.syncFeed(ctx, feed)
	r.Duration = time.Since(start).Round(time.Millisecond).String()
	if err != nil {
		r.Error = err.Error()
		return r
	}
	// Get count from DB for this source.
	iocs, _ := s.store.ListIOCs(ctx, "", feed.Name, false, 0, 0)
	r.Upserted = len(iocs)
	r.Parsed = r.Upserted // best approximation after upsert
	return r
}

// Start runs the sync loop. Call from a goroutine.
func (s *Syncer) Start(ctx context.Context) {
	if !s.cfg.Enabled {
		s.log.Info().Msg("IOC feed sync disabled")
		return
	}

	interval := s.cfg.SyncInterval
	if interval < time.Minute {
		interval = 6 * time.Hour
	}

	s.log.Info().
		Dur("interval", interval).
		Int("feeds", len(s.feeds)).
		Msg("IOC feed syncer started")

	// Run once immediately at startup.
	s.syncAll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncAll(ctx)
		}
	}
}

func (s *Syncer) syncAll(ctx context.Context) {
	for _, feed := range s.feeds {
		if err := s.syncFeed(ctx, feed); err != nil {
			s.log.Warn().Err(err).Str("feed", feed.Name).Msg("feed sync failed")
		}
	}
}

func (s *Syncer) syncFeed(ctx context.Context, feed Feed) error {
	s.log.Debug().Str("feed", feed.Name).Str("url", feed.URL).Msg("fetching feed")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "TraceGuard-IOC-Syncer/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, feed.URL)
	}

	raws := feed.Parser(resp.Body)
	if len(raws) == 0 {
		s.log.Debug().Str("feed", feed.Name).Msg("no IOCs parsed from feed")
		return nil
	}

	now := time.Now()
	expires := now.Add(7 * 24 * time.Hour) // IOCs expire in 7 days unless refreshed

	iocs := make([]models.IOC, 0, len(raws))
	for _, r := range raws {
		value := strings.ToLower(strings.TrimSpace(r.Value))
		if value == "" {
			continue
		}
		iocType := feed.Type
		if r.IOCType != "" {
			iocType = r.IOCType
		}
		iocs = append(iocs, models.IOC{
			ID:          "ioc-" + uuid.New().String(),
			Type:        iocType,
			Value:       value,
			Source:      feed.Name,
			Severity:    3, // HIGH
			Description: r.Description,
			Tags:        r.Tags,
			Enabled:     true,
			ExpiresAt:   &expires,
			CreatedAt:   now,
		})
	}

	count, err := s.store.InsertIOCBatch(ctx, iocs)
	if err != nil {
		return fmt.Errorf("batch insert: %w", err)
	}

	s.log.Info().
		Str("feed", feed.Name).
		Int("parsed", len(iocs)).
		Int("upserted", count).
		Msg("feed sync complete")
	return nil
}

// ─── Default feeds ────────────────────────────────────────────────────────────

func defaultFeeds() []Feed {
	return []Feed{
		{
			Name:   "feodotracker",
			URL:    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
			Type:   "ip",
			Parser: parsePlainTextIPs("Feodo Tracker C2 IP", []string{"c2", "botnet", "feodo"}),
		},
		{
			Name:   "emergingthreats",
			URL:    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Type:   "ip",
			Parser: parsePlainTextIPs("ET compromised IP", []string{"compromised"}),
		},
		{
			Name:   "urlhaus",
			URL:    "https://urlhaus.abuse.ch/downloads/csv_recent/",
			Type:   "domain",
			Parser: parseURLhausCSV,
		},
		{
			Name:   "malwarebazaar",
			URL:    "https://bazaar.abuse.ch/export/txt/sha256/recent/",
			Type:   "hash_sha256",
			Parser: parsePlainTextHashes("MalwareBazaar recent SHA256", []string{"malware"}),
		},
	}
}

// ─── Feed parsers ─────────────────────────────────────────────────────────────

// parsePlainTextIPs handles simple newline-separated IP lists with # comments.
func parsePlainTextIPs(desc string, tags []string) func(io.Reader) []rawIOC {
	return func(body io.Reader) []rawIOC {
		var out []rawIOC
		scanner := bufio.NewScanner(body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Validate it looks like an IP.
			ip := net.ParseIP(line)
			if ip == nil {
				continue
			}
			out = append(out, rawIOC{
				Value:       ip.String(),
				Description: desc,
				Tags:        tags,
			})
		}
		return out
	}
}

// parsePlainTextHashes handles newline-separated hash lists with # comments.
func parsePlainTextHashes(desc string, tags []string) func(io.Reader) []rawIOC {
	return func(body io.Reader) []rawIOC {
		var out []rawIOC
		scanner := bufio.NewScanner(body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// SHA256 hashes are 64 hex chars.
			if len(line) == 64 && isHex(line) {
				out = append(out, rawIOC{
					Value:       line,
					Description: desc,
					Tags:        tags,
				})
			}
		}
		return out
	}
}

// parseURLhausCSV parses the URLhaus CSV feed.
// Format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
func parseURLhausCSV(body io.Reader) []rawIOC {
	var out []rawIOC
	r := csv.NewReader(body)
	r.Comment = '#'
	r.LazyQuotes = true

	seen := make(map[string]bool)
	for {
		record, err := r.Read()
		if err != nil {
			break
		}
		if len(record) < 7 {
			continue
		}
		// Skip header.
		if record[0] == "id" {
			continue
		}

		rawURL := record[2]
		host := extractHost(rawURL)
		if host == "" {
			continue
		}

		// Deduplicate hosts within this feed.
		if seen[host] {
			continue
		}
		seen[host] = true

		// Classify as IP or domain.
		iocType := "domain"
		if net.ParseIP(host) != nil {
			iocType = "ip"
		}

		tags := []string{"urlhaus"}
		if record[6] != "" {
			for _, t := range strings.Split(record[6], ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}

		threat := record[5]
		desc := fmt.Sprintf("URLhaus: %s (threat: %s)", rawURL, threat)

		out = append(out, rawIOC{
			Value:       host,
			IOCType:     iocType,
			Description: desc,
			Tags:        tags,
		})
	}
	return out
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func extractHost(rawURL string) string {
	// Strip scheme.
	u := rawURL
	for _, prefix := range []string{"https://", "http://", "ftp://"} {
		u = strings.TrimPrefix(u, prefix)
	}
	// Strip path.
	if idx := strings.IndexByte(u, '/'); idx > 0 {
		u = u[:idx]
	}
	// Strip port.
	if host, _, err := net.SplitHostPort(u); err == nil {
		u = host
	}
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" || u == "localhost" {
		return ""
	}
	return u
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
