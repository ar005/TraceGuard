// internal/monitor/browser/history_poller.go
//
// Polls Chrome/Chromium and Firefox SQLite history databases on a schedule
// and emits BROWSER_HISTORY events for newly visited URLs.
//
// Because browsers lock their SQLite files while open, this poller copies
// each DB to a temp file before reading. Visited URLs newer than the last
// checkpoint per profile are forwarded to the event bus.
//
// Linux paths probed:
//   Chrome/Chromium: ~/.config/{google-chrome,chromium,brave-browser}/*/History
//   Firefox:         ~/.mozilla/firefox/*.*/places.sqlite

package browser

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// HistoryConfig configures the history poller.
type HistoryConfig struct {
	Enabled       bool
	PollIntervalS int // default 300 (5 min)
}

// DefaultHistoryConfig returns safe defaults.
func DefaultHistoryConfig() HistoryConfig {
	return HistoryConfig{
		Enabled:       false,
		PollIntervalS: 300,
	}
}

// HistoryPoller polls browser SQLite history files.
type HistoryPoller struct {
	cfg        HistoryConfig
	bus        events.Bus
	log        zerolog.Logger
	checkpoints sync.Map // profileKey → int64 (Chrome microseconds or Firefox microseconds)
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewHistoryPoller creates a HistoryPoller.
func NewHistoryPoller(cfg HistoryConfig, bus events.Bus, log zerolog.Logger) *HistoryPoller {
	return &HistoryPoller{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "browser_history").Logger(),
	}
}

// Start launches the polling goroutine. Non-blocking.
func (p *HistoryPoller) Start(ctx context.Context) error {
	interval := time.Duration(p.cfg.PollIntervalS) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	innerCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.log.Info().Dur("interval", interval).Msg("browser history poller started")
		// Run immediately, then on each tick.
		p.poll(innerCtx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.poll(innerCtx)
			case <-innerCtx.Done():
				return
			}
		}
	}()

	return nil
}

// Stop shuts down the poller.
func (p *HistoryPoller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.log.Info().Msg("browser history poller stopped")
}

func (p *HistoryPoller) poll(ctx context.Context) {
	for _, profile := range p.findProfiles() {
		if ctx.Err() != nil {
			return
		}
		p.pollProfile(ctx, profile)
	}
}

type browserProfile struct {
	browserName string
	profilePath string
	dbPath      string
	dbType      string // "chrome" or "firefox"
}

// findProfiles discovers browser SQLite history files under all home dirs.
func (p *HistoryPoller) findProfiles() []browserProfile {
	var profiles []browserProfile

	homeDirs := p.homeDirectories()

	for _, home := range homeDirs {
		// Chrome / Chromium / Brave
		chromeBases := []struct{ name, dir string }{
			{"Chrome", filepath.Join(home, ".config", "google-chrome")},
			{"Chromium", filepath.Join(home, ".config", "chromium")},
			{"Brave", filepath.Join(home, ".config", "brave-browser")},
			{"Edge", filepath.Join(home, ".config", "microsoft-edge")},
		}
		for _, base := range chromeBases {
			// Each profile is a subdirectory containing a "History" file.
			entries, err := os.ReadDir(base.dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				dbPath := filepath.Join(base.dir, e.Name(), "History")
				if _, err := os.Stat(dbPath); err == nil {
					profiles = append(profiles, browserProfile{
						browserName: base.name,
						profilePath: filepath.Join(base.dir, e.Name()),
						dbPath:      dbPath,
						dbType:      "chrome",
					})
				}
			}
		}

		// Firefox
		ffBase := filepath.Join(home, ".mozilla", "firefox")
		ffEntries, err := os.ReadDir(ffBase)
		if err == nil {
			for _, e := range ffEntries {
				if !e.IsDir() {
					continue
				}
				dbPath := filepath.Join(ffBase, e.Name(), "places.sqlite")
				if _, err := os.Stat(dbPath); err == nil {
					profiles = append(profiles, browserProfile{
						browserName: "Firefox",
						profilePath: filepath.Join(ffBase, e.Name()),
						dbPath:      dbPath,
						dbType:      "firefox",
					})
				}
			}
		}
	}

	return profiles
}

func (p *HistoryPoller) homeDirectories() []string {
	// Always include common paths.
	candidates := []string{"/root"}
	entries, err := os.ReadDir("/home")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, filepath.Join("/home", e.Name()))
			}
		}
	}
	return candidates
}

func (p *HistoryPoller) pollProfile(ctx context.Context, profile browserProfile) {
	// Copy the locked DB to a temp file so we can read it while the browser is open.
	tmp, err := p.copyDB(profile.dbPath)
	if err != nil {
		p.log.Debug().Err(err).Str("db", profile.dbPath).Msg("cannot copy history db")
		return
	}
	defer os.Remove(tmp)

	switch profile.dbType {
	case "chrome":
		p.pollChrome(ctx, profile, tmp)
	case "firefox":
		p.pollFirefox(ctx, profile, tmp)
	}
}

func (p *HistoryPoller) copyDB(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.CreateTemp("", "edr-history-*.sqlite")
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

func (p *HistoryPoller) profileKey(profile browserProfile) string {
	return profile.browserName + ":" + profile.profilePath
}

// Chrome stores timestamps as microseconds since 1601-01-01 00:00:00 UTC.
var chromiumEpoch = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

func chromiumMicroToTime(us int64) time.Time {
	return chromiumEpoch.Add(time.Duration(us) * time.Microsecond)
}

func (p *HistoryPoller) pollChrome(ctx context.Context, profile browserProfile, dbPath string) {
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro&immutable=1")
	if err != nil {
		p.log.Debug().Err(err).Msg("open chrome history db")
		return
	}
	defer db.Close()

	key := p.profileKey(profile)
	var since int64
	if v, ok := p.checkpoints.Load(key); ok {
		since = v.(int64)
	}

	// Chrome history schema: urls(id, url, title, visit_count, last_visit_time)
	rows, err := db.QueryContext(ctx,
		`SELECT url, title, visit_count, last_visit_time
		 FROM urls
		 WHERE last_visit_time > ?
		 ORDER BY last_visit_time ASC
		 LIMIT 500`,
		since,
	)
	if err != nil {
		p.log.Debug().Err(err).Msg("query chrome history")
		return
	}
	defer rows.Close()

	var maxTs int64 = since
	emitted := 0
	for rows.Next() {
		var rawURL, title string
		var visitCount int
		var lastVisitTs int64

		if err := rows.Scan(&rawURL, &title, &visitCount, &lastVisitTs); err != nil {
			continue
		}
		if lastVisitTs > maxTs {
			maxTs = lastVisitTs
		}

		domain := domainFromURL(rawURL)
		visitTime := chromiumMicroToTime(lastVisitTs)

		p.bus.Publish(&types.BrowserHistoryEvent{
			BaseEvent: types.BaseEvent{
				ID:        uuid.New().String(),
				Type:      types.EventBrowserHistory,
				Timestamp: visitTime,
				AgentID:   p.bus.AgentID(),
				Hostname:  p.bus.Hostname(),
				Severity:  types.SeverityInfo,
				Tags:      []string{"browser_history", profile.browserName},
			},
			URL:         rawURL,
			Domain:      domain,
			Title:       title,
			VisitCount:  visitCount,
			LastVisitAt: visitTime.UTC().Format(time.RFC3339),
			BrowserName: profile.browserName,
			ProfilePath: profile.profilePath,
		})
		emitted++
	}

	if maxTs > since {
		p.checkpoints.Store(key, maxTs)
	}

	if emitted > 0 {
		p.log.Debug().
			Str("browser", profile.browserName).
			Str("profile", profile.profilePath).
			Int("emitted", emitted).
			Msg("browser history events emitted")
	}
}

// Firefox stores timestamps as microseconds since Unix epoch.
func (p *HistoryPoller) pollFirefox(ctx context.Context, profile browserProfile, dbPath string) {
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro&immutable=1")
	if err != nil {
		p.log.Debug().Err(err).Msg("open firefox history db")
		return
	}
	defer db.Close()

	key := p.profileKey(profile)
	var since int64
	if v, ok := p.checkpoints.Load(key); ok {
		since = v.(int64)
	}

	// Firefox places.sqlite: moz_places(url, title, visit_count, last_visit_date)
	rows, err := db.QueryContext(ctx,
		`SELECT url, title, visit_count, last_visit_date
		 FROM moz_places
		 WHERE last_visit_date > ?
		   AND hidden = 0
		 ORDER BY last_visit_date ASC
		 LIMIT 500`,
		since,
	)
	if err != nil {
		p.log.Debug().Err(err).Msg("query firefox history")
		return
	}
	defer rows.Close()

	var maxTs int64 = since
	emitted := 0
	for rows.Next() {
		var rawURL string
		var title sql.NullString
		var visitCount int
		var lastVisitTs sql.NullInt64

		if err := rows.Scan(&rawURL, &title, &visitCount, &lastVisitTs); err != nil {
			continue
		}
		if !lastVisitTs.Valid {
			continue
		}
		ts := lastVisitTs.Int64
		if ts > maxTs {
			maxTs = ts
		}

		// Firefox stores microseconds since Unix epoch.
		visitTime := time.UnixMicro(ts).UTC()
		domain := domainFromURL(rawURL)

		p.bus.Publish(&types.BrowserHistoryEvent{
			BaseEvent: types.BaseEvent{
				ID:        uuid.New().String(),
				Type:      types.EventBrowserHistory,
				Timestamp: visitTime,
				AgentID:   p.bus.AgentID(),
				Hostname:  p.bus.Hostname(),
				Severity:  types.SeverityInfo,
				Tags:      []string{"browser_history", "Firefox"},
			},
			URL:         rawURL,
			Domain:      domain,
			Title:       title.String,
			VisitCount:  visitCount,
			LastVisitAt: visitTime.Format(time.RFC3339),
			BrowserName: "Firefox",
			ProfilePath: profile.profilePath,
		})
		emitted++
	}

	if maxTs > since {
		p.checkpoints.Store(key, maxTs)
	}

	if emitted > 0 {
		p.log.Debug().
			Str("profile", profile.profilePath).
			Int("emitted", emitted).
			Msg("firefox history events emitted")
	}
}

func domainFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Hostname())
}
