// internal/monitor/browser/monitor.go
//
// Browser monitor — receives web request events from the TraceGuard browser
// extension (Chrome/Firefox) via a localhost-only HTTP endpoint.
//
// The extension POSTs JSON batches to http://127.0.0.1:9999/browser-events.
// Each event contains: url, method, status_code, referrer, redirect chain,
// tab_url, response headers, etc.
//
// This monitor converts them into BROWSER_REQUEST events and publishes
// them to the agent's event bus for streaming to the backend.

package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config for the browser monitor.
type Config struct {
	Enabled    bool
	ListenAddr string // default "127.0.0.1:9999"
}

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:    false,
		ListenAddr: "127.0.0.1:9999",
	}
}

// Monitor receives browser events via HTTP.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	server *http.Server
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a browser monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "browser").Logger(),
	}
}

// incomingBatch is the JSON payload from the extension.
type incomingBatch struct {
	Events []incomingEvent `json:"events"`
}

// incomingEvent is a single browser request event from the extension.
type incomingEvent struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	Type            string            `json:"type"` // main_frame, sub_frame, xmlhttprequest
	Initiator       string            `json:"initiator"`
	TabID           int               `json:"tab_id"`
	TabURL          string            `json:"tab_url"`
	Timestamp       string            `json:"timestamp"`
	IP              string            `json:"ip"`
	FromCache       bool              `json:"from_cache"`
	Error           string            `json:"error"`
	RedirectChain   []redirectEntry   `json:"redirect_chain"`
	ResponseHeaders map[string]string `json:"response_headers"`
	BrowserName     string            `json:"browser_name"`
}

type redirectEntry struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

// Start begins the HTTP listener. Non-blocking.
func (m *Monitor) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/browser-events", m.handleEvents)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	m.server = &http.Server{
		Addr:         m.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Verify we're only binding to localhost.
	host, _, err := net.SplitHostPort(m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen addr %q: %w", m.cfg.ListenAddr, err)
	}
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return fmt.Errorf("browser monitor must bind to localhost only, got %q", host)
	}

	ln, err := net.Listen("tcp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("browser monitor listen: %w", err)
	}

	// Internal cancel so Stop() can unblock the ctx goroutine.
	innerCtx, innerCancel := context.WithCancel(ctx)
	m.cancel = innerCancel

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.log.Info().Str("addr", m.cfg.ListenAddr).Msg("browser monitor HTTP listener started")
		if err := m.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			m.log.Error().Err(err).Msg("browser monitor HTTP server error")
		}
	}()

	// Shut down when context is cancelled (or Stop is called).
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-innerCtx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		m.server.Shutdown(shutCtx)
	}()

	return nil
}

// Stop shuts down the HTTP listener.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("browser monitor stopped")
}

func (m *Monitor) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only accept from localhost.
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteHost != "127.0.0.1" && remoteHost != "::1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024)) // 2MB max
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var batch incomingBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	accepted := 0
	for _, ev := range batch.Events {
		if ev.URL == "" {
			continue
		}
		m.publishEvent(ev)
		accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"accepted":%d}`, accepted)
}

func (m *Monitor) publishEvent(ev incomingEvent) {
	// Parse URL for domain extraction.
	parsedURL, err := url.Parse(ev.URL)
	if err != nil {
		return
	}

	domain := parsedURL.Hostname()
	urlPath := parsedURL.Path
	if parsedURL.RawQuery != "" {
		urlPath += "?" + parsedURL.RawQuery
	}

	// Build redirect chain as strings.
	var redirectURLs []string
	for _, r := range ev.RedirectChain {
		redirectURLs = append(redirectURLs, r.URL)
	}

	// Determine severity.
	severity := types.SeverityInfo
	if ev.StatusCode == 0 && ev.Error != "" {
		severity = types.SeverityLow
	}

	// Determine content type from headers.
	contentType := ""
	if ev.ResponseHeaders != nil {
		contentType = ev.ResponseHeaders["content-type"]
	}

	// Parse timestamp or use now.
	ts := time.Now()
	if ev.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
			ts = parsed
		}
	}

	// Determine referrer — initiator in Chrome, originUrl in Firefox.
	referrer := ev.Initiator
	if referrer == "" {
		referrer = ev.TabURL
	}

	// Check if this looks like a form submission.
	isFormSubmit := ev.Method == "POST" && ev.Type == "main_frame"

	// Build tags.
	var tags []string
	tags = append(tags, "browser")
	if ev.Type != "" {
		tags = append(tags, ev.Type)
	}
	if isFormSubmit {
		tags = append(tags, "form-submit")
	}
	if ev.FromCache {
		tags = append(tags, "cached")
	}
	if len(redirectURLs) > 0 {
		tags = append(tags, "redirected")
	}
	if strings.Contains(strings.ToLower(urlPath), "login") ||
		strings.Contains(strings.ToLower(urlPath), "signin") ||
		strings.Contains(strings.ToLower(urlPath), "auth") {
		tags = append(tags, "auth-page")
	}

	browserEv := &types.BrowserRequestEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventBrowserRequest,
			Timestamp: ts,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      tags,
		},
		URL:           ev.URL,
		Domain:        domain,
		Path:          urlPath,
		Method:        ev.Method,
		StatusCode:    ev.StatusCode,
		ContentType:   contentType,
		Referrer:      referrer,
		TabURL:        ev.TabURL,
		ResourceType:  ev.Type,
		ServerIP:      ev.IP,
		FromCache:     ev.FromCache,
		Error:         ev.Error,
		IsFormSubmit:  isFormSubmit,
		RedirectChain: redirectURLs,
		BrowserName:   ev.BrowserName,
	}

	m.bus.Publish(browserEv)

	m.log.Debug().
		Str("url", ev.URL).
		Str("domain", domain).
		Int("status", ev.StatusCode).
		Str("method", ev.Method).
		Msg("browser request")
}
