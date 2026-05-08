package iocfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/mispfeed"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/stix"
	"github.com/youredr/edr-backend/internal/taxii"
	"github.com/youredr/edr-backend/internal/store"
)

// CustomSyncer syncs user-defined feeds (http, TAXII, MISP).
type CustomSyncer struct {
	store  *store.Store
	log    zerolog.Logger
	client *http.Client
}

// NewCustom creates a CustomSyncer.
func NewCustom(st *store.Store, log zerolog.Logger) *CustomSyncer {
	return &CustomSyncer{
		store:  st,
		log:    log.With().Str("component", "custom-feed-syncer").Logger(),
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// SyncFeed runs a full sync for one feed, writes a sync log entry, returns (added, error).
func (cs *CustomSyncer) SyncFeed(ctx context.Context, f *models.CustomIOCFeed) (int, error) {
	logEntry := &models.FeedSyncLog{FeedID: f.ID, TenantID: f.TenantID}
	_ = cs.store.CreateFeedSyncLog(ctx, logEntry)

	added, err := cs.doSync(ctx, f)

	errStr := ""
	if err != nil {
		errStr = err.Error()
		cs.log.Warn().Err(err).Str("feed", f.Name).Msg("custom feed sync failed")
	} else {
		cs.log.Info().Str("feed", f.Name).Int("added", added).Msg("custom feed sync done")
	}
	_ = cs.store.FinishFeedSyncLog(ctx, logEntry.ID, added, 0, errStr)
	if err == nil {
		_ = cs.store.MarkCustomFeedSynced(ctx, f.ID, added)
	}
	return added, err
}

func (cs *CustomSyncer) doSync(ctx context.Context, f *models.CustomIOCFeed) (int, error) {
	switch f.Protocol {
	case "taxii":
		return cs.syncTAXII(ctx, f)
	case "misp":
		return cs.syncMISP(ctx, f)
	default:
		return cs.syncHTTP(ctx, f)
	}
}

// ─── HTTP sync ────────────────────────────────────────────────────────────────

func (cs *CustomSyncer) syncHTTP(ctx context.Context, f *models.CustomIOCFeed) (int, error) {
	if f.URL == "" {
		return 0, fmt.Errorf("no URL configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "TraceGuard-Feed-Syncer/1.0")

	resp, err := cs.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	iocs := cs.parseHTTP(resp.Body, f)
	return cs.upsertIOCs(ctx, iocs)
}

func (cs *CustomSyncer) parseHTTP(body io.Reader, f *models.CustomIOCFeed) []models.IOC {
	switch f.Format {
	case "stix":
		data, err := io.ReadAll(io.LimitReader(body, 50*1024*1024))
		if err != nil {
			return nil
		}
		return stixBundleToIOCs(data, f.Name)
	case "csv":
		return parseCSVFeed(body, f)
	default: // txt — newline-separated values
		return parseTxtFeed(body, f)
	}
}

func parseTxtFeed(body io.Reader, f *models.CustomIOCFeed) []models.IOC {
	now := time.Now()
	exp := now.Add(7 * 24 * time.Hour)
	var out []models.IOC
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, newIOC(line, f.FeedType, f.Name, now, exp))
	}
	return out
}

func parseCSVFeed(body io.Reader, f *models.CustomIOCFeed) []models.IOC {
	now := time.Now()
	exp := now.Add(7 * 24 * time.Hour)
	var out []models.IOC
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Take first field of CSV as the value
		value := strings.SplitN(line, ",", 2)[0]
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if value != "" {
			out = append(out, newIOC(value, f.FeedType, f.Name, now, exp))
		}
	}
	return out
}

// ─── TAXII sync ───────────────────────────────────────────────────────────────

func (cs *CustomSyncer) syncTAXII(ctx context.Context, f *models.CustomIOCFeed) (int, error) {
	if f.TAXIIUrl == "" {
		return 0, fmt.Errorf("TAXII URL not configured")
	}
	client := taxii.New(f.TAXIIUrl, f.TAXIIUsername, f.TAXIIPassword)

	collections, err := client.ListCollections(ctx)
	if err != nil {
		return 0, fmt.Errorf("list collections: %w", err)
	}

	total := 0
	for _, col := range collections {
		if !col.CanRead {
			continue
		}
		bundle, err := client.FetchBundle(ctx, col.ID)
		if err != nil {
			cs.log.Warn().Err(err).Str("collection", col.ID).Msg("taxii: fetch bundle failed")
			continue
		}
		iocs := stixBundleToIOCs(bundle, f.Name)
		n, err := cs.upsertIOCs(ctx, iocs)
		if err != nil {
			cs.log.Warn().Err(err).Str("collection", col.ID).Msg("taxii: upsert failed")
		}
		total += n
	}
	return total, nil
}

// ─── MISP sync ────────────────────────────────────────────────────────────────

func (cs *CustomSyncer) syncMISP(ctx context.Context, f *models.CustomIOCFeed) (int, error) {
	if f.MISPUrl == "" || f.MISPKey == "" {
		return 0, fmt.Errorf("MISP URL or key not configured")
	}
	client := mispfeed.New(f.MISPUrl, f.MISPKey)
	attrs, err := client.FetchAttributes(ctx)
	if err != nil {
		return 0, fmt.Errorf("misp fetch: %w", err)
	}

	now := time.Now()
	exp := now.Add(7 * 24 * time.Hour)
	iocs := make([]models.IOC, 0, len(attrs))
	for _, a := range attrs {
		if a.Value == "" {
			continue
		}
		ioc := newIOC(a.Value, a.IOCType, f.Name, now, exp)
		ioc.Description = a.Comment
		ioc.Tags = append(ioc.Tags, a.Tags...)
		iocs = append(iocs, ioc)
	}
	return cs.upsertIOCs(ctx, iocs)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func stixBundleToIOCs(data json.RawMessage, source string) []models.IOC {
	result, err := stix.Import([]byte(data), source)
	if err != nil || result == nil {
		return nil
	}
	now := time.Now()
	exp := now.Add(7 * 24 * time.Hour)
	for i := range result.IOCs {
		result.IOCs[i].ExpiresAt = &exp
		result.IOCs[i].CreatedAt = now
	}
	return result.IOCs
}

func newIOC(value, iocType, source string, now, exp time.Time) models.IOC {
	value = strings.ToLower(strings.TrimSpace(value))
	if iocType == "" {
		iocType = guessIOCType(value)
	}
	return models.IOC{
		ID:        "ioc-" + uuid.New().String(),
		Type:      iocType,
		Value:     value,
		Source:    source,
		Severity:  3,
		Tags:      []string{"custom-feed"},
		Enabled:   true,
		ExpiresAt: &exp,
		CreatedAt: now,
	}
}

func guessIOCType(value string) string {
	if net.ParseIP(value) != nil {
		return "ip"
	}
	if len(value) == 64 && isHexStr(value) {
		return "hash_sha256"
	}
	if len(value) == 32 && isHexStr(value) {
		return "hash_md5"
	}
	return "domain"
}

func isHexStr(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (cs *CustomSyncer) upsertIOCs(ctx context.Context, iocs []models.IOC) (int, error) {
	if len(iocs) == 0 {
		return 0, nil
	}
	return cs.store.InsertIOCBatch(ctx, iocs)
}

// TestConnectivity checks whether the feed endpoint is reachable without syncing.
func (cs *CustomSyncer) TestConnectivity(ctx context.Context, f *models.CustomIOCFeed) (bool, string) {
	switch f.Protocol {
	case "taxii":
		if f.TAXIIUrl == "" {
			return false, "TAXII URL not configured"
		}
		client := taxii.New(f.TAXIIUrl, f.TAXIIUsername, f.TAXIIPassword)
		cols, err := client.ListCollections(ctx)
		if err != nil {
			return false, err.Error()
		}
		return true, fmt.Sprintf("%d collections found", len(cols))
	case "misp":
		if f.MISPUrl == "" {
			return false, "MISP URL not configured"
		}
		// Simple HEAD / GET to root to check auth
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.MISPUrl+"/servers/getPyMISPVersion.json", nil)
		if err != nil {
			return false, err.Error()
		}
		req.Header.Set("Authorization", f.MISPKey)
		resp, err := cs.client.Do(req)
		if err != nil {
			return false, err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return true, "MISP reachable"
	default:
		if f.URL == "" {
			return false, "URL not configured"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, f.URL, nil)
		if err != nil {
			return false, err.Error()
		}
		resp, err := cs.client.Do(req)
		if err != nil {
			return false, err.Error()
		}
		resp.Body.Close()
		return resp.StatusCode < 400, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
}
