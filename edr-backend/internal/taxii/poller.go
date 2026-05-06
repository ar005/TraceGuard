package taxii

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

// Poller polls enabled TAXII feeds and imports new IOCs into the store.
type Poller struct {
	st  *store.Store
	log zerolog.Logger
}

func NewPoller(st *store.Store, log zerolog.Logger) *Poller {
	return &Poller{st: st, log: log}
}

// Run ticks every 5 minutes and polls any due feeds.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	p.pollDue(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollDue(ctx)
		}
	}
}

func (p *Poller) pollDue(ctx context.Context) {
	feeds, err := p.st.ListDueTAXIIFeeds(ctx)
	if err != nil {
		p.log.Error().Err(err).Msg("taxii: list due feeds")
		return
	}
	for _, f := range feeds {
		go p.PollFeed(ctx, f)
	}
}

// PollFeed fetches one TAXII feed and imports its indicators.
func (p *Poller) PollFeed(ctx context.Context, f models.TAXIIFeed) {
	run := &models.TAXIIPollRun{
		FeedID:   f.ID,
		TenantID: f.TenantID,
		Status:   "running",
	}
	if err := p.st.CreateTAXIIPollRun(ctx, run); err != nil {
		p.log.Error().Err(err).Str("feed", f.ID).Msg("taxii: create poll run")
		return
	}

	fetched, imported, pollErr := p.fetch(ctx, &f)

	status, errMsg := "ok", ""
	if pollErr != nil {
		status = "error"
		errMsg = pollErr.Error()
		p.log.Error().Err(pollErr).Str("feed", f.Name).Msg("taxii: poll failed")
	}

	_ = p.st.FinishTAXIIPollRun(ctx, run.ID, fetched, imported, status, errMsg)
	nextPoll := time.Now().Add(time.Duration(f.PollInterval) * time.Second)
	_ = p.st.FinishTAXIIPoll(ctx, f.ID, nextPoll, f.IOCCount+imported, errMsg)
}

func (p *Poller) fetch(ctx context.Context, f *models.TAXIIFeed) (fetched, imported int, err error) {
	baseURL := f.DiscoveryURL
	if f.APIRoot != "" {
		baseURL = strings.TrimRight(f.DiscoveryURL, "/") + "/" + strings.Trim(f.APIRoot, "/")
	}
	client := New(baseURL, f.Username, f.PasswordEnc)

	collID := f.CollectionID
	if collID == "" {
		cols, cerr := client.ListCollections(ctx)
		if cerr != nil {
			return 0, 0, fmt.Errorf("list collections: %w", cerr)
		}
		if len(cols) == 0 {
			return 0, 0, fmt.Errorf("no collections found")
		}
		collID = cols[0].ID
	}

	bundle, berr := client.FetchBundle(ctx, collID)
	if berr != nil {
		return 0, 0, fmt.Errorf("fetch bundle: %w", berr)
	}

	indicators, perr := parseIndicators(bundle)
	if perr != nil {
		return 0, 0, fmt.Errorf("parse bundle: %w", perr)
	}
	fetched = len(indicators)

	for _, ind := range indicators {
		ioc := stixIndicatorToIOC(ind)
		if ioc == nil {
			continue
		}
		ioc.Source = f.Name // use feed name so hits can be traced back
		if uerr := p.st.InsertIOC(ctx, ioc); uerr != nil {
			p.log.Warn().Err(uerr).Str("ioc", ioc.Value).Msg("taxii: insert ioc")
			continue
		}
		imported++
	}
	return
}

type stixIndicator struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Pattern    string `json:"pattern"`
	ValidUntil string `json:"valid_until"`
}

type stixBundle struct {
	Objects []json.RawMessage `json:"objects"`
}

func parseIndicators(raw json.RawMessage) ([]stixIndicator, error) {
	var b stixBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	var out []stixIndicator
	for _, obj := range b.Objects {
		var ind stixIndicator
		if err := json.Unmarshal(obj, &ind); err != nil {
			continue
		}
		if ind.Type == "indicator" {
			out = append(out, ind)
		}
	}
	return out, nil
}

// patternRe extracts the value from STIX patterns like [ipv4-addr:value = '1.2.3.4']
var patternRe = regexp.MustCompile(`\[\s*(\S+?)\s*=\s*'([^']+)'`)

func stixIndicatorToIOC(ind stixIndicator) *models.IOC {
	m := patternRe.FindStringSubmatch(ind.Pattern)
	if len(m) < 3 {
		return nil
	}
	prop, value := m[1], m[2]

	iocType := ""
	switch {
	case strings.HasPrefix(prop, "ipv4-addr"), strings.HasPrefix(prop, "ipv6-addr"):
		iocType = "ip"
	case strings.HasPrefix(prop, "domain-name"):
		iocType = "domain"
	case strings.HasPrefix(prop, "url"):
		iocType = "url"
	case strings.Contains(prop, "MD5"):
		iocType = "hash_md5"
	case strings.Contains(prop, "SHA-1"):
		iocType = "hash_sha1"
	case strings.Contains(prop, "SHA-256"):
		iocType = "hash_sha256"
	default:
		return nil
	}

	ioc := &models.IOC{
		ID:          "ioc-" + uuid.New().String(),
		Type:        iocType,
		Value:       value,
		Source:      "taxii",
		Severity:    2,
		Description: ind.Name,
		Enabled:     true,
		CreatedAt:   time.Now(),
	}
	if ind.ValidUntil != "" {
		if t, err := time.Parse(time.RFC3339, ind.ValidUntil); err == nil {
			ioc.ExpiresAt = &t
		}
	}
	return ioc
}
