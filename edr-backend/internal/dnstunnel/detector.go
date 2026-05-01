// internal/dnstunnel/detector.go
//
// DNSTunnelDetector identifies DNS-based data exfiltration:
//   - Long subdomains (>50 chars) — encoded payload per query
//   - High Shannon entropy (>3.5 bits/char) — encrypted/compressed data
//   - High query rate (>50 queries/min to same base domain) — C2 beaconing

package dnstunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	maxSubdomainLen  = 50
	maxEntropyBits   = 3.5
	maxQueriesPerMin = 50
	queryWindow      = time.Minute
)

type DNSTunnelStore interface {
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Detector struct {
	store   DNSTunnelStore
	log     zerolog.Logger
	mu      sync.Mutex
	queries map[string][]time.Time // "agentID|baseDomain" -> timestamps
	alerted map[string]bool
}

func New(st *store.Store, log zerolog.Logger) *Detector {
	return &Detector{
		store:   st,
		log:     log.With().Str("component", "dns-tunnel-detector").Logger(),
		queries: make(map[string][]time.Time),
		alerted: make(map[string]bool),
	}
}

func (d *Detector) Observe(ctx context.Context, ev *models.XdrEvent) {
	if ev.Event.EventType != "DNS_QUERY" && ev.Event.EventType != "DNS_LOOKUP" &&
		ev.Event.EventType != "NETWORK_DNS" {
		return
	}

	var payload map[string]interface{}
	if len(ev.Event.Payload) > 0 {
		_ = json.Unmarshal(ev.Event.Payload, &payload)
	}

	query, _ := payload["query"].(string)
	if query == "" {
		query, _ = payload["name"].(string)
	}
	if query == "" {
		return
	}
	query = strings.ToLower(strings.TrimSuffix(query, "."))

	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	baseDomain := baseDomain(query)
	subdomain := subdomainPart(query)

	// Signal 1: long subdomain label
	if len(subdomain) > maxSubdomainLen {
		go d.fireAlert(ctx, ev, query, fmt.Sprintf("long subdomain label (%d chars)", len(subdomain)), "long_subdomain")
		return
	}

	// Signal 2: high entropy subdomain
	if subdomain != "" && shannonEntropy(subdomain) > maxEntropyBits {
		go d.fireAlert(ctx, ev, query, fmt.Sprintf("high-entropy subdomain (%.2f bits/char)", shannonEntropy(subdomain)), "high_entropy")
		return
	}

	// Signal 3: high query rate
	if baseDomain == "" {
		return
	}
	key := ev.AgentID + "|" + baseDomain

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.alerted[key] {
		return
	}

	cutoff := ts.Add(-queryWindow)
	times := d.queries[key]
	fresh := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, ts)
	d.queries[key] = fresh

	if len(fresh) > maxQueriesPerMin {
		d.alerted[key] = true
		go d.fireAlert(context.Background(), ev, baseDomain,
			fmt.Sprintf("high DNS query rate: %d queries/min to %s", len(fresh), baseDomain), "high_rate")
	}
}

func (d *Detector) fireAlert(ctx context.Context, ev *models.XdrEvent, domain, reason, signal string) {
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("DNS Tunneling Detected: %s → %s", ev.AgentID, domain),
		Description: fmt.Sprintf(
			"Possible DNS tunneling on agent %s to domain %s — %s. Common for C2 or data exfiltration.",
			ev.AgentID, domain, reason),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-dns-tunnel-" + signal,
		RuleName:    "DNS Tunneling",
		MitreIDs:    []string{"T1071.004", "T1048.003"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		SourceTypes: []string{"network"},
	}
	if err := d.store.InsertAlert(ctx, alert); err != nil {
		d.log.Warn().Err(err).Str("domain", domain).Msg("dns tunnel alert insert failed")
	} else {
		d.log.Warn().Str("agent", ev.AgentID).Str("domain", domain).Str("signal", signal).Msg("DNS TUNNEL ALERT")
	}
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func baseDomain(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func subdomainPart(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) <= 2 {
		return ""
	}
	// Return the first label (leftmost)
	return parts[0]
}
