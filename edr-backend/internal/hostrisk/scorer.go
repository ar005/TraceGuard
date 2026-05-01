// internal/hostrisk/scorer.go
//
// HostRiskScorer evaluates process/network events and updates agent risk_score.
// Signals:
//   - process_injection:  ptrace/mmap_exec/memfd event types
//   - rare_parent_child:  browser/office spawning shell
//   - off_hours_process:  privileged process outside 06:00-22:00 UTC
//   - network_recon:      >10 unique dst_ips within 5 minutes

package hostrisk

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	scoreInjection    int16 = 35
	scoreRareParent   int16 = 20
	scoreOffHours     int16 = 10
	scoreNetworkRecon int16 = 25
	reconWindow             = 5 * time.Minute
	reconThresh             = 10
)

var suspiciousParents = map[string]bool{
	"chrome": true, "firefox": true, "msedge": true, "chromium": true,
	"iexplore": true, "winword": true, "excel": true, "powerpnt": true,
	"outlook": true, "acrobat": true, "acrord32": true, "libreoffice": true,
}

type HostRiskStore interface {
	UpdateAgentRisk(ctx context.Context, agentID string, score int16, factors []string) error
	GetAgentRisk(ctx context.Context, agentID string) (int16, json.RawMessage, error)
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Scorer struct {
	store   HostRiskStore
	log     zerolog.Logger
	mu      sync.Mutex
	dstSeen map[string][]dstRecord // agentID -> recent dst IPs+times
}

type dstRecord struct {
	ip string
	at time.Time
}

func New(st *store.Store, log zerolog.Logger) *Scorer {
	return &Scorer{
		store:   st,
		log:     log.With().Str("component", "host-risk-scorer").Logger(),
		dstSeen: make(map[string][]dstRecord),
	}
}

func (s *Scorer) Score(ctx context.Context, ev *models.XdrEvent) {
	if ev.AgentID == "" {
		return
	}

	var delta int16
	var factors []string

	switch ev.Event.EventType {
	case "PROCESS_CREATE", "PROCESS_EXEC":
		d, f := s.scoreProcess(ev)
		delta += d
		factors = append(factors, f...)
	case "NETWORK_CONNECTION", "NETWORK_CONNECT":
		d, f := s.scoreNetwork(ev)
		delta += d
		factors = append(factors, f...)
	case "MEMORY_MAP", "PTRACE", "MEMFD_CREATE", "PROCESS_INJECT":
		delta += scoreInjection
		factors = append(factors, "process_injection")
	}

	if delta == 0 {
		return
	}

	existing, rawFactors, err := s.store.GetAgentRisk(ctx, ev.AgentID)
	if err != nil {
		existing = 0
		rawFactors = json.RawMessage(`[]`)
	}

	var existingFactors []string
	_ = json.Unmarshal(rawFactors, &existingFactors)
	merged := mergeFactors(existingFactors, factors)
	newScore := clamp(existing + delta)

	if err := s.store.UpdateAgentRisk(ctx, ev.AgentID, newScore, merged); err != nil {
		s.log.Warn().Err(err).Str("agent_id", ev.AgentID).Msg("update agent risk failed")
	}
}

func (s *Scorer) scoreProcess(ev *models.XdrEvent) (delta int16, factors []string) {
	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// Off-hours privileged process
	hour := ts.UTC().Hour()
	if hour < 6 || hour >= 22 {
		pname := strings.ToLower(ev.Event.ProcessName)
		for _, kw := range []string{"sudo", "su", "passwd", "shadow", "crypt", "useradd", "visudo"} {
			if strings.Contains(pname, kw) {
				delta += scoreOffHours
				factors = append(factors, "off_hours_process")
				break
			}
		}
	}

	// Rare parent-child: browser/office spawning a child
	var payload map[string]interface{}
	if len(ev.Event.Payload) > 0 {
		_ = json.Unmarshal(ev.Event.Payload, &payload)
	}
	if parent, ok := payload["parent_process_name"].(string); ok {
		if suspiciousParents[strings.ToLower(parent)] {
			delta += scoreRareParent
			factors = append(factors, "rare_parent_child")
		}
	}

	return delta, factors
}

func (s *Scorer) scoreNetwork(ev *models.XdrEvent) (delta int16, factors []string) {
	if ev.DstIP == nil {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := ev.Event.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-reconWindow)

	records := s.dstSeen[ev.AgentID]
	fresh := records[:0]
	for _, r := range records {
		if r.at.After(cutoff) {
			fresh = append(fresh, r)
		}
	}
	fresh = append(fresh, dstRecord{ip: ev.DstIP.String(), at: now})
	s.dstSeen[ev.AgentID] = fresh

	if uniqueIPs(fresh) > reconThresh {
		delta += scoreNetworkRecon
		factors = append(factors, "network_recon")
	}
	return delta, factors
}

func uniqueIPs(records []dstRecord) int {
	seen := make(map[string]bool, len(records))
	for _, r := range records {
		seen[r.ip] = true
	}
	return len(seen)
}

func clamp(v int16) int16 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func mergeFactors(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		seen[v] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
