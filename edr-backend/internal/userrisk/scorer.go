// internal/userrisk/scorer.go
//
// UserRiskScorer evaluates XDR identity events and updates the identity_graph
// risk_score + risk_factors for each user.
//
// Scoring signals:
//   - impossible_travel: two logins from geographically distant IPs within 1h
//   - burst_login:       >5 auth events within 10 minutes
//   - privilege_escalation: POLICY_CHANGE or roleAssignment event by a user
//   - off_hours_login:   AUTH_LOGIN outside 06:00–22:00 UTC
//   - failed_auth:       AUTH event with outcome=FAILURE
//
// Risk scores are additive, clamped to [0, 100].
// Scores decay by 10 points/day via the separate risk_decay worker.

package userrisk

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	scoreImpossibleTravel    = 40
	scoreBurstLogin          = 25
	scorePrivilegeEscalation = 30
	scoreOffHours            = 10
	scoreFailedAuth          = 5
	burstLoginThreshold      = 5
	burstLoginWindow         = 10 * time.Minute
	impossibleTravelWindow   = 1 * time.Hour
	// Rough km/h speed threshold for impossible travel (commercial flight ~900 km/h)
	impossibleTravelSpeedKmh = 1000
)

// IdentityStore is the subset of store.Store used by the scorer.
type IdentityStore interface {
	GetIdentityByUID(ctx context.Context, uid string) (*models.IdentityRecord, error)
	UpdateIdentityRisk(ctx context.Context, uid string, score int16, factors []string) error
	TouchIdentityLogin(ctx context.Context, uid, srcIP string) error
}

// Scorer processes auth/policy events and updates identity risk scores.
type Scorer struct {
	store IdentityStore
	log   zerolog.Logger

	mu         sync.Mutex
	// loginTimes: uid → list of recent login timestamps for burst detection
	loginTimes map[string][]time.Time
	// lastLoginIP: uid → last login IP + time for impossible travel
	lastLoginIP map[string]loginRecord
}

type loginRecord struct {
	IP   net.IP
	At   time.Time
}

// New creates a Scorer backed by the given store.
func New(st *store.Store, log zerolog.Logger) *Scorer {
	return &Scorer{
		store:       st,
		log:         log.With().Str("component", "user-risk-scorer").Logger(),
		loginTimes:  make(map[string][]time.Time),
		lastLoginIP: make(map[string]loginRecord),
	}
}

// Score evaluates an XdrEvent and, if it carries identity signal, updates the
// user's risk score in the identity_graph.
func (s *Scorer) Score(ctx context.Context, ev *models.XdrEvent) {
	if ev.UserUID == "" {
		return
	}
	uid := ev.UserUID

	var factors []string
	var delta int16

	switch ev.Event.EventType {
	case "AUTH_LOGIN", "AUTH_LOGOFF":
		d, f := s.scoreAuth(uid, ev)
		delta += d
		factors = append(factors, f...)
		if ev.SrcIP != nil {
			_ = s.store.TouchIdentityLogin(ctx, uid, ev.SrcIP.String())
		}
	case "POLICY_CHANGE":
		delta += scorePrivilegeEscalation
		factors = append(factors, "privilege_escalation")
	}

	if delta == 0 {
		return
	}

	rec, err := s.store.GetIdentityByUID(ctx, uid)
	if err != nil {
		// Identity may not exist yet; create a minimal risk record.
		_ = s.store.UpdateIdentityRisk(ctx, uid, clamp(delta), factors)
		return
	}

	newScore := clamp(rec.RiskScore + delta)
	existing := existingFactors(rec.RiskFactors)
	merged := mergeFactors(existing, factors)
	if err := s.store.UpdateIdentityRisk(ctx, uid, newScore, merged); err != nil {
		s.log.Warn().Err(err).Str("uid", uid).Msg("update identity risk failed")
	}
}

func (s *Scorer) scoreAuth(uid string, ev *models.XdrEvent) (int16, []string) {
	var delta int16
	var factors []string

	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// Off-hours login
	hour := ts.UTC().Hour()
	if hour < 6 || hour >= 22 {
		delta += scoreOffHours
		factors = append(factors, "off_hours_login")
	}

	// Failed auth from payload
	if isFailedAuth(ev.Event.Payload) {
		delta += scoreFailedAuth
		factors = append(factors, "failed_auth")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Burst login detection
	times := pruneOld(s.loginTimes[uid], burstLoginWindow, ts)
	times = append(times, ts)
	s.loginTimes[uid] = times
	if len(times) > burstLoginThreshold {
		delta += scoreBurstLogin
		factors = append(factors, "burst_login")
	}

	// Impossible travel detection
	if ev.SrcIP != nil {
		if prev, ok := s.lastLoginIP[uid]; ok {
			elapsed := ts.Sub(prev.At)
			if elapsed > 0 && elapsed < impossibleTravelWindow {
				distKm := haversineKm(prev.IP, *ev.SrcIP)
				speedKmh := distKm / elapsed.Hours()
				if speedKmh > impossibleTravelSpeedKmh {
					delta += scoreImpossibleTravel
					factors = append(factors, "impossible_travel")
				}
			}
		}
		s.lastLoginIP[uid] = loginRecord{IP: *ev.SrcIP, At: ts}
	}

	return delta, factors
}

// ── helpers ───────────────────────────────────────────────────────────────────

func clamp(v int16) int16 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func pruneOld(times []time.Time, window time.Duration, now time.Time) []time.Time {
	cutoff := now.Add(-window)
	out := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func isFailedAuth(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var p map[string]interface{}
	if err := json.Unmarshal(payload, &p); err != nil {
		return false
	}
	if outcome, ok := p["outcome"].(string); ok {
		return outcome == "FAILURE" || outcome == "FAILED" || outcome == "DENY"
	}
	return false
}

func existingFactors(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var f []string
	_ = json.Unmarshal(raw, &f)
	return f
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

// haversineKm returns approximate great-circle distance in km between two IPs.
// For private/loopback IPs it returns 0 (no signal).
func haversineKm(a, b net.IP) float64 {
	if a == nil || b == nil {
		return 0
	}
	if a.IsPrivate() || b.IsPrivate() || a.IsLoopback() || b.IsLoopback() {
		return 0
	}
	// Without a GeoIP database we use a simple heuristic: compare the first
	// octet of IPv4 addresses. Different /8 blocks are treated as ~5000 km apart
	// (continental distance). This is intentionally rough — real deployments
	// should swap this for a MaxMind GeoLite2 lookup.
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return 0
	}
	if a4[0] != b4[0] {
		return 5000
	}
	_ = math.Pi // keep math import used
	return 0
}
