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
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/geoip"
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
	// Commercial flight ~900 km/h; 1000 km/h threshold gives small buffer.
	impossibleTravelSpeedKmh = 1000
)

// IdentityStore is the subset of store.Store used by the scorer.
type IdentityStore interface {
	GetIdentityByUID(ctx context.Context, uid string) (*models.IdentityRecord, error)
	UpdateIdentityRisk(ctx context.Context, uid string, score int16, factors []string) error
	TouchIdentityLogin(ctx context.Context, uid, srcIP string) error
	InsertAlert(ctx context.Context, a *models.Alert) error
}

// Scorer processes auth/policy events and updates identity risk scores.
type Scorer struct {
	store  IdentityStore
	geo    *geoip.Client
	log    zerolog.Logger

	mu          sync.Mutex
	loginTimes  map[string][]time.Time
	lastLoginIP map[string]loginRecord
}

type loginRecord struct {
	IP  net.IP
	Lat float64
	Lon float64
	At  time.Time
}

// New creates a Scorer backed by the given store.
func New(st *store.Store, log zerolog.Logger) *Scorer {
	return &Scorer{
		store:       st,
		geo:         geoip.New(),
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
	case "AUTH_LOGIN", "AUTH_LOGOFF", "IDENTITY_AUTH_LOGIN", "IDENTITY_AUTH_LOGIN_FAILED":
		d, f, impossible := s.scoreAuth(ctx, uid, ev)
		delta += d
		factors = append(factors, f...)
		if ev.SrcIP != nil {
			_ = s.store.TouchIdentityLogin(ctx, uid, ev.SrcIP.String())
		}
		if impossible {
			s.fireImpossibleTravelAlert(ctx, uid, ev)
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

func (s *Scorer) scoreAuth(ctx context.Context, uid string, ev *models.XdrEvent) (delta int16, factors []string, impossibleTravel bool) {
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

	// Impossible travel detection using real GeoIP
	if ev.SrcIP != nil {
		lat, lon := s.resolveGeo(ctx, *ev.SrcIP)
		if prev, ok := s.lastLoginIP[uid]; ok {
			elapsed := ts.Sub(prev.At)
			if elapsed > 0 && elapsed < impossibleTravelWindow && lat != 0 && prev.Lat != 0 {
				distKm := geoip.HaversineKm(prev.Lat, prev.Lon, lat, lon)
				speedKmh := distKm / elapsed.Hours()
				if speedKmh > impossibleTravelSpeedKmh {
					delta += scoreImpossibleTravel
					factors = append(factors, "impossible_travel")
					impossibleTravel = true
				}
			}
		}
		s.lastLoginIP[uid] = loginRecord{IP: *ev.SrcIP, Lat: lat, Lon: lon, At: ts}
	}

	return delta, factors, impossibleTravel
}

// resolveGeo returns lat/lon for an IP using the GeoIP client.
// Returns 0,0 for private/loopback or on lookup failure (safe no-op).
func (s *Scorer) resolveGeo(ctx context.Context, ip net.IP) (lat, lon float64) {
	loc, err := s.geo.Lookup(ip)
	if err != nil {
		s.log.Debug().Err(err).Str("ip", ip.String()).Msg("geoip lookup failed")
		return 0, 0
	}
	if loc == nil {
		return 0, 0
	}
	return loc.Lat, loc.Lon
}

// fireImpossibleTravelAlert creates a high-severity alert for impossible travel.
func (s *Scorer) fireImpossibleTravelAlert(ctx context.Context, uid string, ev *models.XdrEvent) {
	prev := s.lastLoginIP[uid]
	srcIPStr := ""
	if ev.SrcIP != nil {
		srcIPStr = ev.SrcIP.String()
	}
	alert := &models.Alert{
		ID:          "alert-" + uuid.New().String(),
		TenantID:    ev.TenantID,
		Title:       "Impossible Travel Detected: " + uid,
		Description: "User " + uid + " authenticated from " + srcIPStr + " within 1 hour of a login from " + prev.IP.String() + " — geographically impossible at normal travel speed.",
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-impossible-travel",
		RuleName:    "Impossible Travel",
		MitreIDs:    []string{"T1078"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		UserUID:     uid,
		SrcIP:       srcIPStr,
		SourceTypes: []string{"identity"},
	}
	if err := s.store.InsertAlert(ctx, alert); err != nil {
		s.log.Warn().Err(err).Str("uid", uid).Msg("impossible travel alert insert failed")
	} else {
		s.log.Warn().Str("uid", uid).Str("src_ip", srcIPStr).Str("prev_ip", prev.IP.String()).Msg("IMPOSSIBLE TRAVEL ALERT FIRED")
	}
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
