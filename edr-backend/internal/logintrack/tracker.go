// internal/logintrack/tracker.go
//
// LoginTracker records every AUTH_LOGIN / AUTH_LOGOFF event to login_sessions
// and fires alerts for:
//   - concurrent_sessions: same user active from >3 IPs simultaneously
//   - new_country_login:   first login from a new country (GeoIP)

package logintrack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/geoip"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const (
	concurrentSessionThresh = 3
	bruteForceFailThreshold = 5
	bruteForceWindow        = 10 * time.Minute
	stuffingIPThreshold     = 8
	stuffingWindow          = 10 * time.Minute
)

type LoginStore interface {
	InsertLoginSession(ctx context.Context, ls *models.LoginSession) error
	CloseLoginSession(ctx context.Context, userUID, tenantID string, loggedOutAt time.Time) error
	InsertAlert(ctx context.Context, a *models.Alert) error
}

type Tracker struct {
	store        LoginStore
	geo          *geoip.Client
	log          zerolog.Logger
	mu           sync.Mutex
	activeIPs    map[string]map[string]time.Time // uid -> (ip -> loginAt)
	knownCountry map[string]map[string]bool      // uid -> countryCode -> seen
	bruteLogins  map[string][]time.Time          // uid -> failed login timestamps
	stuffing     map[string]map[string]time.Time // src_ip -> uid -> last failure time
}

func New(st *store.Store, log zerolog.Logger) *Tracker {
	return &Tracker{
		store:        st,
		geo:          geoip.New(),
		log:          log.With().Str("component", "login-tracker").Logger(),
		activeIPs:    make(map[string]map[string]time.Time),
		knownCountry: make(map[string]map[string]bool),
		bruteLogins:  make(map[string][]time.Time),
		stuffing:     make(map[string]map[string]time.Time),
	}
}

func (t *Tracker) Track(ctx context.Context, ev *models.XdrEvent) {
	uid := ev.UserUID
	if uid == "" {
		return
	}
	switch ev.Event.EventType {
	case "AUTH_LOGIN", "IDENTITY_AUTH_LOGIN", "IDENTITY_AUTH_LOGIN_FAILED":
		t.handleLogin(ctx, uid, ev)
	case "AUTH_LOGOFF", "IDENTITY_AUTH_LOGOFF":
		t.handleLogoff(ctx, uid, ev)
	}
}

func (t *Tracker) handleLogin(ctx context.Context, uid string, ev *models.XdrEvent) {
	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	var srcIPStr *string
	if ev.SrcIP != nil {
		s := ev.SrcIP.String()
		srcIPStr = &s
	}

	ls := &models.LoginSession{
		ID:         "lsess-" + uuid.New().String(),
		TenantID:   ev.TenantID,
		UserUID:    uid,
		AgentID:    ev.AgentID,
		SrcIP:      srcIPStr,
		Hostname:   ev.Event.Hostname,
		LoggedInAt: ts,
		EventID:    ev.Event.ID,
	}
	if err := t.store.InsertLoginSession(ctx, ls); err != nil {
		t.log.Warn().Err(err).Str("uid", uid).Msg("insert login session failed")
	}

	isFailure := strings.HasSuffix(ev.Event.EventType, "_FAILED") || isLoginFailed(ev.Event.Payload)

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.activeIPs[uid] == nil {
		t.activeIPs[uid] = make(map[string]time.Time)
	}
	if srcIPStr != nil {
		t.activeIPs[uid][*srcIPStr] = ts
	}

	// Concurrent sessions alert
	if len(t.activeIPs[uid]) > concurrentSessionThresh {
		count := len(t.activeIPs[uid])
		go t.fireConcurrentSessionAlert(ctx, uid, ev, count)
	}

	// New country detection
	if ev.SrcIP != nil {
		loc, err := t.geo.Lookup(*ev.SrcIP)
		if err == nil && loc != nil && loc.Country != "" {
			cc := loc.Country
			if t.knownCountry[uid] == nil {
				t.knownCountry[uid] = make(map[string]bool)
			}
			isNew := !t.knownCountry[uid][cc]
			isFirst := len(t.knownCountry[uid]) == 0
			t.knownCountry[uid][cc] = true
			if isNew && !isFirst {
				go t.fireNewCountryAlert(ctx, uid, ev, cc)
			}
		}
	}

	// Brute force → account takeover
	if isFailure {
		t.bruteLogins[uid] = pruneLoginTimes(t.bruteLogins[uid], bruteForceWindow, ts)
		t.bruteLogins[uid] = append(t.bruteLogins[uid], ts)

		// Credential stuffing: track unique accounts failing from same IP
		if srcIPStr != nil {
			if t.stuffing[*srcIPStr] == nil {
				t.stuffing[*srcIPStr] = make(map[string]time.Time)
			}
			cutoff := ts.Add(-stuffingWindow)
			for u, prevTime := range t.stuffing[*srcIPStr] {
				if prevTime.Before(cutoff) {
					delete(t.stuffing[*srcIPStr], u)
				}
			}
			t.stuffing[*srcIPStr][uid] = ts
			if len(t.stuffing[*srcIPStr]) >= stuffingIPThreshold {
				count := len(t.stuffing[*srcIPStr])
				go t.fireCredentialStuffingAlert(ctx, *srcIPStr, ev, count)
				// Reset to avoid repeated alerts for the same IP burst
				t.stuffing[*srcIPStr] = make(map[string]time.Time)
			}
		}
	} else {
		// Successful login — check if preceded by brute force failures
		failTimes := pruneLoginTimes(t.bruteLogins[uid], bruteForceWindow, ts)
		failCount := len(failTimes)
		t.bruteLogins[uid] = nil // reset on success
		if failCount >= bruteForceFailThreshold {
			go t.fireBruteForceSuccessAlert(ctx, uid, ev, failCount)
		}
	}
}

func (t *Tracker) handleLogoff(ctx context.Context, uid string, ev *models.XdrEvent) {
	ts := ev.Event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	if err := t.store.CloseLoginSession(ctx, uid, ev.TenantID, ts); err != nil {
		t.log.Warn().Err(err).Str("uid", uid).Msg("close login session failed")
	}
	if ev.SrcIP != nil {
		t.mu.Lock()
		if t.activeIPs[uid] != nil {
			delete(t.activeIPs[uid], ev.SrcIP.String())
		}
		t.mu.Unlock()
	}
}

func (t *Tracker) fireConcurrentSessionAlert(ctx context.Context, uid string, ev *models.XdrEvent, count int) {
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("Concurrent Sessions: %s (%d IPs)", uid, count),
		Description: fmt.Sprintf(
			"User %s has active sessions from %d different IP addresses simultaneously — possible credential sharing or compromise.",
			uid, count),
		Severity:    3,
		Status:      "OPEN",
		RuleID:      "rule-concurrent-sessions",
		RuleName:    "Concurrent Sessions",
		MitreIDs:    []string{"T1078"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		UserUID:     uid,
		SourceTypes: []string{"identity"},
	}
	if err := t.store.InsertAlert(ctx, alert); err != nil {
		t.log.Warn().Err(err).Str("uid", uid).Msg("concurrent sessions alert failed")
	} else {
		t.log.Warn().Str("uid", uid).Int("count", count).Msg("CONCURRENT SESSIONS ALERT FIRED")
	}
}

func (t *Tracker) fireNewCountryAlert(ctx context.Context, uid string, ev *models.XdrEvent, countryCode string) {
	srcIPStr := ""
	if ev.SrcIP != nil {
		srcIPStr = ev.SrcIP.String()
	}
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("New Country Login: %s from %s", uid, countryCode),
		Description: fmt.Sprintf(
			"User %s logged in from a new country (%s, IP: %s) not previously observed.",
			uid, countryCode, srcIPStr),
		Severity:    2,
		Status:      "OPEN",
		RuleID:      "rule-new-country-login",
		RuleName:    "New Country Login",
		MitreIDs:    []string{"T1078"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		UserUID:     uid,
		SrcIP:       srcIPStr,
		SourceTypes: []string{"identity"},
	}
	if err := t.store.InsertAlert(ctx, alert); err != nil {
		t.log.Warn().Err(err).Str("uid", uid).Msg("new country login alert failed")
	} else {
		t.log.Warn().Str("uid", uid).Str("country", countryCode).Msg("NEW COUNTRY LOGIN ALERT FIRED")
	}
}

func (t *Tracker) fireBruteForceSuccessAlert(ctx context.Context, uid string, ev *models.XdrEvent, failCount int) {
	srcIPStr := ""
	if ev.SrcIP != nil {
		srcIPStr = ev.SrcIP.String()
	}
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("Brute Force Account Takeover: %s", uid),
		Description: fmt.Sprintf(
			"User %s had %d failed login attempts in the last %d minutes followed by a successful authentication from %s — possible account takeover.",
			uid, failCount, int(bruteForceWindow.Minutes()), srcIPStr),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-itdr-brute-force-takeover",
		RuleName:    "Brute Force Account Takeover",
		MitreIDs:    []string{"T1110", "T1110.001"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		UserUID:     uid,
		SrcIP:       srcIPStr,
		SourceTypes: []string{"identity"},
	}
	if err := t.store.InsertAlert(ctx, alert); err != nil {
		t.log.Warn().Err(err).Str("uid", uid).Msg("brute force takeover alert failed")
	} else {
		t.log.Warn().Str("uid", uid).Int("fail_count", failCount).Str("src_ip", srcIPStr).Msg("BRUTE FORCE TAKEOVER ALERT FIRED")
	}
}

func (t *Tracker) fireCredentialStuffingAlert(ctx context.Context, srcIP string, ev *models.XdrEvent, accountCount int) {
	alert := &models.Alert{
		ID:       "alert-" + uuid.New().String(),
		TenantID: ev.TenantID,
		Title:    fmt.Sprintf("Credential Stuffing from %s", srcIP),
		Description: fmt.Sprintf(
			"IP %s attempted authentication against %d distinct accounts within %d minutes — consistent with a credential stuffing attack.",
			srcIP, accountCount, int(stuffingWindow.Minutes())),
		Severity:    4,
		Status:      "OPEN",
		RuleID:      "rule-itdr-credential-stuffing",
		RuleName:    "Credential Stuffing",
		MitreIDs:    []string{"T1110", "T1110.004"},
		EventIDs:    []string{ev.Event.ID},
		AgentID:     ev.AgentID,
		Hostname:    ev.Event.Hostname,
		SrcIP:       srcIP,
		SourceTypes: []string{"identity"},
	}
	if err := t.store.InsertAlert(ctx, alert); err != nil {
		t.log.Warn().Err(err).Str("src_ip", srcIP).Msg("credential stuffing alert failed")
	} else {
		t.log.Warn().Str("src_ip", srcIP).Int("account_count", accountCount).Msg("CREDENTIAL STUFFING ALERT FIRED")
	}
}

// pruneLoginTimes removes timestamps older than window relative to now.
func pruneLoginTimes(times []time.Time, window time.Duration, now time.Time) []time.Time {
	cutoff := now.Add(-window)
	out := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// isLoginFailed checks the event payload for an explicit failure outcome field.
func isLoginFailed(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var p map[string]interface{}
	if err := json.Unmarshal(payload, &p); err != nil {
		return false
	}
	if outcome, ok := p["outcome"].(string); ok {
		outcome = strings.ToUpper(outcome)
		return outcome == "FAILURE" || outcome == "FAILED" || outcome == "DENY" || outcome == "DENIED"
	}
	return false
}
