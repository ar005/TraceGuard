// internal/logintrack/tracker.go
//
// LoginTracker records every AUTH_LOGIN / AUTH_LOGOFF event to login_sessions
// and fires alerts for:
//   - concurrent_sessions: same user active from >3 IPs simultaneously
//   - new_country_login:   first login from a new country (GeoIP)

package logintrack

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/geoip"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
)

const concurrentSessionThresh = 3

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
}

func New(st *store.Store, log zerolog.Logger) *Tracker {
	return &Tracker{
		store:        st,
		geo:          geoip.New(),
		log:          log.With().Str("component", "login-tracker").Logger(),
		activeIPs:    make(map[string]map[string]time.Time),
		knownCountry: make(map[string]map[string]bool),
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
