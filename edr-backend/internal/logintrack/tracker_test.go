package logintrack

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

/* ── Mock LoginStore ────────────────────────────────────────────── */

type mockStore struct {
	mu     sync.Mutex
	alerts []*models.Alert
	ch     chan *models.Alert
}

func newMockStore(buf int) *mockStore {
	return &mockStore{ch: make(chan *models.Alert, buf)}
}

func (m *mockStore) InsertLoginSession(_ context.Context, _ *models.LoginSession) error {
	return nil
}

func (m *mockStore) CloseLoginSession(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

func (m *mockStore) InsertAlert(_ context.Context, a *models.Alert) error {
	m.mu.Lock()
	m.alerts = append(m.alerts, a)
	m.mu.Unlock()
	m.ch <- a
	return nil
}

/* ── Test helpers ───────────────────────────────────────────────── */

func newTracker(st *mockStore) *Tracker {
	return &Tracker{
		store:        st,
		geo:          nil, // geoip not needed for these tests
		log:          zerolog.Nop(),
		activeIPs:    make(map[string]map[string]time.Time),
		knownCountry: make(map[string]map[string]bool),
		bruteLogins:  make(map[string][]time.Time),
		stuffing:     make(map[string]map[string]time.Time),
	}
}

func failedLoginEvent(id, uid string, ts time.Time, srcIP *net.IP) *models.XdrEvent {
	return &models.XdrEvent{
		Event: models.Event{
			ID:        id,
			EventType: "IDENTITY_AUTH_LOGIN_FAILED",
			Timestamp: ts,
		},
		UserUID: uid,
		SrcIP:   srcIP,
	}
}

func successLoginEvent(id, uid string, ts time.Time, srcIP *net.IP) *models.XdrEvent {
	return &models.XdrEvent{
		Event: models.Event{
			ID:        id,
			EventType: "AUTH_LOGIN",
			Timestamp: ts,
		},
		UserUID: uid,
		SrcIP:   srcIP,
	}
}

func waitAlert(t *testing.T, ch <-chan *models.Alert, pred func(*models.Alert) bool) *models.Alert {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case a := <-ch:
			if pred(a) {
				return a
			}
		case <-deadline:
			t.Fatal("timed out waiting for expected alert")
			return nil
		}
	}
}

func expectNoAlert(t *testing.T, ch <-chan *models.Alert, wait time.Duration) {
	t.Helper()
	select {
	case a := <-ch:
		t.Errorf("unexpected alert fired: rule_id=%s title=%s", a.RuleID, a.Title)
	case <-time.After(wait):
		// good — no alert
	}
}

/* ── Brute Force Account Takeover ───────────────────────────────── */

func TestBruteForceAlertFiredAtThreshold(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	uid := "victim@example.com"

	// Send exactly bruteForceFailThreshold failures
	for i := range bruteForceFailThreshold {
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("f%d", i), uid, now.Add(time.Duration(i)*time.Minute), nil))
	}

	// Successful login at t+6m (still within 10m window)
	tr.Track(ctx, successLoginEvent("ok", uid, now.Add(6*time.Minute), nil))

	a := waitAlert(t, st.ch, func(a *models.Alert) bool {
		return a.RuleID == "rule-itdr-brute-force-takeover"
	})
	if a.Severity != 4 {
		t.Errorf("expected severity 4, got %d", a.Severity)
	}
	if a.UserUID != uid {
		t.Errorf("expected user_uid=%s, got %s", uid, a.UserUID)
	}
}

func TestBruteForceNotFiredBelowThreshold(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	uid := "user@example.com"

	// One fewer failure than threshold
	for i := range bruteForceFailThreshold - 1 {
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("f%d", i), uid, now.Add(time.Duration(i)*time.Minute), nil))
	}
	tr.Track(ctx, successLoginEvent("ok", uid, now.Add(5*time.Minute), nil))

	expectNoAlert(t, st.ch, 300*time.Millisecond)
}

func TestBruteForceExpiredFailuresNotCounted(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	uid := "user@example.com"

	// Send 5 failures but all outside the 10-minute window
	old := now.Add(-15 * time.Minute)
	for i := range bruteForceFailThreshold {
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("f%d", i), uid, old.Add(time.Duration(i)*time.Second), nil))
	}
	tr.Track(ctx, successLoginEvent("ok", uid, now, nil))

	expectNoAlert(t, st.ch, 300*time.Millisecond)
}

func TestBruteForceResetsAfterSuccess(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	uid := "user@example.com"

	// First sequence: 5 failures → success → alert fires
	for i := range bruteForceFailThreshold {
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("a%d", i), uid, now.Add(time.Duration(i)*time.Minute), nil))
	}
	tr.Track(ctx, successLoginEvent("ok1", uid, now.Add(6*time.Minute), nil))
	waitAlert(t, st.ch, func(a *models.Alert) bool { return a.RuleID == "rule-itdr-brute-force-takeover" })

	// Second sequence: only 2 failures → success → no new alert
	for i := range 2 {
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("b%d", i), uid, now.Add(time.Duration(7+i)*time.Minute), nil))
	}
	tr.Track(ctx, successLoginEvent("ok2", uid, now.Add(10*time.Minute), nil))

	expectNoAlert(t, st.ch, 300*time.Millisecond)
}

/* ── Credential Stuffing ─────────────────────────────────────────── */

func TestCredentialStuffingAlertFiredAtThreshold(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	attackerIP := net.ParseIP("203.0.113.99")

	for i := range stuffingIPThreshold {
		uid := fmt.Sprintf("account%d@corp.com", i)
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("s%d", i), uid, now.Add(time.Duration(i)*30*time.Second), &attackerIP))
	}

	a := waitAlert(t, st.ch, func(a *models.Alert) bool {
		return a.RuleID == "rule-itdr-credential-stuffing"
	})
	if a.Severity != 4 {
		t.Errorf("expected severity 4, got %d", a.Severity)
	}
	if a.SrcIP != attackerIP.String() {
		t.Errorf("expected src_ip=%s, got %s", attackerIP.String(), a.SrcIP)
	}
}

func TestCredentialStuffingNotFiredBelowThreshold(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	attackerIP := net.ParseIP("203.0.113.100")

	// One fewer than threshold
	for i := range stuffingIPThreshold - 1 {
		uid := fmt.Sprintf("account%d@corp.com", i)
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("s%d", i), uid, now.Add(time.Duration(i)*30*time.Second), &attackerIP))
	}

	expectNoAlert(t, st.ch, 300*time.Millisecond)
}

func TestCredentialStuffingDifferentIPsNotAggregated(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()

	// stuffingIPThreshold failures but from different IPs — should not trigger
	for i := range stuffingIPThreshold {
		ip := net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1))
		uid := fmt.Sprintf("account%d@corp.com", i)
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("s%d", i), uid, now.Add(time.Duration(i)*30*time.Second), &ip))
	}

	expectNoAlert(t, st.ch, 300*time.Millisecond)
}

func TestCredentialStuffingResetsAfterFiring(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	attackerIP := net.ParseIP("203.0.113.101")

	// First burst: fires alert and resets map
	for i := range stuffingIPThreshold {
		uid := fmt.Sprintf("firstbatch%d@corp.com", i)
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("f%d", i), uid, now.Add(time.Duration(i)*30*time.Second), &attackerIP))
	}
	waitAlert(t, st.ch, func(a *models.Alert) bool { return a.RuleID == "rule-itdr-credential-stuffing" })

	// Immediately after reset: only 2 more failures — should not fire again
	for i := range 2 {
		uid := fmt.Sprintf("secondbatch%d@corp.com", i)
		tr.Track(ctx, failedLoginEvent(fmt.Sprintf("g%d", i), uid, now.Add(time.Duration(stuffingIPThreshold+i)*30*time.Second), &attackerIP))
	}
	expectNoAlert(t, st.ch, 300*time.Millisecond)
}

/* ── Concurrent Sessions ─────────────────────────────────────────── */

func TestConcurrentSessionsAlertFired(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	uid := "executive@corp.com"

	// concurrentSessionThresh + 1 logins from different IPs triggers alert
	for i := range concurrentSessionThresh + 1 {
		ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1))
		tr.Track(ctx, successLoginEvent(fmt.Sprintf("cs%d", i), uid, now.Add(time.Duration(i)*time.Second), &ip))
	}

	a := waitAlert(t, st.ch, func(a *models.Alert) bool {
		return a.RuleID == "rule-concurrent-sessions"
	})
	if a.UserUID != uid {
		t.Errorf("expected user_uid=%s, got %s", uid, a.UserUID)
	}
}

func TestConcurrentSessionsNotFiredAtThreshold(t *testing.T) {
	st := newMockStore(20)
	tr := newTracker(st)
	ctx := context.Background()
	now := time.Now()
	uid := "user@corp.com"

	// Exactly concurrentSessionThresh IPs — must not fire (threshold is strictly >)
	for i := range concurrentSessionThresh {
		ip := net.ParseIP(fmt.Sprintf("192.168.2.%d", i+1))
		tr.Track(ctx, successLoginEvent(fmt.Sprintf("cs%d", i), uid, now.Add(time.Duration(i)*time.Second), &ip))
	}

	expectNoAlert(t, st.ch, 300*time.Millisecond)
}
