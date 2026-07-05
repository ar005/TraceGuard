//go:build windows

// internal/monitor/dns/monitor.go
// DNS monitor for Windows.
//
// Primary path: ETW Microsoft-Windows-DNS-Client Event 3008 (QueryPerformed).
// Fires for every DNS resolution with sub-millisecond latency, PID attribution,
// and coverage of fast-flux domains whose cache TTL is shorter than a polling interval.
//
// Fallback: if the ETW session cannot be created (e.g. insufficient privilege or
// pre-Win10 build), the monitor transparently degrades to the original
// ipconfig /displaydns polling approach.

package dns

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/etw"
	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// QueryStatus values for ETW Event 3008.
const (
	queryStatusSuccess = 0
	queryStatusNXDomain = 9003 // DNS_ERROR_RCODE_NAME_ERROR — domain does not exist
)

// Config for the DNS monitor.
type Config struct{}

// Monitor subscribes to DNS-Client ETW events and emits NET_DNS events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	sess   *etw.Session
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a DNS monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "dns").Logger(),
	}
}

// Start registers the ETW DNS-Client provider and begins consuming events.
// Falls back to ipconfig /displaydns polling if the ETW session cannot be established.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	sess, err := etw.NewSession("TraceGuard-DNS")
	if err != nil {
		m.log.Warn().Err(err).Msg("ETW session unavailable, falling back to polling")
		return m.startPolling(ctx)
	}

	if err := sess.EnableProvider(etw.GUIDDNSClient, etw.TraceLevelInformation, 0xFFFFFFFFFFFFFFFF); err != nil {
		sess.Close()
		m.log.Warn().Err(err).Msg("ETW provider enable failed, falling back to polling")
		return m.startPolling(ctx)
	}

	sess.Subscribe(etw.GUIDDNSClient, m.handleETWEvent)
	m.sess = sess

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := sess.Consume(ctx); err != nil && ctx.Err() == nil {
			m.log.Error().Err(err).Msg("ETW consume error")
		}
	}()

	m.log.Info().Msg("DNS monitor started (ETW Microsoft-Windows-DNS-Client)")
	return nil
}

// Stop cancels the ETW session and waits for the dispatch goroutine to exit.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.sess != nil {
		m.sess.Close()
	}
	m.wg.Wait()
	m.log.Info().Msg("DNS monitor stopped")
}

// handleETWEvent processes Event 3008 (QueryPerformed) from the DNS-Client provider.
//
// Event 3008 UserData layout:
//
//	Offset  Type    Field
//	0       UINT32  QueryOptions  (flags; not used)
//	4       UINT32  QueryStatus   (0=success, 9003=NXDOMAIN)
//	8       UINT16  ResultCount
//	10      WSTR    QueryName     (null-terminated UTF-16)
//	…       WSTR    QueryResults  (semicolon-separated IPs, null-terminated UTF-16)
func (m *Monitor) handleETWEvent(ev etw.Event) {
	if ev.EventID != etw.EventDNSQuery {
		return
	}

	data := ev.UserData
	if len(data) < 12 {
		return
	}

	_, offset := etw.ReadUint32(data, 0)          // QueryOptions — unused
	status, offset := etw.ReadUint32(data, offset) // QueryStatus
	_, offset = etw.ReadUint16(data, offset)        // ResultCount — unused (count in results string)
	domain, offset := etw.ReadUTF16NullTerminated(data, offset)
	resultsStr, _ := etw.ReadUTF16NullTerminated(data, offset)

	if domain == "" {
		return
	}

	tags := []string{"dns"}
	var ips []string

	switch status {
	case queryStatusSuccess:
		for _, part := range strings.Split(resultsStr, ";") {
			if p := strings.TrimSpace(part); p != "" {
				ips = append(ips, p)
			}
		}
	case queryStatusNXDomain:
		tags = append(tags, "nxdomain")
	default:
		// Other error codes (SERVFAIL, REFUSED, etc.) — emit with no IPs.
	}

	m.bus.Publish(&types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventNetDNS,
			Timestamp: ev.Timestamp,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Tags:      tags,
			Process:   types.ProcessContext{PID: ev.ProcessID},
		},
		DNSQuery:    domain,
		ResolvedIPs: ips,
		Protocol:    types.ProtoUDP,
		DstPort:     53,
	})

	m.log.Debug().
		Str("domain", domain).
		Strs("ips", ips).
		Uint32("pid", ev.ProcessID).
		Uint32("status", status).
		Msg("DNS event")
}

// ── Polling fallback ──────────────────────────────────────────────────────────
// Used when the ETW session cannot be established. Behaviour is identical to
// the original implementation: ipconfig /displaydns every 5 s, 24 h dedup window.

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("DNS monitor started (polling ipconfig /displaydns)")
	return nil
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[string]time.Time)
	const knownTTL = 24 * time.Hour
	const knownCap = 10000

	for _, entry := range m.getDNSCache(ctx) {
		known[entry.Domain] = time.Now()
	}
	m.log.Debug().Int("baseline_entries", len(known)).Msg("DNS cache baseline captured")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	sweepTicker := time.NewTicker(10 * time.Minute)
	defer sweepTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepTicker.C:
			cutoff := time.Now().Add(-knownTTL)
			for d, t := range known {
				if t.Before(cutoff) {
					delete(known, d)
				}
			}
			if len(known) > knownCap {
				known = make(map[string]time.Time)
			}
		case <-ticker.C:
			for _, entry := range m.getDNSCache(ctx) {
				if _, seen := known[entry.Domain]; !seen {
					m.emitDNSPolled(entry)
				}
				known[entry.Domain] = time.Now()
			}
		}
	}
}

func (m *Monitor) getDNSCache(ctx context.Context) []dnsEntry {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(cmdCtx, "ipconfig", "/displaydns").Output()
	if err != nil {
		m.log.Debug().Err(err).Msg("ipconfig /displaydns failed")
		return nil
	}
	return parseDNSOutput(out)
}

func (m *Monitor) emitDNSPolled(entry dnsEntry) {
	m.bus.Publish(&types.NetworkEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventNetDNS,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Tags:      []string{"dns"},
		},
		DNSQuery:    entry.Domain,
		ResolvedIPs: entry.IPs,
		Protocol:    types.ProtoUDP,
		DstPort:     53,
	})
	m.log.Debug().Str("domain", entry.Domain).Strs("ips", entry.IPs).Msg("DNS cache entry (polled)")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
