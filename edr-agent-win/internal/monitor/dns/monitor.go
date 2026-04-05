// internal/monitor/dns/monitor.go
// DNS monitor for Windows — polls DNS client cache for query visibility.
// Future: ETW Microsoft-Windows-DNS-Client for real-time DNS queries with PID.
//
// Parses output of `ipconfig /displaydns` to extract cached DNS records
// and emits NET_DNS events for new domains.

package dns

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// Config for the DNS monitor.
type Config struct{}

// Monitor polls the Windows DNS cache for new entries.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
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

// dnsEntry represents a parsed DNS cache record.
type dnsEntry struct {
	Domain string
	IPs    []string
}

// Start begins polling the DNS cache.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("DNS monitor started (polling DNS cache)")
	return nil
}

// Stop halts the DNS monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("DNS monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Track known domains to only emit new ones.
	known := make(map[string]bool)

	// Build initial baseline.
	for _, entry := range m.getDNSCache(ctx) {
		known[entry.Domain] = true
	}
	m.log.Debug().Int("baseline_entries", len(known)).Msg("DNS cache baseline captured")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			entries := m.getDNSCache(ctx)
			for _, entry := range entries {
				if !known[entry.Domain] {
					m.emitDNS(entry)
					known[entry.Domain] = true
				}
			}
		}
	}
}

// getDNSCache runs `ipconfig /displaydns` and parses the output.
func (m *Monitor) getDNSCache(ctx context.Context) []dnsEntry {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "ipconfig", "/displaydns")
	out, err := cmd.Output()
	if err != nil {
		m.log.Debug().Err(err).Msg("ipconfig /displaydns failed")
		return nil
	}

	return parseDNSOutput(out)
}

// parseDNSOutput parses the ipconfig /displaydns output into entries.
// Format:
//
//	Record Name . . . . . : example.com
//	A (Host) Record . . . : 93.184.216.34
func parseDNSOutput(data []byte) []dnsEntry {
	var entries []dnsEntry
	var current *dnsEntry

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "Record Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				domain := strings.TrimSpace(parts[1])
				if domain != "" {
					current = &dnsEntry{Domain: domain}
				}
			}
		} else if current != nil && strings.Contains(line, "A (Host) Record") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				if ip != "" {
					current.IPs = append(current.IPs, ip)
				}
			}
		} else if current != nil && strings.Contains(line, "AAAA Record") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				if ip != "" {
					current.IPs = append(current.IPs, ip)
				}
			}
		} else if line == "" && current != nil {
			if current.Domain != "" {
				entries = append(entries, *current)
			}
			current = nil
		}
	}
	// Flush last entry.
	if current != nil && current.Domain != "" {
		entries = append(entries, *current)
	}

	return entries
}

func (m *Monitor) emitDNS(entry dnsEntry) {
	ev := &types.NetworkEvent{
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
	}

	m.bus.Publish(ev)
	m.log.Debug().Str("domain", entry.Domain).Strs("ips", entry.IPs).Msg("DNS cache entry")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
