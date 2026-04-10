// internal/monitor/share/monitor.go
// Network share monitor for Windows — enumerates shares via `net share`.
//
// Polls periodically and emits SHARE_MOUNT / SHARE_UNMOUNT events
// when new shares appear or existing shares are removed.

package share

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

// Config for the share monitor.
type Config struct {
	PollIntervalS int
}

// Monitor polls network shares and detects changes.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a share monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 10
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "share").Logger(),
	}
}

// shareInfo holds parsed share details.
type shareInfo struct {
	Name     string
	Resource string
	Remark   string
}

// Start begins polling for share changes.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("share monitor started (polling net share)")
	return nil
}

// Stop halts the share monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("share monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[string]shareInfo)
	for _, s := range m.enumShares(ctx) {
		known[s.Name] = s
	}
	m.log.Debug().Int("baseline_shares", len(known)).Msg("share baseline captured")

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.enumShares(ctx)
			currentMap := make(map[string]shareInfo)

			for _, s := range current {
				currentMap[s.Name] = s
				if _, exists := known[s.Name]; !exists {
					m.emitMount(s)
				}
			}

			for name, s := range known {
				if _, exists := currentMap[name]; !exists {
					m.emitUnmount(s)
				}
			}

			known = currentMap
		}
	}
}

func (m *Monitor) enumShares(ctx context.Context) []shareInfo {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "net", "share")
	out, err := cmd.Output()
	if err != nil {
		m.log.Debug().Err(err).Msg("net share failed")
		return nil
	}

	return parseNetShare(out)
}

// parseNetShare parses `net share` output.
// Format:
//
//	Share name   Resource                        Remark
//	---------------------------------------------------------
//	C$           C:\                             Default share
//	IPC$                                         Remote IPC
func parseNetShare(data []byte) []shareInfo {
	var shares []shareInfo
	scanner := bufio.NewScanner(bytes.NewReader(data))

	inHeader := true
	for scanner.Scan() {
		line := scanner.Text()

		// Skip header lines.
		if inHeader {
			if strings.HasPrefix(line, "---") {
				inHeader = false
			}
			continue
		}

		// End of share list.
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "The command completed") {
			continue
		}

		// Parse share line — name is the first field (up to first whitespace block).
		// The format is columnar, not CSV, so we parse by position.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Split on two or more spaces.
		parts := splitOnMultiSpace(trimmed)
		if len(parts) == 0 {
			continue
		}

		s := shareInfo{Name: parts[0]}
		if len(parts) > 1 {
			s.Resource = parts[1]
		}
		if len(parts) > 2 {
			s.Remark = parts[2]
		}

		shares = append(shares, s)
	}

	return shares
}

func splitOnMultiSpace(s string) []string {
	var parts []string
	current := ""
	spaceCount := 0

	for _, r := range s {
		if r == ' ' {
			spaceCount++
		} else {
			if spaceCount >= 2 && current != "" {
				parts = append(parts, strings.TrimSpace(current))
				current = ""
			} else if spaceCount == 1 {
				current += " "
			}
			spaceCount = 0
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, strings.TrimSpace(current))
	}
	return parts
}

func (m *Monitor) emitMount(s shareInfo) {
	// Admin shares (C$, IPC$, ADMIN$) are less interesting.
	severity := types.SeverityMedium
	var tags []string
	tags = append(tags, "share")
	if strings.HasSuffix(s.Name, "$") {
		severity = types.SeverityInfo
		tags = append(tags, "admin-share")
	}

	ev := &types.ShareMountEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventShareMount,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Tags:      tags,
		},
		Source:     s.Name,
		MountPoint: s.Resource,
		FSType:     "SMB",
		Options:    s.Remark,
	}

	m.bus.Publish(ev)
	m.log.Info().Str("share", s.Name).Str("resource", s.Resource).Msg("new share detected")
}

func (m *Monitor) emitUnmount(s shareInfo) {
	ev := &types.ShareMountEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventShareUnmount,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Tags:      []string{"share"},
		},
		Source:     s.Name,
		MountPoint: s.Resource,
		FSType:     "SMB",
	}

	m.bus.Publish(ev)
	m.log.Info().Str("share", s.Name).Msg("share removed")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
