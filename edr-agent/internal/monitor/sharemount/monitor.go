// Package sharemount monitors network filesystem mounts (NFS, CIFS, SMB)
// by polling /proc/mounts. Detects lateral movement via new share mounts.
// Emits SHARE_MOUNT and SHARE_UNMOUNT events.

package sharemount

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// networkFSTypes are the filesystem types we consider network shares.
var networkFSTypes = map[string]bool{
	"cifs":  true,
	"nfs":   true,
	"nfs4":  true,
	"smbfs": true,
}

// mountInfo holds parsed info for a single network mount.
type mountInfo struct {
	Source     string
	MountPoint string
	FSType     string
	Options    string
	RemoteHost string
}

// Config for the network share monitor.
type Config struct {
	Enabled       bool
	PollIntervalS int // default 10
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{Enabled: true, PollIntervalS: 10}
}

// Monitor polls /proc/mounts to detect network share mount/unmount events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates a new network share mount monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 10
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "sharemount").Logger(),
		stopCh: make(chan struct{}),
	}
}

// Start begins polling /proc/mounts for network share changes.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		m.log.Info().Msg("network share monitor disabled")
		return nil
	}

	// Take initial baseline snapshot.
	baseline, err := readNetworkMounts()
	if err != nil {
		return err
	}
	m.log.Info().Int("mounts", len(baseline)).Msg("network share monitor baseline captured")

	m.wg.Add(1)
	go m.pollLoop(ctx, baseline)
	return nil
}

// Stop signals the monitor to shut down and waits for completion.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Monitor) pollLoop(ctx context.Context, baseline map[string]mountInfo) {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			current, err := readNetworkMounts()
			if err != nil {
				m.log.Error().Err(err).Msg("failed to read /proc/mounts")
				continue
			}

			// Detect new mounts.
			for mp, info := range current {
				if _, existed := baseline[mp]; !existed {
					m.log.Warn().
						Str("source", info.Source).
						Str("mount_point", mp).
						Str("fs_type", info.FSType).
						Str("remote_host", info.RemoteHost).
						Msg("network share mounted")
					m.emitEvent(types.EventShareMount, info)
				}
			}

			// Detect unmounts.
			for mp, info := range baseline {
				if _, exists := current[mp]; !exists {
					m.log.Warn().
						Str("source", info.Source).
						Str("mount_point", mp).
						Str("fs_type", info.FSType).
						Msg("network share unmounted")
					m.emitEvent(types.EventShareUnmount, info)
				}
			}

			// Update baseline.
			baseline = current
		}
	}
}

func (m *Monitor) emitEvent(eventType types.EventType, info mountInfo) {
	sev := types.SeverityMedium
	if eventType == types.EventShareUnmount {
		sev = types.SeverityLow
	}

	ev := &types.ShareMountEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      eventType,
			Timestamp: time.Now(),
			Severity:  sev,
		},
		Source:     info.Source,
		MountPoint: info.MountPoint,
		FSType:     info.FSType,
		Options:    info.Options,
		RemoteHost: info.RemoteHost,
	}

	m.bus.Publish(ev)
}

// readNetworkMounts parses /proc/mounts and returns only network filesystem entries.
// Format: device mountpoint fstype options dump pass
func readNetworkMounts() (map[string]mountInfo, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	mounts := make(map[string]mountInfo)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		fsType := fields[2]
		if !networkFSTypes[fsType] {
			continue
		}

		source := fields[0]
		mountPoint := fields[1]
		options := fields[3]
		remoteHost := extractRemoteHost(source, fsType)

		mounts[mountPoint] = mountInfo{
			Source:     source,
			MountPoint: mountPoint,
			FSType:     fsType,
			Options:    options,
			RemoteHost: remoteHost,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

// extractRemoteHost extracts the hostname or IP from a mount source string.
//
//	CIFS: //hostname/share  -> hostname
//	NFS:  hostname:/export  -> hostname
func extractRemoteHost(source, fsType string) string {
	switch {
	case fsType == "cifs" || fsType == "smbfs":
		// Format: //hostname/share or //ip/share
		s := strings.TrimPrefix(source, "//")
		if idx := strings.Index(s, "/"); idx > 0 {
			return s[:idx]
		}
		return s
	case fsType == "nfs" || fsType == "nfs4":
		// Format: hostname:/export/path
		if idx := strings.Index(source, ":"); idx > 0 {
			return source[:idx]
		}
		return source
	default:
		return source
	}
}
