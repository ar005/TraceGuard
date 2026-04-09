// internal/monitor/driver/monitor.go
// Driver monitor for Windows — enumerates loaded kernel drivers via EnumDeviceDrivers.
//
// Polls periodically, compares with baseline, and emits KERNEL_MODULE_LOAD
// and KERNEL_MODULE_UNLOAD events for newly loaded or removed drivers.

package driver

import (
	"context"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

var (
	modPsapi                = windows.NewLazySystemDLL("psapi.dll")
	procEnumDeviceDrivers   = modPsapi.NewProc("EnumDeviceDrivers")
	procGetDeviceDriverBaseNameW = modPsapi.NewProc("GetDeviceDriverBaseNameW")
	procGetDeviceDriverFileNameW = modPsapi.NewProc("GetDeviceDriverFileNameW")
)

// Config for the driver monitor.
type Config struct {
	PollIntervalS int
}

// Monitor polls loaded drivers and detects changes.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a driver monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 5
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "driver").Logger(),
	}
}

// driverInfo holds details about a loaded driver.
type driverInfo struct {
	BaseAddr uintptr
	Name     string
	FilePath string
}

// Start begins polling for driver changes.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("driver monitor started (polling EnumDeviceDrivers)")
	return nil
}

// Stop halts the driver monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("driver monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	// Build initial baseline.
	known := make(map[uintptr]driverInfo)
	for _, d := range m.enumDrivers() {
		known[d.BaseAddr] = d
	}
	m.log.Debug().Int("baseline_drivers", len(known)).Msg("driver baseline captured")

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.enumDrivers()
			currentMap := make(map[uintptr]driverInfo)

			for _, d := range current {
				currentMap[d.BaseAddr] = d
				if _, exists := known[d.BaseAddr]; !exists {
					m.emitLoad(d)
				}
			}

			for addr, d := range known {
				if _, exists := currentMap[addr]; !exists {
					m.emitUnload(d)
				}
			}

			known = currentMap
		}
	}
}

func (m *Monitor) enumDrivers() []driverInfo {
	// First call: get needed buffer size.
	var needed uint32
	ret, _, _ := procEnumDeviceDrivers.Call(0, 0, uintptr(unsafe.Pointer(&needed)))
	if ret == 0 || needed == 0 {
		return nil
	}

	count := needed / uint32(unsafe.Sizeof(uintptr(0)))
	addrs := make([]uintptr, count)

	ret, _, _ = procEnumDeviceDrivers.Call(
		uintptr(unsafe.Pointer(&addrs[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ret == 0 {
		return nil
	}

	actualCount := needed / uint32(unsafe.Sizeof(uintptr(0)))
	if actualCount > count {
		actualCount = count
	}

	var drivers []driverInfo
	for i := uint32(0); i < actualCount; i++ {
		addr := addrs[i]
		if addr == 0 {
			continue
		}

		name := m.getDriverBaseName(addr)
		filePath := m.getDriverFileName(addr)

		drivers = append(drivers, driverInfo{
			BaseAddr: addr,
			Name:     name,
			FilePath: filePath,
		})
	}

	return drivers
}

func (m *Monitor) getDriverBaseName(addr uintptr) string {
	var buf [260]uint16
	ret, _, _ := procGetDeviceDriverBaseNameW.Call(
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

func (m *Monitor) getDriverFileName(addr uintptr) string {
	var buf [260]uint16
	ret, _, _ := procGetDeviceDriverFileNameW.Call(
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

func (m *Monitor) emitLoad(d driverInfo) {
	ev := &types.KernelModuleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventKernelModuleLoad,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityLow,
			Tags:      []string{"driver"},
		},
		ModuleName: d.Name,
		FilePath:   d.FilePath,
	}

	m.bus.Publish(ev)
	m.log.Info().Str("driver", d.Name).Str("path", d.FilePath).Msg("driver loaded")
}

func (m *Monitor) emitUnload(d driverInfo) {
	ev := &types.KernelModuleEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventKernelModuleUnload,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityLow,
			Tags:      []string{"driver"},
		},
		ModuleName: d.Name,
		FilePath:   d.FilePath,
	}

	m.bus.Publish(ev)
	m.log.Info().Str("driver", d.Name).Msg("driver unloaded")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
