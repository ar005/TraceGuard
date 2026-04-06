// internal/monitor/memmon/monitor.go
// Memory injection monitor for Windows — scans process memory for RWX regions.
//
// Uses CreateToolhelp32Snapshot to enumerate processes, then OpenProcess +
// VirtualQueryEx to scan memory regions. Flags MEM_PRIVATE regions with
// PAGE_EXECUTE_READWRITE protection as potential injection indicators.
//
// Skips known JIT processes: java.exe, node.exe, chrome.exe, firefox.exe, msedge.exe, etc.

package memmon

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

const (
	// Memory protection constants.
	pageExecuteReadWrite = 0x40 // PAGE_EXECUTE_READWRITE
	memPrivate           = 0x20000 // MEM_PRIVATE
	memCommit            = 0x1000 // MEM_COMMIT
)

// MEMORY_BASIC_INFORMATION for VirtualQueryEx.
type memoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	_                 [2]byte
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var (
	modKernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx = modKernel32.NewProc("VirtualQueryEx")
)

// Config for the memory monitor.
type Config struct {
	PollIntervalS int
	IgnoreComms   []string
}

// Monitor scans process memory for suspicious RWX regions.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// Tracks (PID, BaseAddress) already reported to avoid spam.
	reported map[reportKey]bool
	reportMu sync.Mutex
}

type reportKey struct {
	PID  uint32
	Addr uintptr
}

// New creates a memory monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 15
	}
	if len(cfg.IgnoreComms) == 0 {
		cfg.IgnoreComms = []string{
			"java.exe", "javaw.exe", "node.exe", "python.exe", "python3.exe",
			"chrome.exe", "firefox.exe", "msedge.exe", "code.exe",
			"dotnet.exe", "pwsh.exe", "powershell.exe",
		}
	}
	return &Monitor{
		cfg:      cfg,
		bus:      bus,
		log:      log.With().Str("monitor", "memmon").Logger(),
		reported: make(map[reportKey]bool),
	}
}

// Start begins scanning process memory.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("memory monitor started (scanning for RWX regions)")
	return nil
}

// Stop halts the memory monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("memory monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanProcesses()
		}
	}
}

func (m *Monitor) scanProcesses() {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		m.log.Error().Err(err).Msg("CreateToolhelp32Snapshot failed")
		return
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(handle, &entry); err != nil {
		return
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		pid := entry.ProcessID

		// Skip system processes and self.
		if pid > 4 && !m.isIgnored(name) {
			m.scanProcess(pid, name)
		}

		if err := windows.Process32Next(handle, &entry); err != nil {
			break
		}
	}
}

func (m *Monitor) isIgnored(name string) bool {
	lower := strings.ToLower(name)
	for _, ignore := range m.cfg.IgnoreComms {
		if strings.ToLower(ignore) == lower {
			return true
		}
	}
	return false
}

func (m *Monitor) scanProcess(pid uint32, name string) {
	hProc, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		// Access denied is normal for system/protected processes.
		return
	}
	defer windows.CloseHandle(hProc)

	var addr uintptr
	var mbi memoryBasicInfo
	mbiSize := unsafe.Sizeof(mbi)

	for {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(hProc),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			mbiSize,
		)
		if ret == 0 {
			break
		}

		// Check for committed, private, RWX regions.
		if mbi.State == memCommit &&
			mbi.Type == memPrivate &&
			mbi.Protect == pageExecuteReadWrite {

			key := reportKey{PID: pid, Addr: mbi.BaseAddress}
			m.reportMu.Lock()
			alreadyReported := m.reported[key]
			if !alreadyReported {
				m.reported[key] = true
			}
			m.reportMu.Unlock()

			if !alreadyReported {
				m.emitInject(pid, name, mbi.BaseAddress, mbi.RegionSize)
			}
		}

		// Advance to next region.
		addr = mbi.BaseAddress + mbi.RegionSize
		if addr <= mbi.BaseAddress {
			break // overflow protection
		}
	}
}

func (m *Monitor) emitInject(pid uint32, comm string, addr uintptr, size uintptr) {
	ev := &types.MemoryInjectEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventMemoryInject,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityHigh,
			Tags:      []string{"memory", "rwx", "injection"},
			Process:   types.ProcessContext{PID: pid, Comm: comm},
		},
		TargetPID:   pid,
		TargetComm:  comm,
		Address:     fmt.Sprintf("0x%x", addr),
		Size:        int64(size),
		Permissions: "RWX",
		Description: "Private RWX memory region detected (potential code injection)",
		Technique:   "T1055",
	}

	m.bus.Publish(ev)
	m.log.Warn().
		Uint32("pid", pid).
		Str("process", comm).
		Str("address", fmt.Sprintf("0x%x", addr)).
		Int64("size", int64(size)).
		Msg("suspicious RWX memory region detected")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
