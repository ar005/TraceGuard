//go:build windows

// internal/monitor/process/monitor.go
// Process monitor for Windows.
//
// Primary path: ETW Microsoft-Windows-Kernel-Process provider, Events 1 and 2.
// Delivers PROCESS_EXEC / PROCESS_EXIT in real time — fixes WIN-M2 (original
// polling had a 2-second detection lag). A one-time CreateToolhelp32Snapshot
// baseline logs existing processes at startup; ETW handles all new ones.
//
// Command line is read from the process PEB via NtQueryInformationProcess +
// ReadProcessMemory, replacing the original wmic subprocess (5-second timeout).
//
// Fallback: if the ETW session cannot be created, degrades to the original
// 2-second polling approach.

package process

import (
	"context"
	"encoding/binary"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/etw"
	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

var (
	modNtdll                     = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
)

// Config for the process monitor.
type Config struct {
	MaxAncestryDepth int
}

// Monitor watches for process start and stop events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	sess   *etw.Session
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a process monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.MaxAncestryDepth <= 0 {
		cfg.MaxAncestryDepth = 5
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "process").Logger(),
	}
}

// Start takes a one-time snapshot baseline, then subscribes to
// Microsoft-Windows-Kernel-Process ETW events for real-time coverage.
// Falls back to polling if the ETW session cannot be created.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	// Log baseline count so the backend knows how many processes existed
	// before the agent started (these are not emitted as PROCESS_EXEC events).
	m.logBaseline()

	sess, err := etw.NewSession("TraceGuard-Process")
	if err != nil {
		m.log.Warn().Err(err).Msg("ETW session unavailable, falling back to polling")
		return m.startPolling(ctx)
	}

	if err := sess.EnableProvider(etw.GUIDKernelProcess, etw.TraceLevelInformation, 0xFFFFFFFFFFFFFFFF); err != nil {
		sess.Close()
		m.log.Warn().Err(err).Msg("ETW provider enable failed, falling back to polling")
		return m.startPolling(ctx)
	}

	sess.Subscribe(etw.GUIDKernelProcess, m.handleETWEvent)
	m.sess = sess

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := sess.Consume(ctx); err != nil && ctx.Err() == nil {
			m.log.Error().Err(err).Msg("ETW consume error")
		}
	}()

	m.log.Info().Msg("process monitor started (ETW Microsoft-Windows-Kernel-Process)")
	return nil
}

// Stop cancels the ETW session and waits for all dispatch goroutines to finish.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.sess != nil {
		m.sess.Close()
	}
	m.wg.Wait()
	m.log.Info().Msg("process monitor stopped")
}

// handleETWEvent dispatches Kernel-Process events 1 (Start) and 2 (Stop).
// Heavy work (file hashing, PEB reads) runs in goroutines to keep the callback fast.
func (m *Monitor) handleETWEvent(ev etw.Event) {
	if ev.EventID != etw.EventProcessStart && ev.EventID != etw.EventProcessStop {
		return
	}

	pid, ppid, shortName, ok := parseProcessEventData(ev.UserData)
	if !ok || pid == 0 || pid == 4 {
		return
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if ev.EventID == etw.EventProcessStart {
			m.handleProcessStart(pid, ppid, shortName, ev.Timestamp)
		} else {
			m.handleProcessStop(pid, ppid, shortName, ev.Timestamp)
		}
	}()
}

func (m *Monitor) handleProcessStart(pid, ppid uint32, shortName string, ts time.Time) {
	info := &procInfo{PID: pid, PPID: ppid, ExePath: shortName, CreateTime: ts}

	// Prefer full access for PEB-based command line read.
	// Fall back to limited info for protected/system processes.
	hProc, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid,
	)
	if err != nil {
		hProc, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	}
	if err == nil {
		var buf [windows.MAX_PATH]uint16
		size := uint32(len(buf))
		if windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size) == nil {
			info.ExePath = windows.UTF16ToString(buf[:size])
		}
		info.Cmdline = cmdlineFromHandle(hProc)
		windows.CloseHandle(hProc)
	}

	m.emitExec(info)
}

func (m *Monitor) handleProcessStop(pid, ppid uint32, shortName string, ts time.Time) {
	m.emitExit(&procInfo{PID: pid, PPID: ppid, ExePath: shortName, CreateTime: ts})
}

// ── PEB-based command line reader ─────────────────────────────────────────────
//
// Walks PEB → ProcessParameters → CommandLine via ReadProcessMemory.
// Replaces the original wmic subprocess (5-second timeout).
// Requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
//
// Struct offsets (amd64 Windows 10+):
//   PROCESS_BASIC_INFORMATION[8] = PebBaseAddress
//   PEB[0x20]                    = ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
//   RTL_USER_PROCESS_PARAMETERS[0x70] = CommandLine (UNICODE_STRING)
//   UNICODE_STRING: Length(2) + MaxLength(2) + pad(4) + Buffer(8) = 16 bytes

func cmdlineFromHandle(hProc windows.Handle) string {
	// PROCESS_BASIC_INFORMATION is 48 bytes on amd64; PebBaseAddress at offset 8.
	var pbi [48]byte
	var retLen uint32
	if status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProc), 0,
		uintptr(unsafe.Pointer(&pbi[0])), uintptr(len(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	); status != 0 {
		return ""
	}
	pebAddr := *(*uintptr)(unsafe.Pointer(&pbi[8]))
	if pebAddr == 0 {
		return ""
	}

	var procParamsPtr uintptr
	var nRead uintptr
	if err := windows.ReadProcessMemory(
		hProc, pebAddr+0x20,
		(*byte)(unsafe.Pointer(&procParamsPtr)), 8, &nRead,
	); err != nil || procParamsPtr == 0 {
		return ""
	}

	var us [16]byte
	if err := windows.ReadProcessMemory(
		hProc, procParamsPtr+0x70,
		&us[0], 16, &nRead,
	); err != nil {
		return ""
	}
	cmdLen := binary.LittleEndian.Uint16(us[0:2])
	cmdBuf := *(*uintptr)(unsafe.Pointer(&us[8]))
	if cmdLen == 0 || cmdBuf == 0 {
		return ""
	}

	words := make([]uint16, cmdLen/2)
	if err := windows.ReadProcessMemory(
		hProc, cmdBuf,
		(*byte)(unsafe.Pointer(&words[0])), uintptr(cmdLen), &nRead,
	); err != nil {
		return ""
	}
	return windows.UTF16ToString(words)
}

// ── emit helpers ──────────────────────────────────────────────────────────────

func (m *Monitor) emitExec(info *procInfo) {
	if info.PID == 0 || info.PID == 4 {
		return
	}

	severity := types.SeverityInfo
	if isSuspiciousExe(info.ExePath) {
		severity = types.SeverityLow
	}

	// Resolve cmdline if not already set (polling fallback path).
	cmdline := info.Cmdline
	if cmdline == "" {
		if hProc, err := windows.OpenProcess(
			windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, info.PID,
		); err == nil {
			cmdline = cmdlineFromHandle(hProc)
			windows.CloseHandle(hProc)
		}
	}

	args := splitArgs(cmdline)
	interpreter, scriptPath := detectInterpreter(info.ExePath, args)
	scriptContent := captureScriptContent(args, interpreter, scriptPath)
	exeHash, exeSize := hashFile(info.ExePath)
	ancestry := m.buildAncestry(info.PPID, m.cfg.MaxAncestryDepth)

	m.bus.Publish(&types.ProcessExecEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventProcessExec,
			Timestamp: info.CreateTime,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Process: types.ProcessContext{
				PID:       info.PID,
				PPID:      info.PPID,
				ExePath:   info.ExePath,
				Comm:      extractComm(info.ExePath),
				Cmdline:   cmdline,
				Args:      args,
				StartTime: info.CreateTime,
				Username:  info.Username,
			},
		},
		ParentProcess: types.ProcessContext{PID: info.PPID},
		ExeHash:       exeHash,
		ExeSize:       exeSize,
		Interpreter:   interpreter,
		ScriptPath:    scriptPath,
		ScriptContent: scriptContent,
		Ancestry:      ancestry,
	})
}

func (m *Monitor) emitExit(info *procInfo) {
	if info.PID == 0 || info.PID == 4 {
		return
	}
	m.bus.Publish(&types.ProcessExitEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventProcessExit,
			Timestamp: info.CreateTime,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Process: types.ProcessContext{
				PID:     info.PID,
				PPID:    info.PPID,
				ExePath: info.ExePath,
				Comm:    extractComm(info.ExePath),
			},
		},
	})
}

// ── Ancestry ──────────────────────────────────────────────────────────────────

func (m *Monitor) buildAncestry(ppid uint32, depth int) []types.ProcessContext {
	if depth <= 0 || ppid == 0 {
		return nil
	}
	var ancestry []types.ProcessContext
	cur := ppid
	for i := 0; i < depth && cur > 4; i++ {
		hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, cur)
		if err != nil {
			break
		}
		var buf [windows.MAX_PATH]uint16
		sz := uint32(len(buf))
		exePath := ""
		if windows.QueryFullProcessImageName(hProc, 0, &buf[0], &sz) == nil {
			exePath = windows.UTF16ToString(buf[:sz])
		}
		windows.CloseHandle(hProc)

		ancestry = append(ancestry, types.ProcessContext{
			PID:     cur,
			ExePath: exePath,
			Comm:    extractComm(exePath),
		})

		snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			break
		}
		var entry windows.ProcessEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		found := false
		if windows.Process32First(snap, &entry) == nil {
			for {
				if entry.ProcessID == cur {
					cur = entry.ParentProcessID
					found = true
					break
				}
				if windows.Process32Next(snap, &entry) != nil {
					break
				}
			}
		}
		windows.CloseHandle(snap)
		if !found {
			break
		}
	}
	return ancestry
}

// ── Baseline ──────────────────────────────────────────────────────────────────

func (m *Monitor) logBaseline() {
	procs := m.snapshot()
	m.log.Info().Int("existing_processes", len(procs)).Msg("process baseline captured")
}

// ── Polling fallback ──────────────────────────────────────────────────────────
// Preserved from original implementation; activated when ETW is unavailable.

type procInfo struct {
	PID        uint32
	PPID       uint32
	ExePath    string
	Cmdline    string
	Username   string
	CreateTime time.Time
}

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("process monitor started (polling CreateToolhelp32Snapshot)")
	return nil
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[uint32]*procInfo)
	for pid, info := range m.snapshot() {
		known[pid] = info
	}
	m.log.Debug().Int("baseline_processes", len(known)).Msg("process poll baseline")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.snapshot()
			for pid, info := range current {
				if _, exists := known[pid]; !exists {
					m.emitExec(info)
				}
			}
			for pid, info := range known {
				if _, exists := current[pid]; !exists {
					m.emitExit(info)
				}
			}
			known = current
		}
	}
}

func (m *Monitor) snapshot() map[uint32]*procInfo {
	result := make(map[uint32]*procInfo)

	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		m.log.Error().Err(err).Msg("CreateToolhelp32Snapshot failed")
		return result
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(handle, &entry); err != nil {
		return result
	}

	for {
		info := &procInfo{
			PID:        entry.ProcessID,
			PPID:       entry.ParentProcessID,
			ExePath:    windows.UTF16ToString(entry.ExeFile[:]),
			CreateTime: time.Now(),
		}
		if hProc, err := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID,
		); err == nil {
			var buf [windows.MAX_PATH]uint16
			sz := uint32(len(buf))
			if windows.QueryFullProcessImageName(hProc, 0, &buf[0], &sz) == nil {
				info.ExePath = windows.UTF16ToString(buf[:sz])
			}
			windows.CloseHandle(hProc)
		}
		result[entry.ProcessID] = info

		if err := windows.Process32Next(handle, &entry); err != nil {
			break
		}
	}
	return result
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
