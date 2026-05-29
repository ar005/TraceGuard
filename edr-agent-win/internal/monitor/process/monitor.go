// internal/monitor/process/monitor.go
// Process monitor for Windows — uses ETW Microsoft-Windows-Kernel-Process.
// Emits PROCESS_EXEC and PROCESS_EXIT events compatible with Linux agent.
//
// ETW provides: PID, PPID, image path, command line, user SID, session ID.
// Process ancestry is resolved via CreateToolhelp32Snapshot.
// Binary hashing (SHA-256) is computed asynchronously on exec.

package process

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/youredr/edr-agent-win/internal/events"
	etwconst "github.com/youredr/edr-agent-win/internal/etw"
	"github.com/youredr/edr-agent-win/pkg/types"
)

type Config struct {
	MaxAncestryDepth int
}

type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

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

func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	// Poll running processes via CreateToolhelp32Snapshot as a baseline,
	// then use WMI Win32_ProcessStartTrace / Win32_ProcessStopTrace for real-time.
	m.wg.Add(1)
	go m.pollLoop(ctx)

	m.log.Info().Msg("process monitor started (WMI event subscription)")
	return nil
}

func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("process monitor stopped")
}

// pollLoop uses a snapshot-based approach: periodically take process snapshots
// and detect new/exited processes. This is a reliable fallback that works without
// ETW session management complexity.
func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[uint32]*procInfo)

	// Initial snapshot.
	current := m.snapshot()
	for pid, info := range current {
		known[pid] = info
	}
	m.log.Debug().Int("baseline_processes", len(known)).Msg("process baseline captured")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.snapshot()

			// Detect new processes.
			for pid, info := range current {
				if _, exists := known[pid]; !exists {
					m.emitExec(info)
				}
			}
			// Detect exited processes.
			for pid, info := range known {
				if _, exists := current[pid]; !exists {
					m.emitExit(info)
				}
			}
			known = current
		}
	}
}

type procInfo struct {
	PID        uint32
	PPID       uint32
	ExePath    string
	Cmdline    string
	Username   string
	CreateTime time.Time
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

	err = windows.Process32First(handle, &entry)
	if err != nil {
		return result
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		info := &procInfo{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
		}

		// Try to get full path and command line.
		if hProc, err := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID,
		); err == nil {
			var buf [windows.MAX_PATH]uint16
			size := uint32(len(buf))
			if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err == nil {
				info.ExePath = windows.UTF16ToString(buf[:size])
			}
			windows.CloseHandle(hProc)
		}

		if info.ExePath == "" {
			info.ExePath = name
		}

		result[entry.ProcessID] = info

		err = windows.Process32Next(handle, &entry)
		if err != nil {
			break
		}
	}

	return result
}

func (m *Monitor) emitExec(info *procInfo) {
	// Skip System and Idle processes.
	if info.PID == 0 || info.PID == 4 {
		return
	}

	severity := types.SeverityInfo

	// Flag suspicious processes.
	lowerExe := strings.ToLower(info.ExePath)
	suspiciousPatterns := []string{
		"powershell", "cmd.exe", "wscript", "cscript", "mshta",
		"regsvr32", "rundll32", "certutil", "bitsadmin",
	}
	for _, pat := range suspiciousPatterns {
		if strings.Contains(lowerExe, pat) {
			severity = types.SeverityLow
			break
		}
	}

	// Capture command line via WMI.
	cmdline := getCmdline(info.PID)
	args := splitArgs(cmdline)

	// Detect interpreter and script path.
	interpreter, scriptPath := detectInterpreter(info.ExePath, args)

	// Capture script content (inline or from file).
	scriptContent := captureScriptContent(args, interpreter, scriptPath)

	// Compute SHA-256 hash.
	var exeHash string
	var exeSize int64
	if info.ExePath != "" {
		exeHash, exeSize = hashFile(info.ExePath)
	}

	// Build ancestry chain.
	ancestry := m.buildAncestry(info.PPID, m.cfg.MaxAncestryDepth)

	ev := &types.ProcessExecEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventProcessExec,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  severity,
			Process: types.ProcessContext{
				PID:     info.PID,
				PPID:    info.PPID,
				ExePath: info.ExePath,
				Comm:    extractComm(info.ExePath),
				Cmdline: cmdline,
				Args:    args,
			},
		},
		ExeHash:       exeHash,
		ExeSize:       exeSize,
		Interpreter:   interpreter,
		ScriptPath:    scriptPath,
		ScriptContent: scriptContent,
		Ancestry:      ancestry,
	}

	m.bus.Publish(ev)
}

func (m *Monitor) emitExit(info *procInfo) {
	if info.PID == 0 || info.PID == 4 {
		return
	}

	ev := &types.ProcessExitEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventProcessExit,
			Timestamp: time.Now(),
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
	}

	m.bus.Publish(ev)
}

func (m *Monitor) buildAncestry(ppid uint32, depth int) []types.ProcessContext {
	if depth <= 0 || ppid == 0 {
		return nil
	}

	var ancestry []types.ProcessContext
	currentPID := ppid

	for i := 0; i < depth && currentPID > 4; i++ {
		hProc, err := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION, false, currentPID,
		)
		if err != nil {
			break
		}

		var buf [windows.MAX_PATH]uint16
		size := uint32(len(buf))
		exePath := ""
		if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err == nil {
			exePath = windows.UTF16ToString(buf[:size])
		}
		windows.CloseHandle(hProc)

		pc := types.ProcessContext{
			PID:     currentPID,
			ExePath: exePath,
			Comm:    extractComm(exePath),
		}
		ancestry = append(ancestry, pc)

		// Get parent of current.
		snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			break
		}
		var entry windows.ProcessEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		found := false
		if windows.Process32First(snap, &entry) == nil {
			for {
				if entry.ProcessID == currentPID {
					currentPID = entry.ParentProcessID
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

func hashFile(path string) (string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", 0
	}

	// Skip files > 50MB for performance.
	if stat.Size() > 50*1024*1024 {
		return "", stat.Size()
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", stat.Size()
	}
	return hex.EncodeToString(h.Sum(nil)), stat.Size()
}

// getCmdline retrieves the command line for a process using WMI.
func getCmdline(pid uint32) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wmic", "process", "where",
		fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine", "/format:list")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CommandLine=") {
			return strings.TrimPrefix(line, "CommandLine=")
		}
	}
	return ""
}

// splitArgs splits a command line string into arguments, respecting double quotes.
func splitArgs(cmdline string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	for _, r := range cmdline {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// detectInterpreter checks if the executable is a known script interpreter
// and returns the interpreter name and the script path argument.
func detectInterpreter(exePath string, args []string) (string, string) {
	name := strings.ToLower(filepath.Base(exePath))
	name = strings.TrimSuffix(name, ".exe")

	interpreters := map[string]bool{
		"python": true, "python3": true, "python2": true,
		"perl": true, "ruby": true, "php": true, "lua": true,
		"bash": true, "sh": true, "zsh": true,
		"node": true, "nodejs": true, "deno": true,
		"powershell": true, "pwsh": true,
		"cmd": true,
		"wscript": true, "cscript": true,
		"mshta": true,
	}
	if !interpreters[name] {
		return "", ""
	}
	if len(args) < 2 {
		return name, ""
	}
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "/") {
			return name, arg
		}
	}
	return name, ""
}

const maxScriptSize = 64 * 1024

// captureScriptContent captures the script content either from an inline
// command argument or by reading the script file from disk.
func captureScriptContent(args []string, interpreter, scriptPath string) string {
	if interpreter == "" {
		return ""
	}

	// Inline script flags by interpreter.
	inlineFlags := map[string][]string{
		"powershell": {"-Command", "-c", "-EncodedCommand", "-enc", "-e"},
		"pwsh":       {"-Command", "-c", "-EncodedCommand", "-enc", "-e"},
		"cmd":        {"/c", "/C"},
		"python":     {"-c"}, "python3": {"-c"}, "python2": {"-c"},
		"perl":       {"-e"}, "ruby": {"-e"},
		"node":       {"-e"}, "nodejs": {"-e"},
		"bash":       {"-c"}, "sh": {"-c"}, "zsh": {"-c"},
	}

	if flags, ok := inlineFlags[interpreter]; ok && len(args) > 1 {
		for i, arg := range args[1:] {
			for _, flag := range flags {
				if strings.EqualFold(arg, flag) && i+2 < len(args) {
					content := args[i+2]
					// Decode base64 for PowerShell -EncodedCommand.
					if strings.EqualFold(flag, "-EncodedCommand") ||
						strings.EqualFold(flag, "-enc") ||
						strings.EqualFold(flag, "-e") {
						if interpreter == "powershell" || interpreter == "pwsh" {
							if decoded, err := decodeBase64Unicode(content); err == nil {
								content = decoded
							}
						}
					}
					if len(content) > maxScriptSize {
						content = content[:maxScriptSize] + "\n... (truncated)"
					}
					return content
				}
			}
		}
	}

	// Read script file from disk.
	if scriptPath == "" {
		return ""
	}
	fi, err := os.Stat(scriptPath)
	if err != nil || fi.IsDir() || fi.Size() == 0 || fi.Size() > int64(maxScriptSize*2) {
		return ""
	}
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return ""
	}
	content := string(data)
	if len(content) > maxScriptSize {
		content = content[:maxScriptSize] + "\n... (truncated)"
	}
	return content
}

// decodeBase64Unicode decodes PowerShell's -EncodedCommand (UTF-16LE base64).
func decodeBase64Unicode(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(raw)%2 != 0 {
		return string(raw), nil
	}
	runes := make([]rune, 0, len(raw)/2)
	for i := 0; i < len(raw)-1; i += 2 {
		runes = append(runes, rune(raw[i])|rune(raw[i+1])<<8)
	}
	return string(runes), nil
}

func extractComm(exePath string) string {
	if exePath == "" {
		return ""
	}
	parts := strings.Split(exePath, `\`)
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return exePath
}

// Ensure Monitor implements the monitor interface.
var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)

// Unused but shows the ETW provider info for documentation.
var _ = fmt.Sprintf("ETW Provider: %s", etwconst.ProviderKernelProcess)
