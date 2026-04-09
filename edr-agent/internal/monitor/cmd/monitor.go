// internal/monitor/cmd/monitor.go
//
// Command Activity Monitor — dual-source terminal surveillance:
//
//  1. Real-time: polls /proc every 500ms for processes whose parent is a shell.
//     Also scans grandchildren (shell → script → command) to catch more children.
//
//  2. History tailing: follows ~/.bash_history, ~/.zsh_history etc.
//     Handles both bash HISTTIMEFORMAT (#timestamp) and ZSH EXTENDED_HISTORY
//     (: timestamp:elapsed;command) formats.
//
//  3. New-home watcher: inotify on /home so that history files for newly
//     created users are picked up automatically without restarting the agent.
//
// Both sources emit CMD_EXEC / CMD_HISTORY events to the bus.
// Suspicious commands are tagged with elevated severity and detection labels.

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// ─── Event type constants ─────────────────────────────────────────────────────

const (
	EventCmdExec    types.EventType = "CMD_EXEC"
	EventCmdHistory types.EventType = "CMD_HISTORY"
)

// ─── Suspicious command rules ─────────────────────────────────────────────────

type detRule struct {
	re  *regexp.Regexp
	msg string
	sev types.Severity
	tag string
}

var detectionRules = []detRule{
	// Execution / shells
	{regexp.MustCompile(`curl[^|]*\|\s*(ba)?sh`), "curl pipe to shell", types.SeverityHigh, "curl-pipe-shell"},
	{regexp.MustCompile(`wget[^|]*\|\s*(ba)?sh`), "wget pipe to shell", types.SeverityHigh, "wget-pipe-shell"},
	{regexp.MustCompile(`\bnc\s.*-e\s*/`), "netcat reverse shell (-e)", types.SeverityCritical, "netcat-revshell"},
	{regexp.MustCompile(`\bncat\b.*--exec`), "ncat exec", types.SeverityCritical, "ncat-exec"},
	{regexp.MustCompile(`bash\s+-i\s+>&`), "bash interactive reverse shell", types.SeverityCritical, "bash-revshell"},
	{regexp.MustCompile(`/dev/tcp/`), "TCP redirect via /dev/tcp", types.SeverityCritical, "dev-tcp"},
	// Privilege escalation
	{regexp.MustCompile(`sudo\s+(-i|su|bash|sh|-s)`), "sudo root shell", types.SeverityHigh, "sudo-root-shell"},
	{regexp.MustCompile(`chmod\s+[0-7]*[46][57]\s`), "chmod suid/sgid", types.SeverityHigh, "chmod-suid"},
	{regexp.MustCompile(`\bsu\s+-\s*$|\bsu\s+root`), "switch to root", types.SeverityHigh, "su-root"},
	// Persistence
	{regexp.MustCompile(`crontab\s+-[el]`), "crontab edit", types.SeverityMedium, "crontab-edit"},
	{regexp.MustCompile(`authorized_keys`), "SSH authorized_keys access", types.SeverityMedium, "ssh-authkeys"},
	{regexp.MustCompile(`(\.bashrc|\.profile|\.bash_profile|\.zshrc).*>>`), "shell profile append", types.SeverityHigh, "profile-append"},
	{regexp.MustCompile(`systemctl\s+enable|systemctl\s+start`), "service enabled/started", types.SeverityLow, "systemctl-persist"},
	// Credential access
	{regexp.MustCompile(`/etc/shadow|/etc/passwd`), "sensitive credentials file", types.SeverityHigh, "cred-file"},
	{regexp.MustCompile(`(mimikatz|lazagne|secretsdump|hashdump)`), "credential dumper", types.SeverityCritical, "cred-dumper"},
	{regexp.MustCompile(`ssh-keygen\s+-f`), "SSH key generation", types.SeverityMedium, "ssh-keygen"},
	// Obfuscation / staging
	{regexp.MustCompile(`base64\s+(--decode|-d)\s*[|<]|\|\s*base64\s+-d`), "base64 decode", types.SeverityHigh, "base64-decode"},
	{regexp.MustCompile(`python[23]?\s+-c\s*['"]`), "python inline exec", types.SeverityMedium, "python-exec"},
	{regexp.MustCompile(`perl\s+-e\s*['"]`), "perl inline exec", types.SeverityMedium, "perl-exec"},
	{regexp.MustCompile(`php\s+-r\s*['"]`), "php inline exec", types.SeverityMedium, "php-exec"},
	// Defense evasion
	{regexp.MustCompile(`history\s+-c|unset\s+HISTFILE|HISTSIZE=0`), "history evasion", types.SeverityHigh, "history-evasion"},
	{regexp.MustCompile(`iptables\s+-F|ufw\s+disable`), "firewall disabled", types.SeverityHigh, "firewall-disable"},
	{regexp.MustCompile(`setenforce\s+0|echo.*>/sys/fs/selinux/enforce`), "SELinux disabled", types.SeverityHigh, "selinux-disable"},
	{regexp.MustCompile(`shred\s+-[ufz]|wipe\s+|srm\s+`), "secure delete", types.SeverityMedium, "secure-delete"},
	// Reconnaissance
	{regexp.MustCompile(`\b(nmap|masscan|zmap|rustscan)\b`), "port scanner", types.SeverityHigh, "port-scan"},
	{regexp.MustCompile(`\b(id|whoami)\s*$`), "user recon", types.SeverityLow, "user-recon"},
	{regexp.MustCompile(`\buname\s+-a\b`), "system info recon", types.SeverityLow, "sysinfo-recon"},
	{regexp.MustCompile(`cat\s+/etc/(os-release|issue)|lsb_release`), "OS recon", types.SeverityLow, "os-recon"},
	{regexp.MustCompile(`ps\s+(aux|ef)\s*$`), "process listing", types.SeverityLow, "process-recon"},
	// Exfil
	{regexp.MustCompile(`\brsync\b.*--rsh|\bscp\b.*-[rp]`), "data transfer via scp/rsync", types.SeverityMedium, "data-transfer"},
	{regexp.MustCompile(`\(cat\s+.*\|\s*nc\b`), "netcat data exfil", types.SeverityHigh, "nc-exfil"},
	// Exploitation frameworks
	{regexp.MustCompile(`msfconsole|msfvenom|metasploit`), "Metasploit framework", types.SeverityCritical, "metasploit"},
	{regexp.MustCompile(`\bsqlmap\b`), "SQLmap", types.SeverityHigh, "sqlmap"},
	{regexp.MustCompile(`\bhydra\b|\bmedusa\b`), "brute force tool", types.SeverityHigh, "bruteforce"},
	// Writes to critical paths
	{regexp.MustCompile(`>\s*/etc/(sudoers|passwd|shadow|hosts|crontab)`), "write to critical file", types.SeverityCritical, "crit-file-write"},
	{regexp.MustCompile(`echo.*>>\s*/etc/`), "append to /etc", types.SeverityHigh, "etc-append"},
}

// zshExtHistRe matches ZSH EXTENDED_HISTORY lines:  ": 1234567890:0;actual command"
var zshExtHistRe = regexp.MustCompile(`^:\s*\d+:\d+;(.*)$`)

// ─── Types ────────────────────────────────────────────────────────────────────

// Config for the command monitor.
type Config struct {
	// Explicit extra history files (auto-discovery always runs).
	ExtraHistoryFiles []string
	// Poll interval for /proc scanning. 500ms catches most short-lived processes.
	PollInterval time.Duration
	// Emit INFO-severity commands too (noisy, good for forensics).
	EmitAll bool
}

func DefaultConfig() Config {
	return Config{
		PollInterval: 500 * time.Millisecond, // ↓ from 2s — catches processes < 2s
		EmitAll:      true,
	}
}

// CmdEvent is the payload emitted for CMD_EXEC and CMD_HISTORY events.
type CmdEvent struct {
	types.BaseEvent
	PID       uint32 `json:"pid,omitempty"`
	PPID      uint32 `json:"ppid,omitempty"`
	Username  string `json:"username"`
	Cmdline   string `json:"cmdline"`
	ShellName string `json:"shell_name,omitempty"`
	Source    string `json:"source"` // "proc" or "history:<path>"
	Detection string `json:"detection,omitempty"`
	Terminal  string `json:"terminal,omitempty"`
}

func (e *CmdEvent) EventType() string { return string(e.Type) }
func (e *CmdEvent) EventID() string   { return e.ID }

// Monitor watches real-time command and bash/zsh history activity.
type Monitor struct {
	cfg         Config
	bus         events.Bus
	log         zerolog.Logger
	agentID     string
	hostname    string
	mu          sync.Mutex
	seenPIDs    map[uint32]bool   // PIDs emitted (real-time)
	lastHash    map[string]string // history file → last line hash (dedup)
	tailing     map[string]bool   // history files currently being tailed
	unsubExec   func()            // unsubscribe from PROCESS_EXEC events
}

func New(cfg Config, bus events.Bus, log zerolog.Logger, agentID, hostname string) *Monitor {
	return &Monitor{
		cfg:      cfg,
		bus:      bus,
		log:      log.With().Str("monitor", "cmd").Logger(),
		agentID:  agentID,
		hostname: hostname,
		seenPIDs: make(map[uint32]bool),
		lastHash: make(map[string]string),
		tailing:  make(map[string]bool),
	}
}

// ─── Start ────────────────────────────────────────────────────────────────────

func (m *Monitor) Start(ctx context.Context) error {
	histFiles := m.discoverHistoryFiles()
	m.log.Info().
		Strs("history_files", histFiles).
		Dur("poll_interval", m.cfg.PollInterval).
		Bool("emit_all", m.cfg.EmitAll).
		Msg("command monitor started")

	// Real-time /proc watcher at 500ms — catches most processes < 2s
	go m.procLoop(ctx)

	// eBPF-backed process exec subscription — catches short-lived processes
	// that finish before the next /proc poll cycle.
	go m.subscribeExecEvents(ctx)

	// One goroutine per history file
	for _, f := range histFiles {
		m.mu.Lock()
		m.tailing[f] = true
		m.mu.Unlock()
		go m.tailHistory(ctx, f)
	}

	// Watch /home for new user directories → start tailing their history files
	go m.watchNewHomes(ctx)

	return nil
}

func (m *Monitor) Stop() {
	if m.unsubExec != nil {
		m.unsubExec()
	}
	m.log.Info().Msg("command monitor stopped")
}

// ─── eBPF-backed exec subscription ───────────────────────────────────────────
// Subscribes to PROCESS_EXEC events from the process monitor's eBPF tracepoint.
// This catches every execve — including short-lived processes that finish before
// the 500ms /proc poll cycle. The /proc poller is kept as a fallback; seenPIDs
// prevents duplicates between the two sources.

func (m *Monitor) subscribeExecEvents(ctx context.Context) {
	m.unsubExec = m.bus.Subscribe(string(types.EventProcessExec), func(event events.Event) {
		execEv, ok := event.(*types.ProcessExecEvent)
		if !ok {
			return
		}

		pid := execEv.Process.PID
		parentComm := execEv.ParentProcess.Comm
		shellName := parentComm

		// Check if parent is a shell (same logic as scanProc).
		if !isShell(parentComm) {
			// Check grandparent via the ancestry chain populated by the process monitor.
			if len(execEv.Ancestry) > 0 {
				gpComm := execEv.Ancestry[0].Comm
				if !isShell(gpComm) {
					return
				}
				shellName = gpComm
			} else {
				return
			}
		}

		cmdline := execEv.Process.Cmdline
		if cmdline == "" {
			return
		}

		// Mark as seen so the /proc poller doesn't double-emit.
		m.mu.Lock()
		if m.seenPIDs[pid] {
			m.mu.Unlock()
			return
		}
		m.seenPIDs[pid] = true
		m.mu.Unlock()

		sev, tags, detection := analyse(cmdline)
		if !m.cfg.EmitAll && sev == types.SeverityInfo {
			return
		}

		username := execEv.Process.Username
		if username == "" {
			username = uidUsername(execEv.Process.UID)
		}

		evt := &CmdEvent{
			BaseEvent: types.BaseEvent{
				ID:        uuid.New().String(),
				Type:      EventCmdExec,
				Timestamp: execEv.Timestamp,
				AgentID:   m.agentID,
				Hostname:  m.hostname,
				Severity:  sev,
				Tags:      tags,
				Process:   execEv.Process,
			},
			PID:       pid,
			PPID:      execEv.Process.PPID,
			Username:  username,
			Cmdline:   cmdline,
			ShellName: shellName,
			Source:    "ebpf",
			Detection: detection,
		}

		m.log.Info().
			Str("event_id", evt.ID).
			Str("severity", sev.String()).
			Uint32("pid", pid).
			Str("user", username).
			Str("shell", shellName).
			Strs("tags", tags).
			Str("cmd", trunc(cmdline, 200)).
			Msg("CMD_EXEC (ebpf)")

		m.bus.Publish(evt)
	})

	// Block until context is cancelled so the goroutine stays alive.
	<-ctx.Done()
}

// ─── Real-time proc watcher ───────────────────────────────────────────────────

func (m *Monitor) procLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanProc()
		}
	}
}

func (m *Monitor) scanProc() {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)

		m.mu.Lock()
		seen := m.seenPIDs[pid]
		m.mu.Unlock()
		if seen {
			continue
		}

		// Track children of shells AND grandchildren (shell → script → cmd).
		// This catches commands run inside shell scripts spawned from a terminal.
		ppid := readPPID(pid)
		if ppid == 0 {
			continue
		}
		parentComm := strings.TrimSpace(readFile(fmt.Sprintf("/proc/%d/comm", ppid)))
		shellName := parentComm

		if !isShell(parentComm) {
			// Check grandparent — catches: bash → python → subprocess
			gppid := readPPID(ppid)
			if gppid == 0 {
				continue
			}
			grandparentComm := strings.TrimSpace(readFile(fmt.Sprintf("/proc/%d/comm", gppid)))
			if !isShell(grandparentComm) {
				continue
			}
			shellName = grandparentComm
		}

		// Get full cmdline
		cmdlineRaw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdlineRaw), "\x00", " "))
		if cmdline == "" {
			continue
		}

		comm := strings.TrimSpace(readFile(fmt.Sprintf("/proc/%d/comm", pid)))
		username := uidUsername(readUID(pid))
		tty := readTTY(pid)

		m.mu.Lock()
		m.seenPIDs[pid] = true
		m.mu.Unlock()

		sev, tags, detection := analyse(cmdline)
		if !m.cfg.EmitAll && sev == types.SeverityInfo {
			continue
		}

		evt := &CmdEvent{
			BaseEvent: types.BaseEvent{
				ID:        uuid.New().String(),
				Type:      EventCmdExec,
				Timestamp: time.Now(),
				AgentID:   m.agentID,
				Hostname:  m.hostname,
				Severity:  sev,
				Tags:      tags,
				Process: types.ProcessContext{
					PID:     pid,
					PPID:    ppid,
					Comm:    comm,
					Cmdline: cmdline,
				},
			},
			PID:       pid,
			PPID:      ppid,
			Username:  username,
			Cmdline:   cmdline,
			ShellName: shellName,
			Source:    "proc",
			Detection: detection,
			Terminal:  tty,
		}

		m.log.Info().
			Str("event_id", evt.ID).
			Str("severity", sev.String()).
			Uint32("pid", pid).
			Str("user", username).
			Str("shell", shellName).
			Str("tty", tty).
			Strs("tags", tags).
			Str("cmd", trunc(cmdline, 200)).
			Msg("CMD_EXEC")

		m.bus.Publish(evt)
	}
}

// ─── History tailer ───────────────────────────────────────────────────────────

func (m *Monitor) tailHistory(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		m.log.Warn().Err(err).Str("file", path).Msg("cannot open history file — will retry")
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
			m.tailHistory(ctx, path)
			return
		}
	}
	defer f.Close()

	// Seek to end — only emit NEW commands typed after agent starts
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return
	}

	owner := historyOwner(path)
	isZsh := strings.Contains(filepath.Base(path), "zsh")
	m.log.Info().Str("file", path).Str("owner", owner).Bool("zsh", isZsh).Msg("tailing history file")

	reader := bufio.NewReaderSize(f, 4096)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lineBuf strings.Builder

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				b, err := reader.ReadByte()
				if err != nil {
					break
				}
				if b == '\n' {
					line := strings.TrimSpace(lineBuf.String())
					lineBuf.Reset()
					if line == "" {
						continue
					}
					cmd := parseHistoryLine(line, isZsh)
					if cmd != "" {
						m.emitHistory(cmd, path, owner)
					}
				} else {
					lineBuf.WriteByte(b)
				}
			}
		}
	}
}

// parseHistoryLine strips timestamp prefixes from both bash and zsh history formats.
//
// Bash HISTTIMEFORMAT writes a comment line before each command:
//
//	#1234567890
//	actual command
//
// ZSH EXTENDED_HISTORY writes everything on one line:
//
//	: 1234567890:0;actual command
//
// Plain lines (no timestamp) are returned as-is.
func parseHistoryLine(line string, isZsh bool) string {
	// Bash timestamp comment — skip it; the next line is the real command.
	if strings.HasPrefix(line, "#") {
		if _, err := strconv.ParseInt(line[1:], 10, 64); err == nil {
			return "" // pure timestamp comment — skip
		}
		return "" // any other comment — skip
	}

	// ZSH EXTENDED_HISTORY: ": timestamp:elapsed;command"
	if isZsh {
		if m := zshExtHistRe.FindStringSubmatch(line); m != nil {
			return strings.TrimSpace(m[1])
		}
	}

	return line
}

func (m *Monitor) emitHistory(cmd, path, owner string) {
	// Dedup consecutive identical commands
	key := path + ":" + cmd
	m.mu.Lock()
	if m.lastHash[path] == key {
		m.mu.Unlock()
		return
	}
	m.lastHash[path] = key
	m.mu.Unlock()

	sev, tags, detection := analyse(cmd)

	evt := &CmdEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      EventCmdHistory,
			Timestamp: time.Now(),
			AgentID:   m.agentID,
			Hostname:  m.hostname,
			Severity:  sev,
			Tags:      tags,
		},
		Username:  owner,
		Cmdline:   cmd,
		Source:    "history:" + filepath.Base(path),
		Detection: detection,
	}

	m.log.Info().
		Str("event_id", evt.ID).
		Str("severity", sev.String()).
		Str("user", owner).
		Str("file", path).
		Strs("tags", tags).
		Str("cmd", trunc(cmd, 200)).
		Msg("CMD_HISTORY")

	m.bus.Publish(evt)
}

// ─── New-home watcher (inotify) ───────────────────────────────────────────────

// watchNewHomes uses inotify to watch /home for new subdirectories being created.
// When a new home dir appears, it waits briefly for the shell to create history
// files, then starts tailing them — no agent restart needed.
func (m *Monitor) watchNewHomes(ctx context.Context) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		m.log.Warn().Err(err).Msg("inotify unavailable — new-home watching disabled")
		return
	}
	defer unix.Close(fd)

	_, err = unix.InotifyAddWatch(fd, "/home", unix.IN_CREATE|unix.IN_ONLYDIR)
	if err != nil {
		m.log.Warn().Err(err).Msg("inotify watch on /home failed — new-home watching disabled")
		return
	}

	m.log.Info().Msg("watching /home for new user directories")

	buf := make([]byte, 4096)
	pollFd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Poll with 500ms timeout so we can check ctx.Done()
		n, err := unix.Poll(pollFd, 500)
		if err != nil || n == 0 {
			continue
		}

		n, err = unix.Read(fd, buf)
		if err != nil || n == 0 {
			continue
		}

		// Parse inotify events — each event is a fixed 16-byte header + variable name
		offset := 0
		for offset+16 <= n {
			mask    := uint32(buf[offset+4]) | uint32(buf[offset+5])<<8 | uint32(buf[offset+6])<<16 | uint32(buf[offset+7])<<24
			nameLen := uint32(buf[offset+12]) | uint32(buf[offset+13])<<8 | uint32(buf[offset+14])<<16 | uint32(buf[offset+15])<<24

			nameStart := offset + 16
			nameEnd   := nameStart + int(nameLen)
			if nameEnd > n {
				break
			}

			name := strings.TrimRight(string(buf[nameStart:nameEnd]), "\x00")
			offset = nameEnd

			if mask&unix.IN_CREATE != 0 && name != "" {
				homeDir := filepath.Join("/home", name)
				go m.onNewHomeDir(ctx, homeDir)
			}
		}
	}
}

// onNewHomeDir is called when a new directory appears under /home.
// It waits up to 30s for shell history files to be created, then tails them.
func (m *Monitor) onNewHomeDir(ctx context.Context, homeDir string) {
	m.log.Info().Str("home", homeDir).Msg("new home directory detected — watching for history files")

	candidates := []string{
		filepath.Join(homeDir, ".bash_history"),
		filepath.Join(homeDir, ".zsh_history"),
		filepath.Join(homeDir, ".sh_history"),
	}

	// Poll for up to 60s — the user may not log in immediately
	deadline := time.Now().Add(60 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, f := range candidates {
				if _, err := os.Stat(f); err != nil {
					continue
				}
				m.mu.Lock()
				already := m.tailing[f]
				if !already {
					m.tailing[f] = true
				}
				m.mu.Unlock()

				if !already {
					m.log.Info().Str("file", f).Str("home", homeDir).Msg("new history file — starting tail")
					go m.tailHistory(ctx, f)
				}
			}
			if time.Now().After(deadline) {
				return
			}
		}
	}
}

// ─── Discovery ────────────────────────────────────────────────────────────────

func (m *Monitor) discoverHistoryFiles() []string {
	found := map[string]bool{}
	add := func(p string) {
		if _, err := os.Stat(p); err == nil {
			found[p] = true
		}
	}

	add("/root/.bash_history")
	add("/root/.zsh_history")
	add("/root/.sh_history")

	homes, _ := filepath.Glob("/home/*")
	for _, home := range homes {
		add(filepath.Join(home, ".bash_history"))
		add(filepath.Join(home, ".zsh_history"))
		add(filepath.Join(home, ".sh_history"))
	}

	for _, f := range m.cfg.ExtraHistoryFiles {
		add(f)
	}

	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	return out
}

// ─── Detection analysis ───────────────────────────────────────────────────────

func analyse(cmd string) (types.Severity, []string, string) {
	maxSev := types.SeverityInfo
	var tags []string
	var msgs []string
	for _, r := range detectionRules {
		if r.re.MatchString(cmd) {
			if r.sev > maxSev {
				maxSev = r.sev
			}
			tags = append(tags, r.tag)
			msgs = append(msgs, r.msg)
		}
	}
	return maxSev, tags, strings.Join(msgs, "; ")
}

// ─── /proc helpers ────────────────────────────────────────────────────────────

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func readPPID(pid uint32) uint32 {
	for _, line := range strings.Split(readFile(fmt.Sprintf("/proc/%d/status", pid)), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				v, _ := strconv.ParseUint(f[1], 10, 32)
				return uint32(v)
			}
		}
	}
	return 0
}

func readUID(pid uint32) uint32 {
	for _, line := range strings.Split(readFile(fmt.Sprintf("/proc/%d/status", pid)), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				v, _ := strconv.ParseUint(f[1], 10, 32)
				return uint32(v)
			}
		}
	}
	return 0
}

func readTTY(pid uint32) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/0", pid))
	if err != nil {
		return ""
	}
	if strings.HasPrefix(link, "/dev/pts/") || strings.HasPrefix(link, "/dev/tty") {
		return link
	}
	return ""
}

func uidUsername(uid uint32) string {
	data := readFile("/etc/passwd")
	uidStr := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(data, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[2] == uidStr {
			return parts[0]
		}
	}
	return uidStr
}

func isShell(name string) bool {
	switch name {
	case "bash", "sh", "zsh", "ksh", "dash", "fish", "tcsh", "csh":
		return true
	}
	return false
}

func historyOwner(path string) string {
	if strings.HasPrefix(path, "/root/") {
		return "root"
	}
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[1] == "home" {
		return parts[2]
	}
	return "unknown"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
