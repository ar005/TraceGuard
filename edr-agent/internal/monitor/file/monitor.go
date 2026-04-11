// internal/monitor/file/monitor.go
//
// File Integrity Monitor — eBPF-based file activity tracker.
//
// Architecture:
//   1. eBPF ring buffer  — kprobe hooks on vfs_write, vfs_create, vfs_unlink,
//      vfs_rename, security_inode_setattr capture file events with PID, comm,
//      dentry name, inode, mode and size.  Events are raw C structs
//      (file_event) defined in ebpf/file/file.bpf.c.
//
//   2. Path filtering — eBPF gives us the dentry (basename).  Userspace
//      resolves the full path via /proc/<pid>/fd/ inode matching and
//      /proc/<pid>/cwd/<dentry> fallback, then matches against watch prefixes.
//      Events outside all watched directories are silently dropped.
//
//   3. File hashing — on CREATE and WRITE events (hash_on_write=true) the
//      file is SHA-256'd in a bounded worker pool so the hot path stays fast.
//      The event is published after hashing completes (or immediately if the
//      hash queue is full).
//
//   4. Graceful degradation — if eBPF fails (old kernel, missing BTF,
//      missing capabilities) the monitor falls back to recursive inotify with
//      auto-watch of newly created subdirectories. Rename correlation uses a
//      cookie map with a 50 ms timeout.
//
// Config (monitors.file.* in agent.yaml):
//   watch_paths    — list of directory prefixes, default shown below
//   hash_on_write  — bool, default true
//   hash_workers   — int, default 4
//   dedupe_window  — duration, default 500ms (suppress repeated write events)

package file

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
	"github.com/youredr/edr-agent/pkg/utils"
)

// ─── eBPF event type constants (must match file.bpf.c) ───────────────────────

const (
	ebpfFileCreate = 20
	ebpfFileWrite  = 21
	ebpfFileDelete = 22
	ebpfFileRename = 23
	ebpfFileChmod  = 25
)

// ─── Raw kernel struct (mirrors struct file_event in file.bpf.c) ─────────────

const (
	fileCommLen = 16
	fileNameMax = 256
	fileOldMax  = 128
)

type rawFileEvent struct {
	TimestampNs uint64
	EventType   uint32
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	Comm        [fileCommLen]byte
	Path        [fileNameMax]byte
	OldPath     [fileOldMax]byte
	Inode       uint64
	Dev         uint32
	Mode        uint32
	Size        uint64
	Flags       uint32
	Pad         uint32
}

// ─── bpf2go type alias ────────────────────────────────────────────────────────
// bpf2go generates FileObjects / LoadFileObjects from file.bpf.c.

type bpfObjects = FileObjects

func loadBPFObjects(obj *bpfObjects, opts *ebpf.CollectionOptions) error {
	return LoadFileObjects(obj, opts)
}

// ─── Config ───────────────────────────────────────────────────────────────────

// Config controls the file monitor. Fields map to YAML keys under monitors.file.
type Config struct {
	WatchPaths       []string
	HashOnWrite      bool
	HashWorkers      int
	DedupeWindow     time.Duration
	CaptureAllWrites bool // When true, capture file writes from any path (requires eBPF)
}

func defaultConfig() Config {
	return Config{
		WatchPaths: []string{
			"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin",
			"/tmp", "/var/tmp", "/dev/shm",
		},
		HashOnWrite:  true,
		HashWorkers:  4,
		DedupeWindow: 500 * time.Millisecond,
	}
}

// ─── Monitor ─────────────────────────────────────────────────────────────────

// Monitor is the file integrity monitoring component.
type Monitor struct {
	cfg Config
	bus events.Bus
	log zerolog.Logger

	// eBPF state.
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader

	// Async hash worker pool.
	hashCh chan hashReq

	// Deduplication: (op:path) → last-seen time.
	dedupeMu  sync.Mutex
	dedupeMap map[string]time.Time

	// Inotify fallback.
	inotifyFd  int
	inotifyMu  sync.Mutex
	watchDescs map[int32]string // wd → directory path

	stopCh chan struct{}
	wg     sync.WaitGroup
}

type hashReq struct {
	path    string
	publish func(hash string)
}

// New creates a file Monitor. Call Start() to begin monitoring.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if len(cfg.WatchPaths) == 0 {
		d := defaultConfig()
		cfg.WatchPaths = d.WatchPaths
	}
	if cfg.HashWorkers == 0 {
		cfg.HashWorkers = 4
	}
	if cfg.DedupeWindow == 0 {
		cfg.DedupeWindow = 500 * time.Millisecond
	}
	return &Monitor{
		cfg:        cfg,
		bus:        bus,
		log:        log.With().Str("monitor", "file").Logger(),
		hashCh:     make(chan hashReq, 1024),
		dedupeMap:  make(map[string]time.Time),
		watchDescs: make(map[int32]string),
		stopCh:     make(chan struct{}),
	}
}

// Start loads eBPF programs and attaches kprobes, falling back to inotify.
func (m *Monitor) Start(ctx context.Context) error {
	// Start hash worker pool.
	for i := 0; i < m.cfg.HashWorkers; i++ {
		m.wg.Add(1)
		go m.hashWorker()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		m.log.Warn().Err(err).Msg("file monitor: remove memlock failed; using inotify fallback")
		return m.startInotify(ctx)
	}
	if err := loadBPFObjects(&m.objs, nil); err != nil {
		m.log.Warn().Err(err).Msg("file monitor: eBPF load failed; using inotify fallback")
		return m.startInotify(ctx)
	}
	if err := m.attachProbes(); err != nil {
		m.log.Warn().Err(err).Msg("file monitor: kprobe attach failed; using inotify fallback")
		m.closeObjs()
		return m.startInotify(ctx)
	}

	var err error
	m.reader, err = ringbuf.NewReader(m.objs.FileEvents)
	if err != nil {
		m.log.Warn().Err(err).Msg("file monitor: ring buffer open failed; using inotify fallback")
		m.closeObjs()
		return m.startInotify(ctx)
	}

	m.log.Info().
		Strs("paths", m.cfg.WatchPaths).
		Bool("hash_on_write", m.cfg.HashOnWrite).
		Bool("capture_all_writes", m.cfg.CaptureAllWrites).
		Msg("file monitor started (eBPF)")

	m.wg.Add(1)
	go m.readLoop(ctx)
	return nil
}

// Stop shuts down all goroutines and releases resources.
func (m *Monitor) Stop() {
	close(m.stopCh)
	if m.reader != nil {
		m.reader.Close()
	}
	// Close hashCh to unblock hash workers, then wait for all goroutines.
	// The producer (readLoop/inotifyLoop) checks stopCh before sending.
	close(m.hashCh)
	m.wg.Wait()
	m.closeObjs()
	if m.inotifyFd > 0 {
		unix.Close(m.inotifyFd)
	}
	m.log.Info().Msg("file monitor stopped")
}

// ─── eBPF attachment ──────────────────────────────────────────────────────────

func (m *Monitor) attachProbes() error {
	type probeSpec struct {
		sym   string
		prog  *ebpf.Program
		fatal bool
	}
	probes := []probeSpec{
		{"vfs_write", m.objs.KprobeVfsWrite, true},
		{"vfs_create", m.objs.KprobeVfsCreate, false},
		{"vfs_unlink", m.objs.KprobeVfsUnlink, false},
		{"vfs_rename", m.objs.KprobeVfsRename, false},
		{"security_inode_setattr", m.objs.KprobeSecurityInodeSetattr, false},
	}
	for _, p := range probes {
		l, err := link.Kprobe(p.sym, p.prog, nil)
		if err != nil {
			if p.fatal {
				return fmt.Errorf("kprobe/%s: %w", p.sym, err)
			}
			m.log.Warn().Err(err).Msgf("file monitor: kprobe/%s unavailable", p.sym)
			continue
		}
		m.links = append(m.links, l)
	}
	return nil
}

func (m *Monitor) closeObjs() {
	for _, l := range m.links {
		l.Close()
	}
	m.objs.Close()
}

// ─── eBPF ring-buffer read loop ───────────────────────────────────────────────

func (m *Monitor) readLoop(ctx context.Context) {
	defer m.wg.Done()
	for {
		record, err := m.reader.Read()
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
				m.log.Debug().Err(err).Msg("file monitor: ring buffer read")
				return
			}
		}
		if err := m.handleRaw(record.RawSample); err != nil {
			m.log.Debug().Err(err).Msg("file monitor: handle event")
		}
	}
}

func (m *Monitor) handleRaw(raw []byte) error {
	if len(raw) < int(unsafe.Sizeof(rawFileEvent{})) {
		return nil
	}
	var r rawFileEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
		return err
	}

	dentry := nullStr(r.Path[:])
	if dentry == "" {
		return nil
	}

	fullPath := m.resolveFullPath(r.PID, dentry, r.Inode)
	if !m.isWatched(fullPath) {
		// When capture_all_writes is enabled, let write events through regardless of path.
		if !m.cfg.CaptureAllWrites || r.EventType != ebpfFileWrite {
			return nil
		}
	}

	// Deduplicate rapid repeated writes.
	if r.EventType == ebpfFileWrite {
		key := fmt.Sprintf("%d:%s", r.EventType, fullPath)
		if m.dedupeCheck(key) {
			return nil
		}
	}

	ts := bootTimeToWallClock(r.TimestampNs)
	proc := buildProcContext(r.PID, r.PPID, r.UID, nullStr(r.Comm[:]))

	switch r.EventType {
	case ebpfFileCreate:
		ev := m.newEvent(types.EventFileCreate, fullPath, "", ts, proc, r)
		m.scheduleHashOrPublish(ev)
	case ebpfFileWrite:
		ev := m.newEvent(types.EventFileWrite, fullPath, "", ts, proc, r)
		m.scheduleHashOrPublish(ev)
	case ebpfFileDelete:
		ev := m.newEvent(types.EventFileDelete, fullPath, "", ts, proc, r)
		m.publishAndLog(ev)
	case ebpfFileRename:
		oldDentry := nullStr(r.OldPath[:])
		oldPath := m.resolveFullPath(r.PID, oldDentry, 0)
		ev := m.newEvent(types.EventFileRename, fullPath, oldPath, ts, proc, r)
		m.publishAndLog(ev)
	case ebpfFileChmod:
		ev := m.newEvent(types.EventFileChmod, fullPath, "", ts, proc, r)
		m.publishAndLog(ev)
	}
	return nil
}

// newEvent builds a FileEvent from the raw eBPF struct.
func (m *Monitor) newEvent(
	evType types.EventType,
	path, oldPath string,
	ts time.Time,
	proc types.ProcessContext,
	r rawFileEvent,
) *types.FileEvent {
	sev := m.assessSeverity(path, evType)
	ev := &types.FileEvent{
		BaseEvent: types.BaseEvent{
			ID:        utils.NewEventID(),
			Type:      evType,
			Timestamp: ts,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  sev,
			Process:   proc,
		},
		Path:      path,
		OldPath:   oldPath,
		SizeBytes: int64(r.Size),
		Mode:      r.Mode,
		INode:     r.Inode,
		Device:    uint64(r.Dev),
		IsHidden:  strings.HasPrefix(filepath.Base(path), "."),
	}
	if fi, err := os.Lstat(path); err == nil {
		ev.IsSymlink = fi.Mode()&fs.ModeSymlink != 0
	}
	return ev
}

// ─── Hash worker pool ─────────────────────────────────────────────────────────

func (m *Monitor) hashWorker() {
	defer m.wg.Done()
	for req := range m.hashCh {
		hash, _ := utils.HashFile(req.path)
		req.publish(hash)
	}
}

// scheduleHashOrPublish queues hashing if enabled; otherwise publishes immediately.
func (m *Monitor) scheduleHashOrPublish(ev *types.FileEvent) {
	if !m.cfg.HashOnWrite {
		m.publishAndLog(ev)
		return
	}
	// Guard against sending on closed hashCh during shutdown.
	select {
	case <-m.stopCh:
		m.publishAndLog(ev)
		return
	default:
	}
	select {
	case m.hashCh <- hashReq{
		path: ev.Path,
		publish: func(hash string) {
			ev.HashAfter = hash
			m.publishAndLog(ev)
		},
	}:
	default:
		// Hash queue full — publish without hash.
		m.publishAndLog(ev)
	}
}

func (m *Monitor) publishAndLog(ev *types.FileEvent) {
	m.bus.Publish(ev)
	m.logEvent(ev)
}

// ─── Path resolution ──────────────────────────────────────────────────────────

// resolveFullPath resolves the absolute path of a file from /proc/<pid>/fd
// by matching the inode, then falls back to /proc/<pid>/cwd/<dentry>.
func (m *Monitor) resolveFullPath(pid uint32, dentry string, inode uint64) string {
	if dentry == "" {
		return ""
	}

	// Try /proc/<pid>/fd/* → find fd whose target has the right inode or basename.
	if pid > 0 {
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		if entries, err := os.ReadDir(fdDir); err == nil {
			for _, ent := range entries {
				target, err := os.Readlink(filepath.Join(fdDir, ent.Name()))
				if err != nil {
					continue
				}
				if inode != 0 {
					if fi, err := os.Stat(target); err == nil {
						if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == inode {
							return target
						}
					}
				}
				if filepath.Base(target) == dentry {
					return target
				}
			}
		}

		// Fall back to cwd + dentry.
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
			candidate := filepath.Join(cwd, dentry)
			if _, err := os.Lstat(candidate); err == nil {
				return candidate
			}
		}
	}

	return dentry
}

func (m *Monitor) isWatched(path string) bool {
	for _, prefix := range m.cfg.WatchPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ─── Deduplication ───────────────────────────────────────────────────────────

func (m *Monitor) dedupeCheck(key string) bool {
	now := time.Now()
	m.dedupeMu.Lock()
	defer m.dedupeMu.Unlock()
	if last, ok := m.dedupeMap[key]; ok && now.Sub(last) < m.cfg.DedupeWindow {
		return true
	}
	m.dedupeMap[key] = now
	// Periodic cleanup.
	if len(m.dedupeMap) > 8192 {
		cutoff := now.Add(-2 * m.cfg.DedupeWindow)
		for k, v := range m.dedupeMap {
			if v.Before(cutoff) {
				delete(m.dedupeMap, k)
			}
		}
	}
	return false
}

// ─── Severity assessment ──────────────────────────────────────────────────────

func (m *Monitor) assessSeverity(path string, evType types.EventType) types.Severity {
	// Critical: shadow/sudoers writes, executables written to temp dirs.
	critical := []string{"/etc/shadow", "/etc/sudoers", "/usr/bin/sudo", "/usr/bin/su"}
	for _, p := range critical {
		if strings.HasPrefix(path, p) {
			return types.SeverityCritical
		}
	}
	// High: sensitive config + binaries.
	high := []string{
		"/etc/passwd", "/etc/ssh/", "/etc/pam.", "/etc/cron",
		"/etc/ld.so", "/usr/bin/passwd",
	}
	for _, p := range high {
		if strings.HasPrefix(path, p) {
			if evType == types.EventFileWrite || evType == types.EventFileCreate {
				return types.SeverityHigh
			}
			return types.SeverityMedium
		}
	}
	// High: scripts/binaries dropped in volatile dirs.
	volatile := []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	for _, v := range volatile {
		if strings.HasPrefix(path, v) && (evType == types.EventFileCreate || evType == types.EventFileWrite) {
			ext := strings.ToLower(filepath.Ext(path))
			base := filepath.Base(path)
			if ext == "" || ext == ".sh" || ext == ".py" || ext == ".pl" ||
				ext == ".elf" || ext == ".so" || !strings.Contains(base, ".") {
				return types.SeverityHigh
			}
			return types.SeverityMedium
		}
	}
	switch evType {
	case types.EventFileDelete, types.EventFileChmod:
		return types.SeverityLow
	case types.EventFileWrite:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

// ─── Logging ─────────────────────────────────────────────────────────────────

func (m *Monitor) logEvent(ev *types.FileEvent) {
	e := m.log.Debug()
	if ev.Severity >= types.SeverityHigh {
		e = m.log.Warn()
	}
	e.Str("type", string(ev.Type)).
		Str("path", ev.Path).
		Uint32("pid", ev.Process.PID).
		Str("comm", ev.Process.Comm).
		Str("hash", ev.HashAfter).
		Msg("file event")
}

// ─── Inotify fallback ─────────────────────────────────────────────────────────

func (m *Monitor) startInotify(ctx context.Context) error {
	if m.cfg.CaptureAllWrites {
		m.log.Warn().Msg("capture_all_writes requires eBPF; inotify fallback only covers watch_paths")
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	m.inotifyFd = fd

	const mask uint32 = unix.IN_CREATE | unix.IN_CLOSE_WRITE | unix.IN_MODIFY |
		unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_ATTRIB

	var addWatch func(path string) error
	addWatch = func(path string) error {
		wd, err := unix.InotifyAddWatch(fd, path, mask)
		if err != nil {
			return err
		}
		m.inotifyMu.Lock()
		m.watchDescs[int32(wd)] = path
		m.inotifyMu.Unlock()
		return nil
	}

	for _, root := range m.cfg.WatchPaths {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if werr := addWatch(p); werr != nil {
				m.log.Debug().Err(werr).Str("path", p).Msg("inotify: add watch failed")
			}
			return nil
		})
	}

	m.log.Info().
		Strs("paths", m.cfg.WatchPaths).
		Int("watches", len(m.watchDescs)).
		Msg("file monitor started (inotify fallback)")

	m.wg.Add(1)
	go m.inotifyLoop(ctx, addWatch)
	return nil
}

func (m *Monitor) inotifyLoop(ctx context.Context, addWatch func(string) error) {
	defer m.wg.Done()

	buf := make([]byte, 4096*(unix.SizeofInotifyEvent+256))

	// cookie → moved-from path for rename pair correlation.
	var cookieMu sync.Mutex
	cookies := make(map[uint32]string)

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Read(m.inotifyFd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			select {
			case <-m.stopCh:
				return
			default:
				m.log.Warn().Err(err).Msg("inotify read error")
				return
			}
		}

		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			wd := int32(ev.Wd)
			evMask := ev.Mask
			cookie := ev.Cookie
			nameLen := int(ev.Len)

			var name string
			nameStart := offset + unix.SizeofInotifyEvent
			if nameLen > 0 && nameStart+nameLen <= n {
				name = strings.TrimRight(string(buf[nameStart:nameStart+nameLen]), "\x00")
			}
			offset = nameStart + nameLen

			m.inotifyMu.Lock()
			dir := m.watchDescs[wd]
			m.inotifyMu.Unlock()
			if dir == "" {
				continue
			}

			var path string
			if name != "" {
				path = filepath.Join(dir, name)
			} else {
				path = dir
			}

			ts := time.Now()
			proc := types.ProcessContext{} // inotify doesn't provide PID

			isDir := evMask&unix.IN_ISDIR != 0

			switch {
			case evMask&unix.IN_CREATE != 0 && isDir:
				// New subdirectory: add watch so we catch activity inside it.
				if werr := addWatch(path); werr == nil {
					m.log.Debug().Str("path", path).Msg("inotify: watching new dir")
				}

			case evMask&unix.IN_CREATE != 0 && !isDir:
				fe := m.buildInotifyEvent(types.EventFileCreate, path, "", ts, proc)
				m.scheduleHashOrPublish(fe)

			case evMask&unix.IN_CLOSE_WRITE != 0:
				fe := m.buildInotifyEvent(types.EventFileWrite, path, "", ts, proc)
				m.scheduleHashOrPublish(fe)

			case evMask&unix.IN_MODIFY != 0:
				// Dedup: only emit if no CLOSE_WRITE will arrive soon.
				key := fmt.Sprintf("%d:%s", ebpfFileWrite, path)
				if !m.dedupeCheck(key) {
					fe := m.buildInotifyEvent(types.EventFileWrite, path, "", ts, proc)
					m.scheduleHashOrPublish(fe)
				}

			case evMask&unix.IN_DELETE != 0 && !isDir:
				fe := m.buildInotifyEvent(types.EventFileDelete, path, "", ts, proc)
				m.publishAndLog(fe)

			case evMask&unix.IN_MOVED_FROM != 0:
				cookieMu.Lock()
				cookies[cookie] = path
				cookieMu.Unlock()
				// Discard if no MOVED_TO arrives within 50ms.
				go func(c uint32) {
					time.Sleep(50 * time.Millisecond)
					cookieMu.Lock()
					delete(cookies, c)
					cookieMu.Unlock()
				}(cookie)

			case evMask&unix.IN_MOVED_TO != 0:
				cookieMu.Lock()
				oldPath := cookies[cookie]
				delete(cookies, cookie)
				cookieMu.Unlock()
				fe := m.buildInotifyEvent(types.EventFileRename, path, oldPath, ts, proc)
				m.publishAndLog(fe)

			case evMask&unix.IN_ATTRIB != 0:
				fe := m.buildInotifyEvent(types.EventFileChmod, path, "", ts, proc)
				m.publishAndLog(fe)
			}
		}
	}
}

func (m *Monitor) buildInotifyEvent(
	evType types.EventType,
	path, oldPath string,
	ts time.Time,
	proc types.ProcessContext,
) *types.FileEvent {
	return &types.FileEvent{
		BaseEvent: types.BaseEvent{
			ID:        utils.NewEventID(),
			Type:      evType,
			Timestamp: ts,
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  m.assessSeverity(path, evType),
			Process:   proc,
		},
		Path:     path,
		OldPath:  oldPath,
		IsHidden: strings.HasPrefix(filepath.Base(path), "."),
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func nullStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// buildProcContext populates a ProcessContext from eBPF fields + /proc enrichment.
func buildProcContext(pid, ppid, uid uint32, comm string) types.ProcessContext {
	p := types.ProcessContext{PID: pid, PPID: ppid, UID: uid, Comm: comm}
	if pid == 0 {
		return p
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		p.ExePath = exe
	}
	if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		args := make([]string, 0, len(parts))
		for _, pt := range parts {
			if len(pt) > 0 {
				args = append(args, string(pt))
			}
		}
		p.Args = args
		p.Cmdline = strings.Join(args, " ")
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		p.Cwd = cwd
	}
	return p
}

// bootTimeToWallClock converts a kernel ktime_get_ns() timestamp to wall time.
func bootTimeToWallClock(ns uint64) time.Time {
	bns := getBootTimeNs()
	if bns == 0 {
		return time.Now()
	}
	return time.Unix(0, int64(bns+ns))
}

var (
	_bootOnce sync.Once
	_bootNs   uint64
)

func getBootTimeNs() uint64 {
	_bootOnce.Do(func() {
		raw, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "btime ") {
				continue
			}
			var sec uint64
			if _, e := fmt.Sscanf(line, "btime %d", &sec); e == nil {
				_bootNs = sec * uint64(time.Second)
			}
			return
		}
	})
	return _bootNs
}
