//go:build windows

// internal/monitor/file/monitor.go
// File monitor for Windows.
//
// Primary path: ReadDirectoryChangesW + I/O Completion Port (IOCP), watchSubtree=true.
// Delivers FILE_CREATE, FILE_WRITE, FILE_DELETE, FILE_RENAME in real time with no
// depth limit — fixes WIN-M3 (original filepath.Walk stopped at depth 2).
//
// ReadDirectoryChangesW does not expose the PID of the modifying process (Windows
// API limitation). All file events carry Tags=["no-pid"] so analysts know the
// Process.PID field is absent. PID attribution would require Kernel-File ETW (future).
//
// Rename detection: FILE_ACTION_RENAMED_OLD_NAME and FILE_ACTION_RENAMED_NEW_NAME
// arrive as consecutive entries; they are buffered per-directory and emitted as a
// single EventFileRename with both Path (new) and OldPath (old) set.
//
// Fallback: if IOCP setup fails (insufficient privilege or very old Windows build),
// degrades to the original 5-second filepath.Walk polling (depth ≤ 2 only).

package file

import (
	"context"
	"os"
	"path/filepath"
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
	// rdcwNotifyFilter is the set of change types we subscribe to.
	rdcwNotifyFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_SIZE |
		windows.FILE_NOTIFY_CHANGE_CREATION |
		windows.FILE_NOTIFY_CHANGE_SECURITY

	// shutdownSentinel is posted to the IOCP from Stop() to unblock
	// GetQueuedCompletionStatus without waiting for a file-system event.
	// Use ^uintptr(0) (all bits set) — cannot collide with a valid *dirWatch pointer.
	shutdownSentinel = ^uintptr(0)
)

// Config for the file monitor.
type Config struct {
	WatchPaths  []string
	HashOnWrite bool
}

// dirWatch holds per-directory IOCP watch state.
// Each instance is heap-allocated and its address is used as the IOCP completion key
// so drainLoop can recover the watcher without an additional map lookup.
// The address must remain stable while ReadDirectoryChangesW I/O is outstanding;
// Go's non-moving GC guarantees this as long as m.watches holds a reference.
type dirWatch struct {
	handle        windows.Handle
	dirPath       string
	overlapped    windows.Overlapped
	buf           [65536]byte // 64 KB notification buffer
	pendingRename string      // old path, waiting for the matching RENAMED_NEW entry
}

// Monitor watches file-system paths for real-time change events.
type Monitor struct {
	cfg     Config
	bus     events.Bus
	log     zerolog.Logger
	iocp    windows.Handle // 0 when using the polling fallback
	watches []*dirWatch
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = []string{
			`C:\Windows\System32\`,
			`C:\Users\`,
			`C:\ProgramData\`,
			`C:\Windows\Temp\`,
		}
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "file").Logger(),
	}
}

// Start creates an IOCP and registers ReadDirectoryChangesW watchers for every
// configured path. Falls back to filepath.Walk polling if any IOCP step fails.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 0)
	if err != nil {
		m.log.Warn().Err(err).Msg("IOCP creation failed, falling back to polling")
		return m.startPolling(ctx)
	}
	m.iocp = iocp

	for _, dir := range m.cfg.WatchPaths {
		if err := m.addWatch(dir); err != nil {
			m.log.Warn().Err(err).Str("dir", dir).Msg("skipping watch path")
		}
	}

	if len(m.watches) == 0 {
		windows.CloseHandle(m.iocp)
		m.iocp = 0
		m.log.Warn().Msg("no watch paths could be opened, falling back to polling")
		return m.startPolling(ctx)
	}

	m.wg.Add(1)
	go m.drainLoop()

	m.log.Info().Int("paths", len(m.watches)).Msg("file monitor started (ReadDirectoryChangesW + IOCP)")
	return nil
}

// addWatch opens a directory handle for overlapped I/O, associates it with the
// IOCP, and posts the first ReadDirectoryChangesW request.
func (m *Monitor) addWatch(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		p,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return err
	}

	w := &dirWatch{handle: handle, dirPath: dir}

	// Use &w as completion key so drainLoop can recover the watcher in O(1).
	if _, err := windows.CreateIoCompletionPort(handle, m.iocp, uintptr(unsafe.Pointer(w)), 0); err != nil {
		windows.CloseHandle(handle)
		return err
	}

	m.watches = append(m.watches, w)
	m.postRDCW(w)
	return nil
}

// postRDCW (re-)posts a ReadDirectoryChangesW request for the given watcher.
// watchSubtree=true eliminates the depth-2 polling limit (WIN-M3 fix).
func (m *Monitor) postRDCW(w *dirWatch) {
	w.overlapped = windows.Overlapped{} // reset OS-owned fields before each post
	var retlen uint32
	// Errors here (e.g. during shutdown when the handle is closing) are ignored;
	// the drain loop will stop naturally when the IOCP sentinel is received.
	windows.ReadDirectoryChanges(
		w.handle,
		&w.buf[0],
		uint32(len(w.buf)),
		true, // watchSubtree — recursively monitors all subdirectories
		rdcwNotifyFilter,
		&retlen,
		&w.overlapped,
		0, // no completion routine; completions arrive via GetQueuedCompletionStatus
	)
}

// drainLoop blocks on GetQueuedCompletionStatus and dispatches file events.
// Exits when Stop() posts the shutdownSentinel completion key.
func (m *Monitor) drainLoop() {
	defer m.wg.Done()
	defer func() {
		for _, w := range m.watches {
			windows.CloseHandle(w.handle)
		}
		windows.CloseHandle(m.iocp)
	}()

	for {
		var bytesTransferred uint32
		var completionKey uintptr
		var pov *windows.Overlapped

		windows.GetQueuedCompletionStatus(
			m.iocp, &bytesTransferred, &completionKey, &pov, windows.INFINITE,
		)

		if completionKey == shutdownSentinel {
			return
		}
		if pov == nil {
			continue // GetQueuedCompletionStatus failed without an I/O context
		}

		w := (*dirWatch)(unsafe.Pointer(completionKey))

		if bytesTransferred == 0 {
			// Buffer overflow — some notifications were lost; repost immediately.
			m.log.Warn().Str("dir", w.dirPath).Msg("RDCW buffer overflow, some events lost")
			m.postRDCW(w)
			continue
		}

		for _, r := range parseFileNotifyRecords(w.buf[:bytesTransferred]) {
			m.handleRecord(w, r)
		}
		m.postRDCW(w)
	}
}

// handleRecord maps a FILE_NOTIFY_INFORMATION record to an event and emits it.
// Rename pairs are buffered per-directory: RENAMED_OLD is held until RENAMED_NEW arrives.
func (m *Monitor) handleRecord(w *dirWatch, r fileNotifyRecord) {
	fullPath := filepath.Join(w.dirPath, r.FileName)
	switch r.Action {
	case fileActionAdded:
		w.pendingRename = ""
		m.emitFileEvent(types.EventFileCreate, fullPath, "")
	case fileActionRemoved:
		w.pendingRename = ""
		m.emitFileEvent(types.EventFileDelete, fullPath, "")
	case fileActionModified:
		m.emitFileEvent(types.EventFileWrite, fullPath, "")
	case fileActionRenamedOld:
		w.pendingRename = fullPath
	case fileActionRenamedNew:
		oldPath := w.pendingRename
		w.pendingRename = ""
		m.emitFileEvent(types.EventFileRename, fullPath, oldPath)
	}
}

// emitFileEvent publishes a FileEvent to the bus.
// OldPath is set only for rename events.
// Tags always includes "no-pid" because ReadDirectoryChangesW does not expose
// the PID of the process that modified the file.
func (m *Monitor) emitFileEvent(evType types.EventType, path, oldPath string) {
	var hashAfter string
	var sizeBytes int64
	if m.cfg.HashOnWrite && evType == types.EventFileWrite {
		hashAfter, sizeBytes = hashFile(path)
	}

	m.bus.Publish(&types.FileEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      evType,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  classifySeverity(path),
			Tags:      []string{"no-pid"},
		},
		Path:      path,
		OldPath:   oldPath,
		HashAfter: hashAfter,
		SizeBytes: sizeBytes,
		IsHidden:  isHidden(filepath.Base(path)),
	})
}

// Stop posts the shutdown sentinel to the IOCP (IOCP path) or cancels the
// polling context, then waits for all goroutines to exit cleanly.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.iocp != 0 {
		// Unblock GetQueuedCompletionStatus without waiting for a file-system event.
		windows.PostQueuedCompletionStatus(m.iocp, 0, shutdownSentinel, nil)
	}
	m.wg.Wait()
	m.log.Info().Msg("file monitor stopped")
}

// ── Polling fallback ──────────────────────────────────────────────────────────
// Preserved from original implementation; activated when IOCP setup fails.
// Limitation: filepath.Walk is capped at depth ≤ 2 to limit overhead.

func (m *Monitor) startPolling(ctx context.Context) error {
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("file monitor started (polling filepath.Walk, depth ≤ 2)")
	return nil
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[string]time.Time)
	for _, dir := range m.cfg.WatchPaths {
		m.scanDir(dir, known)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := make(map[string]time.Time)
			for _, dir := range m.cfg.WatchPaths {
				m.scanDir(dir, current)
			}
			for path, modTime := range current {
				if prevTime, exists := known[path]; !exists {
					m.emitFileEvent(types.EventFileCreate, path, "")
				} else if modTime.After(prevTime) {
					m.emitFileEvent(types.EventFileWrite, path, "")
				}
			}
			for path := range known {
				if _, exists := current[path]; !exists {
					m.emitFileEvent(types.EventFileDelete, path, "")
				}
			}
			known = current
		}
	}
}

func (m *Monitor) scanDir(dir string, result map[string]time.Time) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if strings.Count(rel, string(filepath.Separator)) > 2 {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			result[path] = info.ModTime()
		}
		return nil
	})
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)
