//go:build windows

// Package etw provides a pure-Go ETW real-time consumer.
// No CGO required — Windows callbacks are bridged via syscall.NewCallback.
// All kernel ETW sessions require SeSystemProfilePrivilege (held by SYSTEM/Admin).
package etw

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW     = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW   = modAdvapi32.NewProc("ControlTraceW")
	procOpenTraceW      = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace    = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace      = modAdvapi32.NewProc("CloseTrace")
	procEnableTraceEx2  = modAdvapi32.NewProc("EnableTraceEx2")
)

const (
	eventTraceRealTimeMode         = 0x00000100
	wNodeFlagTracedGuid            = 0x00020000
	enableTraceParametersVersion   = 2
	controlTraceStop               = 1

	// processTraceModeRealTime | processTraceModeEventRecord
	processTraceMode = 0x10000100

	// EVENT_TRACE_LOGFILEW field offsets (x64 Windows).
	// Layout: LogFileName(*uint16, 8) + LoggerName(*uint16, 8) + CurrentTime(int64, 8)
	//       + BuffersRead(uint32, 4) + ProcessTraceMode(uint32, 4)          [offset 28]
	//       + CurrentEvent(EVENT_TRACE, 88 bytes)                           [offset 32-120]
	//       + LogfileHeader(TRACE_LOGFILE_HEADER, 304 bytes)                [offset 120-424]
	//       + BufferCallback(uintptr, 8) + BufferSize(4) + Filled(4)
	//       + EventsLost(4) + _pad(4) + EventRecordCallback(uintptr, 8)    [offset 448]
	etlOffLoggerName             = 8
	etlOffProcessTraceMode       = 28
	etlOffEventRecordCallback    = 448 // union with EventCallback
	etlStructSize                = 512 // conservative; actual ~488 on x64
)

// EventRecord mirrors the Windows EVENT_RECORD structure.
// Field layout matches the Windows SDK definition for x64.
type EventRecord struct {
	EventHeader  EventHeader
	BufferCtx    [4]byte  // ETW_BUFFER_CONTEXT — not used by consumers
	ExtDataCount uint16
	UserDataLen  uint16
	_            uint32   // padding
	ExtData      uintptr
	UserData     uintptr
	UserContext  uintptr
}

// EventHeader mirrors EVENT_HEADER (part of EVENT_RECORD).
type EventHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64 // Windows FILETIME (100-ns intervals since 1601-01-01)
	ProviderID    windows.GUID
	Descriptor    EventDescriptor
	_             [16]byte // ActivityId — not used
}

// EventDescriptor holds the event classification fields from EVENT_DESCRIPTOR.
type EventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// Event is the parsed, monitor-facing representation of a raw ETW event.
// UserData contains the raw property bytes; each monitor parses them using
// the helpers in event.go.
type Event struct {
	ProviderGUID windows.GUID
	EventID      uint16
	Version      uint8
	Level        uint8
	ProcessID    uint32
	ThreadID     uint32
	Timestamp    time.Time
	UserData     []byte
}

// Handler is called from the ETW dispatch goroutine for every event matching
// a subscribed provider. Implementations must not block.
type Handler func(ev Event)

// Session wraps an ETW real-time trace session.
// A single Session can consume multiple providers; each monitor calls Subscribe
// with its own Handler before calling Consume.
type Session struct {
	name        string
	handle      syscall.Handle // trace session handle from StartTrace
	traceHandle uintptr        // from OpenTrace; 0 until Consume is called
	handlers    map[windows.GUID][]Handler
	mu          sync.RWMutex
	callback    uintptr    // syscall.NewCallback result — pinned for session lifetime
	closeOnce   sync.Once
}

// NewSession creates (or takes over) a named real-time ETW trace session.
// If a session with the same name already exists (e.g. from a previous agent
// crash), it is stopped and restarted so we get a clean session handle.
func NewSession(name string) (*Session, error) {
	s := &Session{
		name:     name,
		handlers: make(map[windows.GUID][]Handler),
	}
	// Pin the callback for the lifetime of the session.
	s.callback = syscall.NewCallback(s.eventCallback)

	if err := s.startTrace(); err != nil {
		return nil, fmt.Errorf("etw NewSession(%s): %w", name, err)
	}
	return s, nil
}

// EnableProvider enables a provider on this session at the given level and
// match-any keyword mask. Must be called before Consume.
func (s *Session) EnableProvider(guid windows.GUID, level uint8, matchAny uint64) error {
	type enableParams struct {
		Version          uint32
		EnableProperty   uint32
		ControlFlags     uint32
		SourceID         windows.GUID
		EnableFilterDesc uintptr
		FilterDescCount  uint32
		_                uint32
	}
	params := enableParams{Version: enableTraceParametersVersion}

	r1, _, err := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&guid)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		uintptr(level),
		uintptr(matchAny), // MatchAnyKeyword
		0,                 // MatchAllKeyword
		0,                 // Timeout (ms; 0 = async)
		uintptr(unsafe.Pointer(&params)),
	)
	if r1 != 0 {
		return fmt.Errorf("EnableTraceEx2(%v): win32=%d (%w)", guid, r1, err)
	}
	return nil
}

// Subscribe registers a handler to receive events from a provider.
// Must be called before Consume; safe to call from multiple goroutines.
func (s *Session) Subscribe(guid windows.GUID, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[guid] = append(s.handlers[guid], h)
}

// Consume opens the session for reading and blocks until ctx is cancelled.
// Events are dispatched to the handlers registered via Subscribe.
// Call EnableProvider for each desired provider before calling Consume.
func (s *Session) Consume(ctx context.Context) error {
	// Build EVENT_TRACE_LOGFILEW using a raw byte slice at known x64 offsets.
	// Using a byte slice avoids having to replicate the full struct hierarchy
	// (EVENT_TRACE + TRACE_LOGFILE_HEADER) which is ~400 bytes of embedded types.
	buf := make([]byte, etlStructSize)

	// Offset 0: LogFileName (*uint16) = nil — real-time sessions use LoggerName only.
	// Already zero.

	// Offset 8: LoggerName (*uint16) — session name connects us to the running trace.
	nameUTF16, err := syscall.UTF16PtrFromString(s.name)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}
	*(*uintptr)(unsafe.Pointer(&buf[etlOffLoggerName])) = uintptr(unsafe.Pointer(nameUTF16))

	// Offset 28: ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
	binary.LittleEndian.PutUint32(buf[etlOffProcessTraceMode:], processTraceMode)

	// Offset 448: EventRecordCallback — our Go callback via syscall.NewCallback trampoline.
	*(*uintptr)(unsafe.Pointer(&buf[etlOffEventRecordCallback])) = s.callback

	th, _, lastErr := procOpenTraceW.Call(uintptr(unsafe.Pointer(&buf[0])))
	if th == ^uintptr(0) { // INVALID_PROCESSTRACE_HANDLE = (TRACEHANDLE)-1
		return fmt.Errorf("OpenTrace(%s): %w", s.name, lastErr)
	}
	s.traceHandle = th

	// ProcessTrace blocks until the trace session is stopped. Run it in a
	// goroutine and stop the session when ctx fires.
	errCh := make(chan error, 1)
	go func() {
		r1, _, e := procProcessTrace.Call(uintptr(unsafe.Pointer(&th)), 1, 0, 0)
		if r1 != 0 {
			errCh <- fmt.Errorf("ProcessTrace: win32=%d (%w)", r1, e)
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-ctx.Done():
		s.Close()
		<-errCh
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Close stops the trace session and releases all resources.
// Safe to call multiple times; subsequent calls are no-ops.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.stopTrace()
		if s.traceHandle != 0 {
			procCloseTrace.Call(s.traceHandle)
			s.traceHandle = 0
		}
	})
}

// eventCallback is invoked by Windows (via syscall.NewCallback trampoline)
// for each ETW event. It copies UserData bytes before dispatching so the
// backing buffer can be reused by the ETW runtime after we return.
func (s *Session) eventCallback(record *EventRecord) uintptr {
	ev := Event{
		ProviderGUID: record.EventHeader.ProviderID,
		EventID:      record.EventHeader.Descriptor.ID,
		Version:      record.EventHeader.Descriptor.Version,
		Level:        record.EventHeader.Descriptor.Level,
		ProcessID:    record.EventHeader.ProcessID,
		ThreadID:     record.EventHeader.ThreadID,
		Timestamp:    filetimeToTime(record.EventHeader.TimeStamp),
	}

	if record.UserDataLen > 0 && record.UserData != 0 {
		ev.UserData = make([]byte, record.UserDataLen)
		src := unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), record.UserDataLen)
		copy(ev.UserData, src)
	}

	s.mu.RLock()
	handlers := s.handlers[ev.ProviderGUID]
	s.mu.RUnlock()

	for _, h := range handlers {
		h(ev)
	}
	return 0
}

// startTrace calls StartTraceW to create a new ETW real-time session.
// If the session name already exists (e.g. previous crash), it stops it first.
func (s *Session) startTrace() error {
	// EVENT_TRACE_PROPERTIES + two UTF-16 strings appended after the struct.
	// The struct is 120 bytes on x64; we append 1024 chars for the logger name.
	type wNodeHeader struct {
		BufferSize        uint32
		ProviderId        uint32
		HistoricalContext uint64
		TimeStamp         int64
		Guid              windows.GUID
		ClientContext     uint32
		Flags             uint32
	}
	type eventTraceProperties struct {
		Wnode               wNodeHeader
		BufferSize          uint32
		MinimumBuffers      uint32
		MaximumBuffers      uint32
		MaximumFileSize     uint32
		LogFileMode         uint32
		FlushTimer          uint32
		EnableFlags         uint32
		AgeLimit            int32
		NumberOfBuffers     uint32
		FreeBuffers         uint32
		EventsLost          uint32
		BuffersWritten      uint32
		LogBuffersLost      uint32
		RealTimeBuffersLost uint32
		LoggerThreadId      syscall.Handle
		LogFileNameOffset   uint32
		LoggerNameOffset    uint32
	}

	const nameMaxChars = 1024
	propStructSize := unsafe.Sizeof(eventTraceProperties{})
	totalSize := propStructSize + uintptr(nameMaxChars)*2 // UTF-16: 2 bytes/char
	buf := make([]byte, totalSize)

	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(totalSize)
	props.Wnode.Flags = wNodeFlagTracedGuid
	props.LogFileMode = eventTraceRealTimeMode
	props.BufferSize = 64 // 64 KB per buffer
	props.MinimumBuffers = 4
	props.MaximumBuffers = 64
	props.LoggerNameOffset = uint32(propStructSize)

	// Write the session name after the struct.
	nameUTF16 := syscall.StringToUTF16(s.name)
	nameDst := (*[nameMaxChars]uint16)(unsafe.Pointer(&buf[propStructSize]))
	n := len(nameUTF16)
	if n > nameMaxChars {
		n = nameMaxChars
	}
	copy(nameDst[:], nameUTF16[:n])

	namePtr, _ := syscall.UTF16PtrFromString(s.name)
	r1, _, err := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&s.handle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
	)

	const errorAlreadyExists = 183
	if r1 == errorAlreadyExists {
		s.stopTraceByName()
		r1, _, err = procStartTraceW.Call(
			uintptr(unsafe.Pointer(&s.handle)),
			uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(props)),
		)
	}
	if r1 != 0 {
		return fmt.Errorf("StartTrace: win32=%d (%w)", r1, err)
	}
	return nil
}

func (s *Session) stopTrace() {
	if s.handle == 0 {
		return
	}
	procControlTraceW.Call(uintptr(s.handle), 0, 0, controlTraceStop)
}

func (s *Session) stopTraceByName() {
	namePtr, _ := syscall.UTF16PtrFromString(s.name)
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(namePtr)), 0, controlTraceStop)
}

// filetimeToTime converts a Windows FILETIME (100-nanosecond intervals since
// 1601-01-01 UTC) to a Go time.Time in UTC.
func filetimeToTime(ft int64) time.Time {
	// Difference between Windows epoch (1601-01-01) and Unix epoch (1970-01-01)
	// in 100-ns intervals.
	const windowsToUnixEpoch int64 = 116444736000000000
	unix100ns := ft - windowsToUnixEpoch
	return time.Unix(unix100ns/1e7, (unix100ns%1e7)*100).UTC()
}
