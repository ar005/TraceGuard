//go:build windows

package etw

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
	procEvtClose     = modWevtapi.NewProc("EvtClose")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
)

const (
	evtSubscribeToFutureEvents = 1 // real-time: only events from the subscribe point onward
	evtRenderEventXML          = 1
)

// EvtXMLHandler is called with the XML text of each matched event.
// It is invoked from a dedicated dispatch goroutine; implementations must not block.
type EvtXMLHandler func(xml string)

// LogSubscription delivers Windows Event Log records in real time via EvtSubscribe.
// This replaces the wevtutil polling approach used by the auth and winevent monitors.
type LogSubscription struct {
	handle   uintptr
	callback uintptr // pinned for subscription lifetime
	eventCh  chan string
}

// NewLogSubscription creates a push subscription to a Windows Event Log channel.
//
//	channel — e.g. "Security", "System", "Microsoft-Windows-Sysmon/Operational"
//	query   — XPath filter, e.g. `*[System[(EventID=4624 or EventID=4625)]]`
//	handler — called for each matched event's XML; must not block
//
// The returned closer stops the subscription and must be called when the
// monitor stops (typically from Monitor.Stop via defer or cleanup).
//
// The subscription is tied to ctx — when ctx is cancelled the dispatch goroutine
// exits, but the EvtSubscribe handle must still be explicitly closed via the
// returned closer.
func NewLogSubscription(ctx context.Context, channel, query string, handler EvtXMLHandler) (closer func(), err error) {
	sub := &LogSubscription{
		eventCh: make(chan string, 256),
	}

	// Windows calls this callback on the thread pool with each new event handle.
	// Action 2 = EvtSubscribeActionDeliver.
	sub.callback = syscall.NewCallback(func(action uint32, _ uintptr, eventHandle uintptr) uintptr {
		if action != 2 {
			return 0
		}
		xml, renderErr := renderEventXML(eventHandle)
		if renderErr == nil && xml != "" {
			select {
			case sub.eventCh <- xml:
			default:
				// Drop if the channel is full rather than blocking the callback thread.
			}
		}
		return 0
	})

	channelPtr, _ := syscall.UTF16PtrFromString(channel)
	queryPtr, _ := syscall.UTF16PtrFromString(query)

	handle, _, lastErr := procEvtSubscribe.Call(
		0, // Session — local machine
		0, // SignalEvent — use callback instead
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		0,            // Bookmark
		0,            // Context
		sub.callback,
		evtSubscribeToFutureEvents,
	)
	if handle == 0 {
		return nil, fmt.Errorf("EvtSubscribe(%s): %w", channel, lastErr)
	}
	sub.handle = handle

	// Dispatch goroutine: relay XML events to the caller's handler.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case xml := <-sub.eventCh:
				handler(xml)
			}
		}
	}()

	return func() { procEvtClose.Call(sub.handle) }, nil
}

// renderEventXML renders an EVT_HANDLE to its XML representation via EvtRender.
// Retries once with a larger buffer if ERROR_INSUFFICIENT_BUFFER (122) is returned.
func renderEventXML(handle uintptr) (string, error) {
	bufSize := uint32(4096)
	buf := make([]uint16, bufSize)
	var used, propCount uint32

	r1, _, err := procEvtRender.Call(
		0, handle,
		evtRenderEventXML,
		uintptr(bufSize*2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propCount)),
	)

	const errorInsufficientBuffer = 122
	if r1 == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == errorInsufficientBuffer {
			buf = make([]uint16, used/2+1)
			r1, _, err = procEvtRender.Call(
				0, handle,
				evtRenderEventXML,
				uintptr(uint32(len(buf))*2),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(&used)),
				uintptr(unsafe.Pointer(&propCount)),
			)
			if r1 == 0 {
				return "", fmt.Errorf("EvtRender retry: %w", err)
			}
		} else {
			return "", fmt.Errorf("EvtRender: %w", err)
		}
	}

	return syscall.UTF16ToString(buf[:used/2]), nil
}
