//go:build windows

package etw

import (
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32  = windows.NewLazySystemDLL("kernel32.dll")
	procQDD      = modKernel32.NewProc("QueryDosDeviceW")
	ntToWin32    map[string]string
	ntMapOnce    sync.Once
)

// ConvertNTPath converts a Windows NT kernel path such as
// \Device\HarddiskVolume3\Windows\System32\cmd.exe to its Win32 drive-letter
// equivalent C:\Windows\System32\cmd.exe.
//
// The NT→Win32 mapping is built once on first call via QueryDosDeviceW and
// cached for the process lifetime. If no mapping is found the original path
// is returned unchanged.
//
// Used by the process and file monitors to normalise paths from ETW events.
func ConvertNTPath(ntPath string) string {
	ntMapOnce.Do(buildNTMap)
	for prefix, drive := range ntToWin32 {
		if strings.HasPrefix(ntPath, prefix) {
			return drive + ntPath[len(prefix):]
		}
	}
	return ntPath
}

// buildNTMap queries QueryDosDeviceW for every drive letter A–Z and records
// the NT device path prefix that each maps to.
func buildNTMap() {
	ntToWin32 = make(map[string]string, 26)
	for c := 'A'; c <= 'Z'; c++ {
		letter := string([]rune{c, ':'})
		letterPtr, _ := syscall.UTF16PtrFromString(letter)

		var buf [1024]uint16
		r1, _, _ := procQDD.Call(
			uintptr(unsafe.Pointer(letterPtr)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if r1 == 0 {
			continue
		}
		// QueryDosDeviceW returns a double-null-terminated list; we only need
		// the first entry (the canonical device name).
		device := syscall.UTF16ToString(buf[:r1])
		if device != "" {
			ntToWin32[device] = letter
		}
	}
}
