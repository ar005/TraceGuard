// pkg/utils/utils.go
// Shared utility functions used across all EDR components.

package utils

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// ─── Event ID generation ──────────────────────────────────────────────────────

var eventCounter atomic.Uint64

// NewEventID generates a UUID-based event identifier.
func NewEventID() string {
	return uuid.New().String()
}

// ─── Hashing ─────────────────────────────────────────────────────────────────

// HashExe computes SHA256 of the file at path.
// Returns (hash_hex, size_bytes). On error returns ("", 0).
func HashExe(path string) (string, int64) {
	// Dereference symlink (e.g. /proc/<pid>/exe).
	realPath, err := os.Readlink(path)
	if err != nil {
		realPath = path
	}

	f, err := os.Open(realPath)
	if err != nil {
		return "", 0
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0
	}
	return hex.EncodeToString(h.Sum(nil)), n
}

// HashFile computes SHA256 of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ─── Boot time → wall clock ───────────────────────────────────────────────────
// eBPF gives us ktime_get_ns() which is nanoseconds since boot.
// To convert to wall clock: wallTime = bootTime + ns_since_boot.

var (
	bootTimeOnce sync.Once
	bootTimeNs   uint64 // unix nanoseconds of system boot
)

func getBootTime() uint64 {
	bootTimeOnce.Do(func() {
		// Read /proc/stat for btime (seconds since epoch at boot).
		f, err := os.Open("/proc/stat")
		if err != nil {
			bootTimeNs = 0
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "btime ") {
				parts := strings.Fields(line)
				if len(parts) == 2 {
					if sec, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						bootTimeNs = sec * uint64(time.Second)
						return
					}
				}
			}
		}
	})
	return bootTimeNs
}

// BootNsToTime converts a kernel ktime_get_ns() value to a wall-clock time.Time.
func BootNsToTime(bootNs uint64) time.Time {
	wallNs := getBootTime() + bootNs
	return time.Unix(0, int64(wallNs))
}

// ─── UID → username ───────────────────────────────────────────────────────────

var (
	uidCacheMu sync.RWMutex
	uidCache   = make(map[uint32]string)
)

// UIDToUsername resolves a UID to a username string.
// Caches results to avoid repeated /etc/passwd reads.
func UIDToUsername(uid uint32) string {
	uidCacheMu.RLock()
	if name, ok := uidCache[uid]; ok {
		uidCacheMu.RUnlock()
		return name
	}
	uidCacheMu.RUnlock()

	name := fmt.Sprintf("%d", uid) // fallback
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		name = u.Username
	}

	uidCacheMu.Lock()
	uidCache[uid] = name
	uidCacheMu.Unlock()
	return name
}

// ─── IP helpers ───────────────────────────────────────────────────────────────

// Uint32ToIPv4 converts a big-endian uint32 from the kernel to a dotted-decimal string.
func Uint32ToIPv4(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(n>>24)&0xff,
		(n>>16)&0xff,
		(n>>8)&0xff,
		n&0xff)
}

// Uint32ToIPv4LE converts a little-endian uint32 (common in x86 eBPF structs).
func Uint32ToIPv4LE(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		n&0xff,
		(n>>8)&0xff,
		(n>>16)&0xff,
		(n>>24)&0xff)
}

// IsPrivateIPv4 returns true for RFC1918, loopback, and link-local addresses.
func IsPrivateIPv4(ip string) bool {
	privateRanges := []string{
		"10.", "192.168.", "127.", "169.254.",
	}
	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	// 172.16.0.0/12
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil && n >= 16 && n <= 31 {
				return true
			}
		}
	}
	return false
}
