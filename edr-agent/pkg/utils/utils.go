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
	"path/filepath"
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

// ─── Process socket enrichment ────────────────────────────────────────────────

// ProcNetEntry is one row from /proc/net/tcp|tcp6|udp.
type ProcNetEntry struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Proto   string // "TCP" | "UDP"
	State   string // hex state → human string
	Inode   string
}

// tcpStateStr maps /proc/net/tcp state hex values to readable names.
func tcpStateStr(hex string) string {
	switch hex {
	case "01": return "ESTABLISHED"
	case "02": return "SYN_SENT"
	case "03": return "SYN_RECV"
	case "04": return "FIN_WAIT1"
	case "05": return "FIN_WAIT2"
	case "06": return "TIME_WAIT"
	case "07": return "CLOSE"
	case "08": return "CLOSE_WAIT"
	case "09": return "LAST_ACK"
	case "0A": return "LISTEN"
	case "0B": return "CLOSING"
	default:   return hex
	}
}

// parseProcNetAddrV4 decodes a "IPHEX:PORTHEX" field from /proc/net/tcp.
// The IP is stored as a little-endian uint32.
func parseProcNetAddrV4(s string) (ip string, port uint16) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	var b [4]byte
	n, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return "", 0
	}
	// little-endian → big-endian
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
	ip = fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	p, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0
	}
	return ip, uint16(p)
}

// ReadProcNetAll reads /proc/net/tcp, tcp6, and udp into a map of inode→ProcNetEntry.
func ReadProcNetAll() map[string]ProcNetEntry {
	out := make(map[string]ProcNetEntry, 64)
	readProcNetFile("/proc/net/tcp",  "TCP", false, out)
	readProcNetFile("/proc/net/tcp6", "TCP", true,  out)
	readProcNetFile("/proc/net/udp",  "UDP", false, out)
	return out
}

func readProcNetFile(path, proto string, isV6 bool, out map[string]ProcNetEntry) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		var srcIP, dstIP string
		var srcPort, dstPort uint16
		if !isV6 {
			srcIP, srcPort = parseProcNetAddrV4(fields[1])
			dstIP, dstPort = parseProcNetAddrV4(fields[2])
		} else {
			// IPv6: skip for now, most curl/nslookup traffic is v4
			continue
		}
		if srcIP == "" {
			continue
		}
		inode := fields[9]
		out[inode] = ProcNetEntry{
			SrcIP: srcIP, SrcPort: srcPort,
			DstIP: dstIP, DstPort: dstPort,
			Proto: proto,
			State: tcpStateStr(strings.ToUpper(fields[3])),
			Inode: inode,
		}
	}
}

// PidOpenSockets scans /proc/<pid>/fd for socket:[] symlinks and maps them
// through /proc/net/tcp|udp to return live connection info at that moment.
// Non-fatal: returns whatever it finds, ignoring permission errors.
func PidOpenSockets(pid uint32) []ProcNetEntry {
	netMap := ReadProcNetAll()
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var results []ProcNetEntry
	seen := make(map[string]bool)
	for _, ent := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, ent.Name()))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(link, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		if seen[inode] {
			continue
		}
		seen[inode] = true
		if entry, ok := netMap[inode]; ok {
			results = append(results, entry)
		}
	}
	return results
}

// ─── Cmdline network target extraction ────────────────────────────────────────

// NetworkArgTarget is a host/IP extracted from a process's command-line arguments.
// (Converted to types.NetworkTarget by the process monitor.)
type NetworkArgTarget struct {
	Raw    string
	Host   string
	Port   uint16
	Scheme string
}

// netTools maps process comm names to true if they are network tools whose
// arguments should be parsed for IP/hostname targets.
var netTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "netcat": true, "ncat": true,
	"nslookup": true, "dig": true, "host": true, "whois": true,
	"ssh": true, "scp": true, "ftp": true, "sftp": true,
	"python": true, "python3": true, "perl": true, "ruby": true,
	"socat": true, "telnet": true, "openssl": true,
}

// ParseNetworkTargets inspects a process's comm name and argument list and
// returns any URL / hostname / IP targets it finds.  This is best-effort and
// does not attempt to fully parse every tool's flag syntax.
func ParseNetworkTargets(comm string, args []string) []NetworkArgTarget {
	base := strings.ToLower(filepath.Base(comm))
	if !netTools[base] {
		return nil
	}
	var targets []NetworkArgTarget
	for _, arg := range args {
		t := extractTarget(arg)
		if t != nil {
			targets = append(targets, *t)
		}
	}
	return targets
}

// extractTarget tries to parse a URL or bare IP/hostname from a single arg.
func extractTarget(arg string) *NetworkArgTarget {
	// Skip flags and empty strings.
	if arg == "" || strings.HasPrefix(arg, "-") {
		return nil
	}

	// Looks like a URL (has "://")
	if idx := strings.Index(arg, "://"); idx != -1 {
		scheme := strings.ToLower(arg[:idx])
		rest := arg[idx+3:]
		// strip path and query
		hostPort := rest
		if i := strings.IndexAny(rest, "/?#"); i != -1 {
			hostPort = rest[:i]
		}
		host, portStr, hasPort := strings.Cut(hostPort, ":")
		var port uint16
		if hasPort {
			p, _ := strconv.ParseUint(portStr, 10, 16)
			port = uint16(p)
		}
		if host == "" {
			return nil
		}
		return &NetworkArgTarget{Raw: arg, Host: host, Port: port, Scheme: scheme}
	}

	// Bare IP address (must be valid dotted-quad)
	if looksLikeIP(arg) {
		return &NetworkArgTarget{Raw: arg, Host: arg}
	}

	// Bare hostname (at least one dot, no slashes, no spaces, not a path)
	if looksLikeHostname(arg) {
		return &NetworkArgTarget{Raw: arg, Host: arg}
	}

	return nil
}

func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func looksLikeHostname(s string) bool {
	if strings.ContainsAny(s, "/ \\@:") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return len(s) >= 4 && len(s) <= 253
}
