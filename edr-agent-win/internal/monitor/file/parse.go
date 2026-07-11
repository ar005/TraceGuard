// parse.go — platform-independent FILE_NOTIFY_INFORMATION parser and helpers.
// No OS-specific imports; testable on Linux CI without the Windows build tag.
package file

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"github.com/youredr/edr-agent-win/pkg/types"
)

// FILE_ACTION_* constants from winnt.h.
const (
	fileActionAdded      = 1
	fileActionRemoved    = 2
	fileActionModified   = 3
	fileActionRenamedOld = 4
	fileActionRenamedNew = 5
)

// fileNotifyRecord is a single parsed entry from a ReadDirectoryChangesW buffer.
type fileNotifyRecord struct {
	Action   uint32
	FileName string // relative path within the watched directory
}

// parseFileNotifyRecords parses the raw buffer returned by ReadDirectoryChangesW.
//
// FILE_NOTIFY_INFORMATION layout (entries linked by NextEntryOffset):
//
//	Offset  Size  Field
//	0       4     NextEntryOffset (bytes to next entry; 0 = last entry)
//	4       4     Action
//	8       4     FileNameLength (in bytes, not UTF-16 code units)
//	12      var   FileName (UTF-16LE, NOT null-terminated)
func parseFileNotifyRecords(buf []byte) []fileNotifyRecord {
	var records []fileNotifyRecord
	offset := 0
	for {
		if offset+12 > len(buf) {
			break
		}
		nextEntryOffset := binary.LittleEndian.Uint32(buf[offset:])
		action := binary.LittleEndian.Uint32(buf[offset+4:])
		nameLen := int(binary.LittleEndian.Uint32(buf[offset+8:]))
		nameStart := offset + 12
		if nameStart+nameLen > len(buf) {
			break
		}
		name := decodeUTF16LE(buf[nameStart : nameStart+nameLen])
		records = append(records, fileNotifyRecord{Action: action, FileName: name})
		if nextEntryOffset == 0 {
			break
		}
		offset += int(nextEntryOffset)
	}
	return records
}

// decodeUTF16LE converts a byte slice containing UTF-16LE encoded text to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		w := uint16(b[i]) | uint16(b[i+1])<<8
		runes = append(runes, rune(w))
	}
	return string(runes)
}

// classifySeverity returns High for modifications to security-critical Windows paths
// and Info for everything else.
func classifySeverity(fullPath string) types.Severity {
	lower := strings.ToLower(fullPath)
	for _, cp := range criticalPathFragments {
		if strings.Contains(lower, cp) {
			return types.SeverityHigh
		}
	}
	return types.SeverityInfo
}

var criticalPathFragments = []string{
	`system32\config\sam`,
	`system32\config\security`,
	`system32\config\system`,
	`system32\sethc.exe`,
	`system32\utilman.exe`,
	`system32\cmd.exe`,
	`system32\drivers\etc\hosts`,
}

// isHidden reports whether a filename looks hidden (Unix-style dot prefix).
// Windows hidden attributes require a stat call which is done separately if needed.
func isHidden(name string) bool {
	return strings.HasPrefix(name, ".")
}

// hashFile returns the SHA-256 hex digest and byte size of the file at path.
// Files larger than 50 MB are not hashed (size is returned without a digest).
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
	if stat.Size() > 50*1024*1024 {
		return "", stat.Size()
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", stat.Size()
	}
	return hex.EncodeToString(h.Sum(nil)), stat.Size()
}
