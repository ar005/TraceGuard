package file

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/youredr/edr-agent-win/pkg/types"
)

// buildFNI constructs a raw FILE_NOTIFY_INFORMATION byte slice.
// nextOff is the byte offset to the next entry (0 = last).
func buildFNI(nextOff, action uint32, name string) []byte {
	// Encode name as UTF-16LE.
	utf16 := make([]byte, len(name)*2)
	for i, r := range name {
		utf16[i*2] = byte(r)
		utf16[i*2+1] = 0
	}
	nameLen := uint32(len(utf16))

	header := make([]byte, 12)
	binary.LittleEndian.PutUint32(header[0:], nextOff)
	binary.LittleEndian.PutUint32(header[4:], action)
	binary.LittleEndian.PutUint32(header[8:], nameLen)
	return append(header, utf16...)
}

func TestParseFileNotifyRecords_Single(t *testing.T) {
	buf := buildFNI(0, fileActionAdded, "foo.txt")
	records := parseFileNotifyRecords(buf)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Action != fileActionAdded {
		t.Errorf("action: got %d, want %d", records[0].Action, fileActionAdded)
	}
	if records[0].FileName != "foo.txt" {
		t.Errorf("FileName: got %q, want %q", records[0].FileName, "foo.txt")
	}
}

func TestParseFileNotifyRecords_Multiple(t *testing.T) {
	entry1 := buildFNI(0, fileActionAdded, "a.txt")
	entry2 := buildFNI(0, fileActionModified, "b.log")

	// Set nextOff in entry1 to point to entry2.
	nextOff := uint32(len(entry1))
	binary.LittleEndian.PutUint32(entry1[0:], nextOff)

	buf := append(entry1, entry2...)
	records := parseFileNotifyRecords(buf)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].FileName != "a.txt" {
		t.Errorf("[0].FileName: got %q", records[0].FileName)
	}
	if records[1].Action != fileActionModified {
		t.Errorf("[1].Action: got %d, want modified", records[1].Action)
	}
}

func TestParseFileNotifyRecords_RenamePair(t *testing.T) {
	old := buildFNI(0, fileActionRenamedOld, "old.tmp")
	neu := buildFNI(0, fileActionRenamedNew, "new.txt")

	binary.LittleEndian.PutUint32(old[0:], uint32(len(old)))
	buf := append(old, neu...)

	records := parseFileNotifyRecords(buf)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Action != fileActionRenamedOld {
		t.Errorf("[0]: want renamedOld, got %d", records[0].Action)
	}
	if records[1].Action != fileActionRenamedNew {
		t.Errorf("[1]: want renamedNew, got %d", records[1].Action)
	}
	if records[1].FileName != "new.txt" {
		t.Errorf("[1].FileName: got %q", records[1].FileName)
	}
}

func TestParseFileNotifyRecords_Empty(t *testing.T) {
	if records := parseFileNotifyRecords(nil); len(records) != 0 {
		t.Errorf("nil buffer: got %d records", len(records))
	}
	if records := parseFileNotifyRecords(make([]byte, 5)); len(records) != 0 {
		t.Errorf("short buffer: got %d records", len(records))
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"A", []byte{0x41, 0x00}, "A"},
		{"hello", []byte{0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00}, "hello"},
		{"odd byte ignored", []byte{0x41, 0x00, 0x42}, "A"}, // trailing byte ignored
	}
	for _, tt := range tests {
		if got := decodeUTF16LE(tt.in); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestClassifySeverity(t *testing.T) {
	critical := []string{
		`C:\Windows\System32\config\SAM`,
		`C:\windows\system32\drivers\etc\hosts`,
		`C:\Windows\System32\sethc.exe`,
		`C:\WINDOWS\system32\utilman.exe`,
	}
	for _, p := range critical {
		if got := classifySeverity(p); got != types.SeverityHigh {
			t.Errorf("classifySeverity(%q): got %q, want High", p, got)
		}
	}
	normal := []string{
		`C:\Users\alice\Documents\notes.txt`,
		`C:\ProgramData\app\log.txt`,
	}
	for _, p := range normal {
		if got := classifySeverity(p); got != types.SeverityInfo {
			t.Errorf("classifySeverity(%q): got %q, want Info", p, got)
		}
	}
}

func TestIsHidden(t *testing.T) {
	if !isHidden(".hidden") {
		t.Error("expected .hidden to be hidden")
	}
	if isHidden("visible.txt") {
		t.Error("expected visible.txt to not be hidden")
	}
	if isHidden("") {
		t.Error("empty string should not be hidden")
	}
}

func TestHashFile_NonExistent(t *testing.T) {
	h, size := hashFile("/nonexistent/no/such/file.exe")
	if h != "" || size != 0 {
		t.Errorf("non-existent file: got (%q, %d), want ('', 0)", h, size)
	}
}

func TestDecodeUTF16LE_WindowsPath(t *testing.T) {
	// "dir\file.txt" encoded as UTF-16LE
	path := `dir\file.txt`
	b := make([]byte, len(path)*2)
	for i, r := range path {
		b[i*2] = byte(r)
		b[i*2+1] = 0
	}
	got := decodeUTF16LE(b)
	if got != path {
		t.Errorf("got %q, want %q", got, path)
	}
	if !strings.Contains(got, `\`) {
		t.Error("decoded path should contain backslash")
	}
}
