package process

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseProcessEventData(t *testing.T) {
	// "cmd.exe" in UTF-16LE + null terminator
	name := []byte{
		0x63, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x2E, 0x00,
		0x65, 0x00, 0x78, 0x00, 0x65, 0x00,
		0x00, 0x00,
	}
	data := make([]byte, 8+len(name))
	binary.LittleEndian.PutUint32(data[0:4], 1234) // PID
	binary.LittleEndian.PutUint32(data[4:8], 5)    // PPID
	copy(data[8:], name)

	pid, ppid, img, ok := parseProcessEventData(data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if pid != 1234 {
		t.Errorf("PID: got %d, want 1234", pid)
	}
	if ppid != 5 {
		t.Errorf("PPID: got %d, want 5", ppid)
	}
	if img != "cmd.exe" {
		t.Errorf("ImageFileName: got %q, want cmd.exe", img)
	}
}

func TestParseProcessEventData_Short(t *testing.T) {
	_, _, _, ok := parseProcessEventData(make([]byte, 9))
	if ok {
		t.Fatal("expected ok=false for 9-byte payload")
	}
	_, _, _, ok2 := parseProcessEventData(nil)
	if ok2 {
		t.Fatal("expected ok=false for nil")
	}
}

func TestReadUTF16LE(t *testing.T) {
	// Immediately null-terminated.
	if s := readUTF16LE([]byte{0x00, 0x00, 0xFF, 0xFF}, 0); s != "" {
		t.Errorf("null-terminated: got %q, want empty", s)
	}
	// "A" with no null terminator.
	if s := readUTF16LE([]byte{0x41, 0x00}, 0); s != "A" {
		t.Errorf("no terminator: got %q, want A", s)
	}
	// Offset past end.
	if s := readUTF16LE([]byte{0x41, 0x00}, 4); s != "" {
		t.Errorf("past end: got %q, want empty", s)
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{`cmd.exe /c echo hello`, []string{"cmd.exe", "/c", "echo", "hello"}},
		{`"C:\Program Files\app.exe" -flag "arg with space"`, []string{`C:\Program Files\app.exe`, "-flag", "arg with space"}},
		{``, nil},
		{`single`, []string{"single"}},
	}
	for _, tt := range tests {
		got := splitArgs(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitArgs(%q): got %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitArgs(%q)[%d]: got %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestSplitArgs_QuotedSpaces(t *testing.T) {
	args := splitArgs(`"C:\path with spaces\foo.exe" -a "two words" -b`)
	if len(args) != 4 {
		t.Fatalf("got %d args, want 4: %v", len(args), args)
	}
	if args[2] != "two words" {
		t.Errorf("quoted arg: got %q, want %q", args[2], "two words")
	}
	if !strings.HasSuffix(args[0], "foo.exe") {
		t.Errorf("first arg path: got %q", args[0])
	}
}

func TestDetectInterpreter(t *testing.T) {
	interp, script := detectInterpreter(
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		[]string{"powershell.exe", "-File", `C:\temp\script.ps1`},
	)
	if interp != "powershell" {
		t.Errorf("interp: got %q, want powershell", interp)
	}
	if script != `C:\temp\script.ps1` {
		t.Errorf("script: got %q, want C:\\temp\\script.ps1", script)
	}

	// Non-interpreter.
	i2, s2 := detectInterpreter(`C:\Windows\notepad.exe`, []string{"notepad.exe"})
	if i2 != "" || s2 != "" {
		t.Errorf("notepad should not be interpreter: got (%q, %q)", i2, s2)
	}

	// Python -c: first non-flag arg is returned as scriptPath.
	// captureScriptContent distinguishes inline content from file paths separately.
	i3, s3 := detectInterpreter(`python.exe`, []string{"python.exe", "-c", "print('hi')"})
	if i3 != "python" {
		t.Errorf("python interp: got %q, want python", i3)
	}
	if s3 != "print('hi')" {
		t.Errorf("script arg: got %q, want print('hi')", s3)
	}
}

func TestDecodeBase64Unicode(t *testing.T) {
	// Encode "Write-Host 'hi'" as PowerShell -EncodedCommand (UTF-16LE base64).
	src := "Write-Host 'hi'"
	utf16le := make([]byte, len(src)*2)
	for i, r := range src {
		utf16le[i*2] = byte(r)
		utf16le[i*2+1] = 0
	}
	encoded := base64.StdEncoding.EncodeToString(utf16le)

	decoded, err := decodeBase64Unicode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded != src {
		t.Errorf("got %q, want %q", decoded, src)
	}
}

func TestDecodeBase64Unicode_BadInput(t *testing.T) {
	_, err := decodeBase64Unicode("not!valid!base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestExtractComm(t *testing.T) {
	tests := []struct{ path, want string }{
		{`C:\Windows\System32\cmd.exe`, "cmd.exe"},
		{`notepad.exe`, "notepad.exe"},
		{"", ""},
		{`C:\deeply\nested\path\foo.exe`, "foo.exe"},
	}
	for _, tt := range tests {
		if got := extractComm(tt.path); got != tt.want {
			t.Errorf("extractComm(%q): got %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestIsSuspiciousExe(t *testing.T) {
	suspicious := []string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\wscript.exe`,
		`C:\Windows\System32\certutil.exe`,
	}
	for _, p := range suspicious {
		if !isSuspiciousExe(p) {
			t.Errorf("expected %q to be suspicious", p)
		}
	}
	if isSuspiciousExe(`C:\Windows\notepad.exe`) {
		t.Error("notepad.exe should not be suspicious")
	}
}

func TestHashFile_NonExistent(t *testing.T) {
	h, size := hashFile("/nonexistent/path/file.exe")
	if h != "" || size != 0 {
		t.Errorf("non-existent file: got (%q, %d), want ('', 0)", h, size)
	}
}
