package registry

import "testing"

// buildPayload constructs a Kernel-Registry ETW event payload for testing.
// The 24-byte header is zeroed; keyPath and optional valueName follow as
// null-terminated UTF-16LE strings.
func buildPayload(keyPath, valueName string) []byte {
	buf := make([]byte, regPayloadHeaderSize)

	encUTF16 := func(s string) []byte {
		b := make([]byte, 0, len(s)*2+2)
		for _, r := range s {
			b = append(b, byte(r), byte(r>>8))
		}
		return append(b, 0, 0) // null terminator
	}

	buf = append(buf, encUTF16(keyPath)...)
	if valueName != "" {
		buf = append(buf, encUTF16(valueName)...)
	}
	return buf
}

func TestParseRegPayload_SetValue(t *testing.T) {
	data := buildPayload(`\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "MyApp")
	key, val, ok := parseRegPayload(1, data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	if key != want {
		t.Errorf("keyPath: got %q, want %q", key, want)
	}
	if val != "MyApp" {
		t.Errorf("valueName: got %q, want %q", val, "MyApp")
	}
}

func TestParseRegPayload_DeleteValue(t *testing.T) {
	data := buildPayload(`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\evildll`, "Start")
	key, val, ok := parseRegPayload(2, data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key == "" {
		t.Error("keyPath should not be empty")
	}
	if val != "Start" {
		t.Errorf("valueName: got %q, want %q", val, "Start")
	}
}

func TestParseRegPayload_CreateKey(t *testing.T) {
	// Event ID 3 — no value name in payload, and we don't try to read one.
	data := buildPayload(`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\newkey`, "")
	key, val, ok := parseRegPayload(3, data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key == "" {
		t.Error("keyPath should not be empty")
	}
	if val != "" {
		t.Errorf("valueName should be empty for CreateKey, got %q", val)
	}
}

func TestParseRegPayload_DeleteKey(t *testing.T) {
	data := buildPayload(`\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "")
	key, val, ok := parseRegPayload(5, data)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if key == "" {
		t.Error("keyPath should not be empty")
	}
	if val != "" {
		t.Errorf("valueName should be empty for DeleteKey, got %q", val)
	}
}

func TestParseRegPayload_TooShort(t *testing.T) {
	short := make([]byte, regPayloadHeaderSize-1) // 23 bytes
	_, _, ok := parseRegPayload(1, short)
	if ok {
		t.Error("expected ok=false for short buffer")
	}
}

func TestParseRegPayload_NilData(t *testing.T) {
	_, _, ok := parseRegPayload(1, nil)
	if ok {
		t.Error("expected ok=false for nil data")
	}
}

func TestParseRegPayload_ExactlyHeaderNullPath(t *testing.T) {
	// 24-byte header only — no key path data; readUTF16Null returns "".
	data := make([]byte, regPayloadHeaderSize)
	_, _, ok := parseRegPayload(1, data)
	if ok {
		t.Error("expected ok=false when keyPath is empty (header only)")
	}
}

func TestRegNTPathToWin32_HKLM(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{`\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services`, `HKLM\SYSTEM\CurrentControlSet\Services`},
		{`\REGISTRY\MACHINE\`, `HKLM\`},
	}
	for _, tt := range tests {
		if got := regNTPathToWin32(tt.in); got != tt.want {
			t.Errorf("regNTPathToWin32(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRegNTPathToWin32_HKCU(t *testing.T) {
	ntPath := `\REGISTRY\USER\S-1-5-21-1234567890-1234567890-1234567890-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	got := regNTPathToWin32(ntPath)
	want := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRegNTPathToWin32_Unknown(t *testing.T) {
	unknown := `HKLM\already\win32\format`
	if got := regNTPathToWin32(unknown); got != unknown {
		t.Errorf("unknown path should be returned unchanged: got %q", got)
	}
}
