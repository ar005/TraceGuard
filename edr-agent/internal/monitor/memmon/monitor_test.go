package memmon

import (
	"testing"

	"github.com/rs/zerolog"
)

func nopLogger() zerolog.Logger {
	return zerolog.Nop()
}

func TestParseMapLine(t *testing.T) {
	m := New(DefaultConfig(), nil, nopLogger())

	tests := []struct {
		name      string
		line      string
		wantOK    bool
		wantTech  string
		wantPerms string
		wantSize  int64
	}{
		{
			name:      "anonymous_rwxp_region",
			line:      "7f1234000000-7f1234001000 rwxp 00000000 00:00 0",
			wantOK:    true,
			wantTech:  "anonymous_exec",
			wantPerms: "rwxp",
			wantSize:  4096,
		},
		{
			name:      "anonymous_exec_only",
			line:      "7f1234000000-7f1234002000 r-xp 00000000 00:00 0",
			wantOK:    true,
			wantTech:  "anonymous_exec",
			wantPerms: "r-xp",
			wantSize:  8192,
		},
		{
			name:   "non_executable_anonymous",
			line:   "7f1234000000-7f1234001000 rw-p 00000000 00:00 0",
			wantOK: false,
		},
		{
			name:   "mapped_file_executable",
			line:   "7f1234000000-7f1234001000 r-xp 00000000 08:01 12345 /usr/lib/libc.so.6",
			wantOK: false,
		},
		{
			name:      "executable_heap",
			line:      "7f1234000000-7f1234010000 rwxp 00000000 00:00 0 [heap]",
			wantOK:    true,
			wantTech:  "anonymous_exec",
			wantPerms: "rwxp",
			wantSize:  65536,
		},
		{
			name:      "executable_stack",
			line:      "7ffd12340000-7ffd12360000 rwxp 00000000 00:00 0 [stack]",
			wantOK:    true,
			wantTech:  "anonymous_exec",
			wantPerms: "rwxp",
			wantSize:  131072,
		},
		{
			name:      "memfd_exec",
			line:      "7f1234000000-7f1234001000 r-xp 00000000 00:00 0 /memfd:malware (deleted)",
			wantOK:    true,
			wantTech:  "memfd_exec",
			wantPerms: "r-xp",
			wantSize:  4096,
		},
		{
			name:   "vdso_not_suspicious",
			line:   "7ffd12340000-7ffd12342000 r-xp 00000000 00:00 0 [vdso]",
			wantOK: false,
		},
		{
			name:   "too_few_fields",
			line:   "7f1234000000-7f1234001000 rwxp",
			wantOK: false,
		},
		{
			name:   "empty_line",
			line:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, technique, ok := m.parseMapLine(tt.line)
			if ok != tt.wantOK {
				t.Errorf("parseMapLine ok: got %v, want %v", ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if technique != tt.wantTech {
				t.Errorf("technique: got %q, want %q", technique, tt.wantTech)
			}
			if r.Permissions != tt.wantPerms {
				t.Errorf("permissions: got %q, want %q", r.Permissions, tt.wantPerms)
			}
			if r.Size != tt.wantSize {
				t.Errorf("size: got %d, want %d", r.Size, tt.wantSize)
			}
		})
	}
}

func TestParseRegionSize(t *testing.T) {
	tests := []struct {
		addrRange string
		want      int64
	}{
		{"7f1234000000-7f1234001000", 4096},
		{"0000000000-0000001000", 4096},
		{"0-1000", 4096},
		{"invalid", 0},
		{"", 0},
		{"abc-xyz", 0}, // not valid hex
	}

	for _, tt := range tests {
		t.Run(tt.addrRange, func(t *testing.T) {
			got := parseRegionSize(tt.addrRange)
			if got != tt.want {
				t.Errorf("parseRegionSize(%q): got %d, want %d", tt.addrRange, got, tt.want)
			}
		})
	}
}

func TestIsIgnored(t *testing.T) {
	m := New(DefaultConfig(), nil, nopLogger())

	tests := []struct {
		comm string
		want bool
	}{
		{"java", true},
		{"node", true},
		{"python3", true},
		{"python", true},
		{"firefox", true},
		{"chrome", true},
		{"chromium", true},
		{"code", true},
		{"bash", false},
		{"nginx", false},
		{"", false},
		{"Java", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := m.isIgnored(tt.comm)
			if got != tt.want {
				t.Errorf("isIgnored(%q): got %v, want %v", tt.comm, got, tt.want)
			}
		})
	}
}

func TestDefaultConfigValues(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.PollIntervalS != 15 {
		t.Errorf("expected PollIntervalS=15, got %d", cfg.PollIntervalS)
	}
	if len(cfg.IgnoreComms) == 0 {
		t.Error("expected non-empty IgnoreComms")
	}
}

func TestNewClampsInterval(t *testing.T) {
	cfg := Config{Enabled: true, PollIntervalS: 0}
	m := New(cfg, nil, nopLogger())
	if m.cfg.PollIntervalS != 15 {
		t.Errorf("expected PollIntervalS clamped to 15, got %d", m.cfg.PollIntervalS)
	}
}
