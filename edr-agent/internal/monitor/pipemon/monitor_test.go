package pipemon

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestClassifyLocation(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/tmp/pipe1", "tmp"},
		{"/tmp/subdir/pipe2", "tmp"},
		{"/var/tmp/pipe3", "tmp"},
		{"/dev/shm/pipe4", "dev_shm"},
		{"/dev/shm/subdir/pipe5", "dev_shm"},
		{"/run/pipe6", "run"},
		{"/run/user/1000/pipe7", "run"},
		{"/home/user/pipe8", "other"},
		{"/opt/app/pipe9", "other"},
		{"", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := classifyLocation(tt.path)
			if got != tt.want {
				t.Errorf("classifyLocation(%q): got %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParsePID(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"1234", 1234},
		{"1", 1},
		{"0", 0},
		{"99999", 99999},
		{"abc", 0},
		{"12abc", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parsePID(tt.input)
			if got != tt.want {
				t.Errorf("parsePID(%q): got %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestBaselineDiffing(t *testing.T) {
	baseline := map[string]pipeInfo{
		"/tmp/pipe_old":    {Path: "/tmp/pipe_old", Permissions: 0644},
		"/dev/shm/pipe_ss": {Path: "/dev/shm/pipe_ss", Permissions: 0666},
	}

	current := map[string]pipeInfo{
		"/tmp/pipe_old":     {Path: "/tmp/pipe_old", Permissions: 0644},
		"/tmp/pipe_new":     {Path: "/tmp/pipe_new", Permissions: 0644},
		"/run/pipe_another": {Path: "/run/pipe_another", Permissions: 0600},
	}

	// Detect new pipes.
	var newPipes []string
	for path := range current {
		if _, existed := baseline[path]; !existed {
			newPipes = append(newPipes, path)
		}
	}
	if len(newPipes) != 2 {
		t.Errorf("expected 2 new pipes, got %d: %v", len(newPipes), newPipes)
	}

	// Detect removed pipes.
	var removedPipes []string
	for path := range baseline {
		if _, exists := current[path]; !exists {
			removedPipes = append(removedPipes, path)
		}
	}
	if len(removedPipes) != 1 || removedPipes[0] != "/dev/shm/pipe_ss" {
		t.Errorf("expected removed pipe '/dev/shm/pipe_ss', got %v", removedPipes)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.PollIntervalS != 10 {
		t.Errorf("expected PollIntervalS=10, got %d", cfg.PollIntervalS)
	}
	if len(cfg.WatchPaths) != 4 {
		t.Errorf("expected 4 watch paths, got %d", len(cfg.WatchPaths))
	}
}

func TestNewClampsDefaults(t *testing.T) {
	cfg := Config{Enabled: true, PollIntervalS: 0}
	m := New(cfg, nil, zerolog.Nop())
	if m.cfg.PollIntervalS != 10 {
		t.Errorf("expected PollIntervalS clamped to 10, got %d", m.cfg.PollIntervalS)
	}
	if len(m.cfg.WatchPaths) != 4 {
		t.Errorf("expected 4 default watch paths, got %d", len(m.cfg.WatchPaths))
	}
}
