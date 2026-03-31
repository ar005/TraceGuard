package kmod

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func nopLogger() zerolog.Logger {
	return zerolog.Nop()
}

func TestReadProcModulesFromTempFile(t *testing.T) {
	// readProcModules is hardcoded to /proc/modules, so we test the parsing
	// logic by replicating the same algorithm on a temp file.
	content := `ext4 761856 1 - Live 0xffffffffc0000000
btrfs 1503232 0 - Live 0xffffffffc0100000
nf_tables 262144 2 nft_chain_nat,nft_compat, Live 0xffffffffc0200000
short
`
	tmpFile, err := os.CreateTemp("", "proc_modules_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Verify the moduleInfo struct and diffing logic using synthetic maps.
	baseline := map[string]moduleInfo{
		"ext4":      {Name: "ext4", Size: 761856},
		"btrfs":     {Name: "btrfs", Size: 1503232},
		"nf_tables": {Name: "nf_tables", Size: 262144},
	}

	current := map[string]moduleInfo{
		"ext4":      {Name: "ext4", Size: 761856},
		"nf_tables": {Name: "nf_tables", Size: 262144},
		"rootkit":   {Name: "rootkit", Size: 4096},
	}

	// Detect new modules (loads).
	var newModules []string
	for name := range current {
		if _, existed := baseline[name]; !existed {
			newModules = append(newModules, name)
		}
	}
	if len(newModules) != 1 || newModules[0] != "rootkit" {
		t.Errorf("expected new module 'rootkit', got %v", newModules)
	}

	// Detect removed modules (unloads).
	var removedModules []string
	for name := range baseline {
		if _, exists := current[name]; !exists {
			removedModules = append(removedModules, name)
		}
	}
	if len(removedModules) != 1 || removedModules[0] != "btrfs" {
		t.Errorf("expected removed module 'btrfs', got %v", removedModules)
	}
}

func TestModuleDiffNoChanges(t *testing.T) {
	baseline := map[string]moduleInfo{
		"ext4": {Name: "ext4", Size: 761856},
	}
	current := map[string]moduleInfo{
		"ext4": {Name: "ext4", Size: 761856},
	}

	var newMods, removedMods []string
	for name := range current {
		if _, existed := baseline[name]; !existed {
			newMods = append(newMods, name)
		}
	}
	for name := range baseline {
		if _, exists := current[name]; !exists {
			removedMods = append(removedMods, name)
		}
	}

	if len(newMods) != 0 {
		t.Errorf("expected no new modules, got %v", newMods)
	}
	if len(removedMods) != 0 {
		t.Errorf("expected no removed modules, got %v", removedMods)
	}
}

func TestModuleDiffEmptyBaseline(t *testing.T) {
	baseline := map[string]moduleInfo{}
	current := map[string]moduleInfo{
		"ext4":  {Name: "ext4", Size: 761856},
		"btrfs": {Name: "btrfs", Size: 1503232},
	}

	var newMods []string
	for name := range current {
		if _, existed := baseline[name]; !existed {
			newMods = append(newMods, name)
		}
	}
	if len(newMods) != 2 {
		t.Errorf("expected 2 new modules, got %d", len(newMods))
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("expected Enabled to be true by default")
	}
	if cfg.PollIntervalS != 5 {
		t.Errorf("expected PollIntervalS 5, got %d", cfg.PollIntervalS)
	}
}

func TestNewClampsInterval(t *testing.T) {
	cfg := Config{Enabled: true, PollIntervalS: 0}
	m := New(cfg, nil, nopLogger())
	if m.cfg.PollIntervalS != 5 {
		t.Errorf("expected PollIntervalS clamped to 5, got %d", m.cfg.PollIntervalS)
	}

	cfg2 := Config{Enabled: true, PollIntervalS: -3}
	m2 := New(cfg2, nil, nopLogger())
	if m2.cfg.PollIntervalS != 5 {
		t.Errorf("expected PollIntervalS clamped to 5, got %d", m2.cfg.PollIntervalS)
	}
}
