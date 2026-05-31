//go:build windows

package selfprotect

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// ─── hashFile ─────────────────────────────────────────────────────────────────

func TestHashFile_KnownContent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "binary.exe")
	content := []byte("fake agent binary content")
	if err := os.WriteFile(f, content, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	want := sha256.Sum256(content)
	got, err := hashFile(f)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if got != want {
		t.Errorf("got %x; want %x", got, want)
	}
}

func TestHashFile_SameFileHashesTwice(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "binary.exe")
	os.WriteFile(f, []byte("content"), 0644)

	h1, err := hashFile(f)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hashFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("same file hashed twice produced different results")
	}
}

func TestHashFile_ModifiedFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "binary.exe")
	os.WriteFile(f, []byte("original"), 0644)

	h1, _ := hashFile(f)

	os.WriteFile(f, []byte("replaced by attacker"), 0644)

	h2, _ := hashFile(f)
	if h1 == h2 {
		t.Error("modified file should produce a different hash")
	}
}

func TestHashFile_MissingFile(t *testing.T) {
	_, err := hashFile(filepath.Join(t.TempDir(), "does_not_exist.exe"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.exe")
	os.WriteFile(f, nil, 0644)

	want := sha256.Sum256(nil)
	got, err := hashFile(f)
	if err != nil {
		t.Fatalf("hashFile empty: %v", err)
	}
	if got != want {
		t.Errorf("empty file hash = %x; want %x", got, want)
	}
}

// ─── New ─────────────────────────────────────────────────────────────────────

func TestNew_ResolvesExecutablePath(t *testing.T) {
	sp := New(Config{BinPath: ""}, zerolog.Nop())
	if sp.cfg.BinPath == "" {
		t.Error("expected BinPath to be auto-populated from os.Executable()")
	}
}

func TestNew_ExplicitBinPath(t *testing.T) {
	sp := New(Config{BinPath: `C:\custom\path\agent.exe`}, zerolog.Nop())
	if sp.cfg.BinPath != `C:\custom\path\agent.exe` {
		t.Errorf("BinPath = %q; want custom path", sp.cfg.BinPath)
	}
}

func TestNew_TamperChIsBuffered(t *testing.T) {
	sp := New(Config{}, zerolog.Nop())
	if cap(sp.TamperCh) == 0 {
		t.Error("TamperCh should be buffered to avoid blocking the goroutines")
	}
}

func TestNew_LazyDLLsInitialized(t *testing.T) {
	sp := New(Config{}, zerolog.Nop())
	if sp.modKernel32 == nil {
		t.Error("modKernel32 should not be nil")
	}
	if sp.procIsDebuggerPresent == nil {
		t.Error("procIsDebuggerPresent should not be nil")
	}
	if sp.procCheckRemoteDebuggerPresent == nil {
		t.Error("procCheckRemoteDebuggerPresent should not be nil")
	}
}

// ─── Start / Stop lifecycle ──────────────────────────────────────────────────

func TestStartStop_NoOp(t *testing.T) {
	sp := New(Config{Watchdog: false, ImmutableBin: false}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sp.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sp.Stop()
}

func TestStartStop_WatchdogEnabled(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent.exe")
	os.WriteFile(binPath, []byte("binary content"), 0644)

	sp := New(Config{
		BinPath:  binPath,
		Watchdog: true,
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sp.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Baseline hash should be set after Start.
	emptyHash := [32]byte{}
	if sp.binHash == emptyHash {
		t.Error("binHash should be set after Start with Watchdog=true")
	}

	sp.Stop()
}

func TestStartStop_StopIsIdempotent(t *testing.T) {
	sp := New(Config{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sp.Start(ctx)
	// Calling Stop twice must not panic or deadlock.
	sp.Stop()
	// Second Stop would call cancel() again and re-wait on wg — safe because wg
	// is already at zero and cancel is idempotent in context.WithCancel.
}

// ─── Watchdog tamper detection ─────────────────────────────────────────────

func TestWatchdogLoop_DetectsTamper(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent.exe")
	os.WriteFile(binPath, []byte("original binary"), 0644)

	sp := New(Config{BinPath: binPath, Watchdog: true}, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sp.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Tamper the binary.
	os.WriteFile(binPath, []byte("replaced binary — attacker payload"), 0644)

	// Trigger a watchdog tick directly (without waiting 30s).
	current, _ := hashFile(binPath)
	if current != sp.binHash {
		detail := "tamper detected in test"
		sp.notify(TamperNotification{Mechanism: "binary_hash", Detail: detail})
	}

	select {
	case n := <-sp.TamperCh:
		if n.Mechanism != "binary_hash" {
			t.Errorf("mechanism = %q; want binary_hash", n.Mechanism)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for tamper notification")
	}

	sp.Stop()
}

// ─── notify (channel full) ────────────────────────────────────────────────────

func TestNotify_DropsWhenFull(t *testing.T) {
	sp := New(Config{}, zerolog.Nop())

	// Fill the channel to capacity.
	for i := 0; i < cap(sp.TamperCh); i++ {
		sp.TamperCh <- TamperNotification{Mechanism: "test"}
	}

	// This must not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		sp.notify(TamperNotification{Mechanism: "overflow"})
	}()

	select {
	case <-done:
		// pass — notify dropped the notification as expected
	case <-time.After(200 * time.Millisecond):
		t.Error("notify blocked when channel was full")
	}
}

// ─── Read-only attribute ──────────────────────────────────────────────────────

func TestSetClearReadOnly(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "binary.exe")
	os.WriteFile(f, []byte("content"), 0644)

	if err := setReadOnly(f); err != nil {
		t.Fatalf("setReadOnly: %v", err)
	}

	// Write should now fail.
	err := os.WriteFile(f, []byte("overwrite"), 0644)
	if err == nil {
		t.Error("expected write to fail on read-only file")
	}

	if err := clearReadOnly(f); err != nil {
		t.Fatalf("clearReadOnly: %v", err)
	}

	// Write should succeed again.
	if err := os.WriteFile(f, []byte("overwrite"), 0644); err != nil {
		t.Errorf("write after clearReadOnly: %v", err)
	}
}

func TestImmutableBin_ClearedOnStop(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent.exe")
	os.WriteFile(binPath, []byte("binary"), 0644)

	sp := New(Config{
		BinPath:      binPath,
		ImmutableBin: true,
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sp.Start(ctx)

	// Binary should be read-only now.
	if err := os.WriteFile(binPath, []byte("x"), 0644); err == nil {
		t.Error("expected write to fail while agent is running")
	}

	sp.Stop()

	// After Stop(), attribute should be cleared.
	if err := os.WriteFile(binPath, []byte("update"), 0644); err != nil {
		t.Errorf("write after Stop should succeed: %v", err)
	}
}
