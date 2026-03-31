package configver

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestGetInitial(t *testing.T) {
	// The package-level version starts at 1 but may have been mutated by
	// prior tests in the same process. Reset it for a deterministic check.
	atomic.StoreInt64(&version, 1)

	got := Get()
	if got != "1" {
		t.Errorf("Get() = %q, want %q", got, "1")
	}
}

func TestBumpIncrementsAndReturns(t *testing.T) {
	atomic.StoreInt64(&version, 1)

	got := Bump()
	if got != "2" {
		t.Errorf("Bump() = %q, want %q", got, "2")
	}
	if g := Get(); g != "2" {
		t.Errorf("Get() after Bump = %q, want %q", g, "2")
	}
}

func TestMultipleBumps(t *testing.T) {
	atomic.StoreInt64(&version, 1)

	for i := 2; i <= 10; i++ {
		got := Bump()
		want := strconv.Itoa(i)
		if got != want {
			t.Fatalf("Bump() #%d = %q, want %q", i-1, got, want)
		}
	}
	if g := Get(); g != "10" {
		t.Errorf("Get() after 9 bumps = %q, want %q", g, "10")
	}
}

func TestConcurrentBumps(t *testing.T) {
	atomic.StoreInt64(&version, 0)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			Bump()
		}()
	}
	wg.Wait()

	got := Get()
	want := strconv.Itoa(goroutines)
	if got != want {
		t.Errorf("Get() after %d concurrent Bump() calls = %q, want %q", goroutines, got, want)
	}
}
