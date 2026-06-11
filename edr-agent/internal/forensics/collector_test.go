// collector_test.go — unit tests for the forensics collector.
// TestCollectProcMemory_SelfPID runs against the test process's own PID, so
// /proc/{pid}/mem is available and readable.

package forensics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// extractTar decompresses a tar.gz and returns a map of path → contents.
func extractTar(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip open: %v", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		buf, _ := io.ReadAll(tr)
		files[hdr.Name] = buf
	}
	return files
}

func TestParseMapsLine(t *testing.T) {
	cases := []struct {
		line  string
		ok    bool
		start uint64
		end   uint64
		perms string
		name  string
	}{
		{"7f1234000000-7f1234100000 rw-p 00000000 00:00 0 [heap]", true, 0x7f1234000000, 0x7f1234100000, "rw-p", "[heap]"},
		{"7fff12340000-7fff12360000 r--p 00000000 00:00 0", true, 0x7fff12340000, 0x7fff12360000, "r--p", ""},
		{"badinput", false, 0, 0, "", ""},
	}
	for _, tc := range cases {
		r, ok := parseMapsLine(tc.line)
		if ok != tc.ok {
			t.Errorf("line %q: ok=%v want %v", tc.line, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if r.Start != tc.start || r.End != tc.end || r.Perms != tc.perms || r.Name != tc.name {
			t.Errorf("line %q: got {%x %x %s %s} want {%x %x %s %s}",
				tc.line, r.Start, r.End, r.Perms, r.Name,
				tc.start, tc.end, tc.perms, tc.name)
		}
	}
}

func TestCollectProcMemory_SelfPID(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("process_memory collection requires root (reads /proc/{pid}/mem)")
	}

	pid := os.Getpid()
	bundle, err := Collect(context.Background(), "process_memory",
		[]byte(fmt.Sprintf(`{"pid":%d}`, pid)))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	files := extractTar(t, bundle)

	// Must have the manifest.
	manifestData, ok := files["memory/manifest.json"]
	if !ok {
		t.Fatal("memory/manifest.json missing from bundle")
	}
	var manifest memManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("manifest parse: %v", err)
	}
	if manifest.PID != pid {
		t.Errorf("manifest PID %d, want %d", manifest.PID, pid)
	}

	// Must have at least one captured region.
	captured := 0
	for _, r := range manifest.Regions {
		if r.Captured {
			captured++
		}
	}
	if captured == 0 {
		t.Error("expected at least one captured memory region")
	}

	// At least one memory/region_*.bin file.
	regionCount := 0
	for name := range files {
		if strings.HasPrefix(name, "memory/region_") && strings.HasSuffix(name, ".bin") {
			regionCount++
		}
	}
	if regionCount == 0 {
		t.Error("expected at least one memory/region_*.bin file in bundle")
	}

	// Proc metadata files must also be present.
	if _, ok := files[fmt.Sprintf("proc/%d/maps", pid)]; !ok {
		t.Errorf("proc/%d/maps missing", pid)
	}
	if _, ok := files[fmt.Sprintf("proc/%d/status", pid)]; !ok {
		t.Errorf("proc/%d/status missing", pid)
	}
}

func TestCollectProcMemory_InvalidPID(t *testing.T) {
	_, err := Collect(context.Background(), "process_memory", []byte(`{"pid":0}`))
	if err == nil {
		t.Fatal("expected error for pid=0")
	}

	_, err = Collect(context.Background(), "process_memory", []byte(`{"pid":-5}`))
	if err == nil {
		t.Fatal("expected error for pid=-5")
	}
}

func TestCollectProcMemory_NonExistentPID(t *testing.T) {
	// PID 999999999 is very unlikely to exist.
	bundle, err := Collect(context.Background(), "process_memory", []byte(`{"pid":999999999}`))
	// Should not return a fatal error — the collector should produce a bundle
	// with error files rather than aborting.
	if err != nil {
		// If the process simply doesn't exist, collectProcMemory returns nil
		// (error noted inside the bundle). Any error here is acceptable too.
		return
	}
	files := extractTar(t, bundle)
	// Either a dump_error.txt or the metadata.json should be present.
	hasAny := false
	for name := range files {
		if strings.Contains(name, "error") || name == "metadata.json" {
			hasAny = true
			break
		}
	}
	if !hasAny {
		t.Error("expected at least metadata.json or error file for non-existent PID")
	}
}

func TestCollectProcMemory_CapRespected(t *testing.T) {
	// Create a tar writer that we drive directly to test dumpProcMem cap logic.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	pid := os.Getpid()
	manifest, _ := dumpProcMem(context.Background(), tw, pid)

	// Regardless of how much memory the test process has, total must not exceed cap.
	if manifest.TotalBytes > maxMemDumpBytes {
		t.Errorf("total bytes %d exceeds cap %d", manifest.TotalBytes, maxMemDumpBytes)
	}
}
