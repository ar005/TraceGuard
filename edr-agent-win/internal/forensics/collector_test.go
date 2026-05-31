//go:build windows

package forensics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── checkForensicsPath ───────────────────────────────────────────────────────

func TestCheckForensicsPath_Blocked(t *testing.T) {
	blocked := []string{
		`C:\Windows\System32\config\SAM`,
		`C:\Windows\System32\config\sam`,   // case-insensitive
		`C:\Windows\System32\config\SAM\subkey`,
		`C:\Windows\System32\config\Security`,
		`C:\Windows\System32\config\Software`,
		`C:\Windows\NTDS\ntds.dit`,
		`C:\Windows\ntds\NTDS.DIT`,
	}
	for _, p := range blocked {
		t.Run(p, func(t *testing.T) {
			if err := checkForensicsPath(p); err == nil {
				t.Errorf("checkForensicsPath(%q) = nil; want error", p)
			}
		})
	}
}

func TestCheckForensicsPath_Allowed(t *testing.T) {
	allowed := []string{
		`C:\Users\victim\Desktop\evil.exe`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Temp\malware.ps1`,
		`C:\ProgramData\TraceGuard\agent.id`,
	}
	for _, p := range allowed {
		t.Run(p, func(t *testing.T) {
			if err := checkForensicsPath(p); err != nil {
				t.Errorf("checkForensicsPath(%q) = %v; want nil", p, err)
			}
		})
	}
}

// ─── Collect — dispatch ───────────────────────────────────────────────────────

func TestCollect_UnknownJobType(t *testing.T) {
	_, err := Collect(context.Background(), "bogus_type", nil)
	if err == nil {
		t.Error("expected error for unknown job type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown job type") {
		t.Errorf("error %q doesn't mention 'unknown job type'", err)
	}
}

func TestCollect_ProcessMemory_InvalidPID(t *testing.T) {
	tests := []struct {
		name   string
		params string
	}{
		{"zero pid", `{"pid":0}`},
		{"pid 1", `{"pid":1}`},
		{"pid 4 (System)", `{"pid":4}`},
		{"no pid field", `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Collect(context.Background(), "process_memory", json.RawMessage(tt.params))
			if err == nil {
				t.Errorf("expected error for params %s, got nil", tt.params)
			}
		})
	}
}

func TestCollect_File_MissingPath(t *testing.T) {
	_, err := Collect(context.Background(), "file", json.RawMessage(`{}`))
	if err == nil {
		t.Error("expected error for file job with no path, got nil")
	}
}

func TestCollect_File_BlockedPath(t *testing.T) {
	params := json.RawMessage(`{"path":"C:\\Windows\\System32\\config\\SAM"}`)
	_, err := Collect(context.Background(), "file", params)
	if err == nil {
		t.Error("expected error for blocked path, got nil")
	}
}

func TestCollect_File_RealFile(t *testing.T) {
	// Write a temp file with known content.
	dir := t.TempDir()
	target := filepath.Join(dir, "test_artifact.txt")
	content := []byte("forensics test payload 12345")
	if err := os.WriteFile(target, content, 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	params := json.RawMessage(`{"path":"` + jsonEscapePath(target) + `"}`)
	bundle, err := Collect(context.Background(), "file", params)
	if err != nil {
		t.Fatalf("Collect(file): %v", err)
	}
	if len(bundle) == 0 {
		t.Fatal("got empty bundle")
	}

	entries := extractTarEntries(t, bundle)

	// Must contain the file under "files/".
	fileKey := "files/" + filepath.Base(target)
	data, ok := entries[fileKey]
	if !ok {
		t.Fatalf("bundle missing %q; got keys: %v", fileKey, mapKeys(entries))
	}
	if !bytes.Equal(data, content) {
		t.Errorf("file content = %q; want %q", data, content)
	}

	// Must contain metadata.json.
	meta, ok := entries["metadata.json"]
	if !ok {
		t.Fatal("bundle missing metadata.json")
	}
	var m map[string]string
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatalf("parse metadata.json: %v", err)
	}
	if m["job_type"] != "file" {
		t.Errorf("metadata job_type = %q; want file", m["job_type"])
	}
	if m["platform"] != "windows" {
		t.Errorf("metadata platform = %q; want windows", m["platform"])
	}
	if m["collected_at"] == "" {
		t.Error("metadata collected_at is empty")
	}
	if m["hostname"] == "" {
		t.Error("metadata hostname is empty")
	}
}

func TestCollect_File_NonExistent(t *testing.T) {
	params := json.RawMessage(`{"path":"C:\\does\\not\\exist\\file.exe"}`)
	_, err := Collect(context.Background(), "file", params)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestCollect_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := Collect(ctx, "artifacts", nil)
	// Artifacts checks ctx.Err() per-command, so it may succeed with partial data
	// or return ctx error. Either is acceptable — the key is it must not panic or hang.
	_ = err
}

// ─── addBytesToTar / addFileDataToTar helpers ─────────────────────────────────

func TestAddBytesToTar(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	addBytesToTar(tw, "test/entry.txt", []byte("hello world"))

	tw.Close()
	gz.Close()

	entries := extractTarEntries(t, buf.Bytes())
	data, ok := entries["test/entry.txt"]
	if !ok {
		t.Fatal("entry not found in tar")
	}
	if string(data) != "hello world" {
		t.Errorf("got %q; want %q", data, "hello world")
	}
}

func TestAddFileDataToTar(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	payload := []byte("minidump payload")
	if err := addFileDataToTar(tw, "minidump/pid_1234.dmp", payload); err != nil {
		t.Fatalf("addFileDataToTar: %v", err)
	}

	tw.Close()
	gz.Close()

	entries := extractTarEntries(t, buf.Bytes())
	data, ok := entries["minidump/pid_1234.dmp"]
	if !ok {
		t.Fatal("entry not found in tar")
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("got %q; want %q", data, payload)
	}
}

func TestAddFileToTar_SizeLimit(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")

	// Write a file exactly at the limit.
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 4096)
	written := 0
	for written < maxFileSize {
		n := maxFileSize - written
		if n > len(chunk) {
			n = len(chunk)
		}
		f.Write(chunk[:n])
		written += n
	}
	// Write 1MB more past the limit.
	for i := 0; i < 256; i++ {
		f.Write(chunk)
	}
	f.Close()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := addFileToTar(tw, big, "big.bin"); err != nil {
		t.Fatalf("addFileToTar: %v", err)
	}
	tw.Close()
	gz.Close()

	entries := extractTarEntries(t, buf.Bytes())
	data, ok := entries["big.bin"]
	if !ok {
		t.Fatal("big.bin not in tar")
	}
	if len(data) > maxFileSize {
		t.Errorf("tar entry size %d exceeds maxFileSize %d", len(data), maxFileSize)
	}
}

// ─── Metadata ─────────────────────────────────────────────────────────────────

func TestCollect_MetadataFields(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sample.txt")
	os.WriteFile(target, []byte("x"), 0644)

	params := json.RawMessage(`{"path":"` + jsonEscapePath(target) + `"}`)
	bundle, err := Collect(context.Background(), "file", params)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	entries := extractTarEntries(t, bundle)
	meta, ok := entries["metadata.json"]
	if !ok {
		t.Fatal("missing metadata.json")
	}
	var m map[string]string
	json.Unmarshal(meta, &m)

	required := []string{"collected_at", "job_type", "hostname", "platform"}
	for _, k := range required {
		if m[k] == "" {
			t.Errorf("metadata.json missing or empty field %q", k)
		}
	}
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

// extractTarEntries reads a gzipped tar and returns filename → content map.
func extractTarEntries(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	out := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %q: %v", hdr.Name, err)
		}
		out[hdr.Name] = body
	}
	return out
}

func mapKeys(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// jsonEscapePath escapes backslashes for use inside a JSON string.
func jsonEscapePath(p string) string {
	return strings.ReplaceAll(p, `\`, `\\`)
}
