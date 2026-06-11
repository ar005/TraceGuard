// internal/forensics/collector.go
//
// Collects forensic artifacts on demand and returns them as an in-memory
// tar.gz archive.  Called by the agent's forensics poll loop when the backend
// returns a pending job.
//
// Collection types:
//   artifacts       – standard Linux forensic artifacts (logs, cron, tmp, proc)
//   process_memory  – /proc/<pid>/ filesystem snapshot (maps, status, etc.)
//   file            – single file download by path
//   full            – artifacts + /proc snapshot for every running PID

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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Params holds the job-specific parameters parsed from JSON.
type Params struct {
	PID  int    `json:"pid"`
	Path string `json:"path"`
}

// forensicsBlocklist are path prefixes that the file collector must never read.
var forensicsBlocklist = []string{
	"/etc/shadow", "/etc/gshadow", "/etc/master.passwd",
	"/root/", "/home/",
	"/.ssh/", "/.gnupg/",
	"/proc/", "/sys/",
}

// checkForensicsPath rejects sensitive paths and symlinks pointing to them.
func checkForensicsPath(p string) error {
	clean := filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		clean = resolved
	}
	lower := strings.ToLower(clean)
	for _, blocked := range forensicsBlocklist {
		if strings.HasPrefix(lower, strings.ToLower(blocked)) || lower == strings.TrimSuffix(strings.ToLower(blocked), "/") {
			return fmt.Errorf("path %q is not permitted for forensic collection", clean)
		}
	}
	return nil
}

// Collect creates a tar.gz archive for the given job type and params.
// Returns the compressed archive as a byte slice.
func Collect(ctx context.Context, jobType string, rawParams json.RawMessage) ([]byte, error) {
	var params Params
	if len(rawParams) > 0 {
		_ = json.Unmarshal(rawParams, &params)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	switch jobType {
	case "artifacts", "full":
		if err := collectArtifacts(ctx, tw); err != nil {
			return nil, fmt.Errorf("artifacts: %w", err)
		}
		if jobType == "full" {
			if err := collectAllProcMemory(ctx, tw); err != nil {
				return nil, fmt.Errorf("proc memory: %w", err)
			}
		}
	case "process_memory":
		if params.PID <= 1 {
			return nil, fmt.Errorf("process_memory requires pid > 1")
		}
		if err := collectProcMemory(ctx, tw, params.PID); err != nil {
			return nil, fmt.Errorf("proc memory pid %d: %w", params.PID, err)
		}
	case "file":
		if params.Path == "" {
			return nil, fmt.Errorf("file requires path in params")
		}
		if err := checkForensicsPath(params.Path); err != nil {
			return nil, err
		}
		clean := filepath.Clean(params.Path)
		if err := addFileToTar(tw, clean, "files"+clean); err != nil {
			return nil, fmt.Errorf("file %s: %w", clean, err)
		}
	default:
		return nil, fmt.Errorf("unknown job type: %s", jobType)
	}

	// Metadata summary file.
	meta := map[string]string{
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"job_type":     jobType,
		"hostname":     localHostname(),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	addBytesToTar(tw, "metadata.json", metaBytes)

	tw.Close()
	gz.Close()
	return buf.Bytes(), nil
}

// ─── Artifact collection ─────────────────────────────────────────────────────

var artifactPaths = []string{
	"/var/log/auth.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/kern.log",
	"/var/log/secure",
	"/var/log/cron",
	"/etc/crontab",
	"/etc/cron.d",
	"/var/spool/cron",
	"/etc/passwd",
	"/etc/group",
	"/etc/sudoers",
	"/root/.bash_history",
	"/root/.zsh_history",
	"/etc/ssh/sshd_config",
	"/root/.ssh/authorized_keys",
	"/root/.ssh/known_hosts",
	"/tmp",
	"/var/tmp",
	"/dev/shm",
}

func collectArtifacts(ctx context.Context, tw *tar.Writer) error {
	// Running processes snapshot.
	addBytesToTar(tw, "artifacts/ps_aux.txt", runCommand(ctx, "ps", "aux"))
	addBytesToTar(tw, "artifacts/network_connections.txt", runCommand(ctx, "ss", "-tunap"))
	addBytesToTar(tw, "artifacts/lsmod.txt", runCommand(ctx, "lsmod"))
	addBytesToTar(tw, "artifacts/lsof.txt", runCommand(ctx, "lsof", "-n"))
	addBytesToTar(tw, "artifacts/crontab_root.txt", runCommand(ctx, "crontab", "-l"))
	addBytesToTar(tw, "artifacts/who.txt", runCommand(ctx, "who"))
	addBytesToTar(tw, "artifacts/last.txt", runCommand(ctx, "last", "-n", "100"))

	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp"} {
		if data, err := os.ReadFile(f); err == nil {
			addBytesToTar(tw, "artifacts/"+filepath.Base(f)+".txt", data)
		}
	}

	for _, p := range artifactPaths {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			count := 0
			_ = filepath.WalkDir(p, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil || count > 5000 {
					return nil
				}
				if d.IsDir() {
					return nil
				}
				_ = addFileToTar(tw, path, "artifacts"+path)
				count++
				return nil
			})
		} else {
			_ = addFileToTar(tw, p, "artifacts"+p)
		}
	}

	// Per-user shell histories under /home.
	entries, _ := os.ReadDir("/home")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, hist := range []string{".bash_history", ".zsh_history"} {
			p := filepath.Join("/home", e.Name(), hist)
			_ = addFileToTar(tw, p, "artifacts"+p)
		}
	}
	return nil
}

// ─── Process memory (proc filesystem) ───────────────────────────────────────

func collectProcMemory(ctx context.Context, tw *tar.Writer, pid int) error {
	base := fmt.Sprintf("/proc/%d", pid)

	// Metadata pseudo-files from /proc/{pid}/
	for _, f := range []string{"maps", "smaps", "smaps_rollup", "status", "cmdline", "environ", "io", "wchan", "syscall", "stack"} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = addFileToTar(tw, filepath.Join(base, f), fmt.Sprintf("proc/%d/%s", pid, f))
	}

	// FD listing — symlink targets only, no file opens.
	fdDir := filepath.Join(base, "fd")
	if fds, err := os.ReadDir(fdDir); err == nil {
		var sb strings.Builder
		for _, e := range fds {
			link, _ := os.Readlink(filepath.Join(fdDir, e.Name()))
			fmt.Fprintf(&sb, "%s -> %s\n", e.Name(), link)
		}
		addBytesToTar(tw, fmt.Sprintf("proc/%d/fd_listing.txt", pid), []byte(sb.String()))
	}

	// Binary memory dump via /proc/{pid}/mem.
	manifest, dumpErr := dumpProcMem(ctx, tw, pid)
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	addBytesToTar(tw, "memory/manifest.json", manifestBytes)

	if dumpErr != nil {
		addBytesToTar(tw, "memory/dump_error.txt", []byte(dumpErr.Error()))
	}
	return nil
}

func collectAllProcMemory(ctx context.Context, tw *tar.Writer) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		_ = collectProcMemory(ctx, tw, pid)
	}
	return nil
}

// ─── Memory dump types and helpers ───────────────────────────────────────────

// memRegion describes a single virtual memory region from /proc/{pid}/maps.
type memRegion struct {
	Start    uint64 `json:"start"`
	End      uint64 `json:"end"`
	Perms    string `json:"perms"`
	Name     string `json:"name"`
	Captured bool   `json:"captured"`
	ErrMsg   string `json:"error,omitempty"`
}

// memManifest is written as memory/manifest.json inside every process_memory bundle.
type memManifest struct {
	PID        int         `json:"pid"`
	Cmdline    string      `json:"cmdline"`
	CapturedAt time.Time   `json:"captured_at"`
	TotalBytes int64       `json:"total_bytes"`
	Capped     bool        `json:"capped"`
	Regions    []memRegion `json:"regions"`
}

const maxMemDumpBytes = 256 * 1024 * 1024 // 256 MB total cap across all regions

// dumpProcMem reads actual memory contents from /proc/{pid}/mem guided by
// /proc/{pid}/maps and writes each captured region as
// memory/region_{start}-{end}.bin inside tw.
// The agent runs as root (required for eBPF), so /proc/{pid}/mem is
// readable without ptrace on Linux 3.2+.
func dumpProcMem(ctx context.Context, tw *tar.Writer, pid int) (memManifest, error) {
	manifest := memManifest{PID: pid, CapturedAt: time.Now().UTC()}

	if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		manifest.Cmdline = strings.ReplaceAll(string(raw), "\x00", " ")
	}

	mapsData, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return manifest, fmt.Errorf("read maps: %w", err)
	}
	var regions []memRegion
	for _, line := range strings.Split(strings.TrimSpace(string(mapsData)), "\n") {
		if r, ok := parseMapsLine(line); ok {
			regions = append(regions, r)
		}
	}

	memFile, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return manifest, fmt.Errorf("open mem: %w", err)
	}
	defer memFile.Close()

	var totalBytes int64
	for i := range regions {
		if ctx.Err() != nil {
			break
		}
		r := &regions[i]

		if len(r.Perms) == 0 || r.Perms[0] != 'r' {
			continue
		}
		if r.Name == "[vvar]" || r.Name == "[vsyscall]" {
			continue
		}

		size := int64(r.End - r.Start)
		if size <= 0 || size > 128*1024*1024 {
			r.ErrMsg = "skipped: single region exceeds 128 MB"
			continue
		}
		if totalBytes+size > maxMemDumpBytes {
			r.ErrMsg = "skipped: total cap reached"
			manifest.Capped = true
			continue
		}

		buf := make([]byte, size)
		n, readErr := memFile.ReadAt(buf, int64(r.Start))
		if n == 0 {
			r.ErrMsg = fmt.Sprintf("read error: %v", readErr)
			continue
		}
		addBytesToTar(tw, fmt.Sprintf("memory/region_%016x-%016x.bin", r.Start, r.End), buf[:n])
		r.Captured = true
		totalBytes += int64(n)
	}

	manifest.Regions = regions
	manifest.TotalBytes = totalBytes
	return manifest, nil
}

// parseMapsLine parses one line from /proc/{pid}/maps.
// Format: start-end perms offset dev inode [name]
func parseMapsLine(line string) (memRegion, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return memRegion{}, false
	}
	parts := strings.SplitN(fields[0], "-", 2)
	if len(parts) != 2 {
		return memRegion{}, false
	}
	start, err1 := strconv.ParseUint(parts[0], 16, 64)
	end, err2 := strconv.ParseUint(parts[1], 16, 64)
	if err1 != nil || err2 != nil {
		return memRegion{}, false
	}
	name := ""
	if len(fields) >= 6 {
		name = fields[5]
	}
	return memRegion{Start: start, End: end, Perms: fields[1], Name: name}, true
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const maxFileSize = 50 * 1024 * 1024 // 50 MB per file

func addFileToTar(tw *tar.Writer, src, archivePath string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	sz := info.Size()
	if sz > maxFileSize {
		sz = maxFileSize
	}
	hdr := &tar.Header{
		Name:    archivePath,
		Size:    sz,
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, io.LimitReader(f, maxFileSize))
	return err
}

func addBytesToTar(tw *tar.Writer, archivePath string, data []byte) {
	hdr := &tar.Header{
		Name:    archivePath,
		Size:    int64(len(data)),
		Mode:    0600,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return
	}
	_, _ = tw.Write(data)
}

func runCommand(ctx context.Context, name string, args ...string) []byte {
	cmd := exec.CommandContext(ctx, name, args...)
	out, _ := cmd.Output()
	return out
}

func localHostname() string {
	h, _ := os.Hostname()
	return h
}
