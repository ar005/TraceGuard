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
	files := []string{
		"maps", "smaps", "smaps_rollup", "status", "cmdline",
		"environ", "io", "wchan", "syscall", "stack",
	}

	for _, f := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		full := filepath.Join(base, f)
		_ = addFileToTar(tw, full, fmt.Sprintf("proc/%d/%s", pid, f))
	}

	// /proc/<pid>/fd — list symlinks only (don't open FDs).
	fdDir := filepath.Join(base, "fd")
	if fds, err := os.ReadDir(fdDir); err == nil {
		var sb strings.Builder
		for _, e := range fds {
			link, _ := os.Readlink(filepath.Join(fdDir, e.Name()))
			fmt.Fprintf(&sb, "%s -> %s\n", e.Name(), link)
		}
		addBytesToTar(tw, fmt.Sprintf("proc/%d/fd_listing.txt", pid), []byte(sb.String()))
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
