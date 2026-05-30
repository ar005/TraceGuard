// internal/forensics/collector.go
// Windows forensic artifact collector — returns a tar.gz bundle on demand.
//
// Job types:
//   artifacts      – registry, event log, netstat, tasklist, prefetch listing
//   process_memory – MiniDumpWriteDump via dbghelp.dll (requires SeDebugPrivilege)
//   file           – single file by path
//   full           – artifacts + minidump for every running process

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
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Params holds job-specific parameters parsed from JSON.
type Params struct {
	PID  int    `json:"pid"`
	Path string `json:"path"`
}

// forensicsBlocklist contains exact lowercase paths the file collector must never read.
// lsass is intentionally absent — OS-level access denial handles it for process_memory.
var forensicsBlocklist = []string{
	`c:\windows\system32\config\sam`,
	`c:\windows\system32\config\security`,
	`c:\windows\system32\config\software`,
	`c:\windows\ntds\ntds.dit`,
}

func checkForensicsPath(p string) error {
	clean := strings.ToLower(filepath.Clean(p))
	for _, blocked := range forensicsBlocklist {
		if clean == blocked || strings.HasPrefix(clean, blocked+string(filepath.Separator)) {
			return fmt.Errorf("path %q is not permitted for forensic collection", p)
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
			if err := collectAllProcessMemory(ctx, tw); err != nil {
				// non-fatal — partial bundle is still useful
				_ = err
			}
		}
	case "process_memory":
		if params.PID <= 4 { // 0=Idle, 4=System — never dump these
			return nil, fmt.Errorf("process_memory requires pid > 4")
		}
		if err := collectProcessMemory(ctx, tw, params.PID); err != nil {
			return nil, fmt.Errorf("process memory pid %d: %w", params.PID, err)
		}
	case "file":
		if params.Path == "" {
			return nil, fmt.Errorf("file requires path in params")
		}
		if err := checkForensicsPath(params.Path); err != nil {
			return nil, err
		}
		clean := filepath.Clean(params.Path)
		if err := addFileToTar(tw, clean, "files/"+filepath.Base(clean)); err != nil {
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
		"platform":     "windows",
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	addBytesToTar(tw, "metadata.json", metaBytes)

	tw.Close()
	gz.Close()
	return buf.Bytes(), nil
}

// ─── Artifact collection ──────────────────────────────────────────────────────

func collectArtifacts(ctx context.Context, tw *tar.Writer) error {
	type cmd struct {
		name string
		args []string
		dest string
	}
	commands := []cmd{
		{"tasklist", []string{"/v", "/fo", "csv"}, "artifacts/tasklist.csv"},
		{"netstat", []string{"-ano"}, "artifacts/netstat.txt"},
		{"schtasks", []string{"/query", "/fo", "csv", "/v"}, "artifacts/schtasks.csv"},
		{"sc", []string{"query", "type=", "all", "state=", "all"}, "artifacts/services.txt"},
		{"driverquery", []string{"/fo", "csv", "/v"}, "artifacts/drivers.csv"},
		{"arp", []string{"-a"}, "artifacts/arp.txt"},
		{"ipconfig", []string{"/displaydns"}, "artifacts/dns_cache.txt"},
		{"quser", []string{}, "artifacts/logged_on_users.txt"},
		{"whoami", []string{"/all"}, "artifacts/whoami_all.txt"},
	}
	for _, c := range commands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		addBytesToTar(tw, c.dest, runCommand(ctx, c.name, c.args...))
	}

	// Registry autorun keys.
	for _, entry := range []struct{ key, dest string }{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "artifacts/reg_run_hklm.txt"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "artifacts/reg_runonce_hklm.txt"},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "artifacts/reg_run_hkcu.txt"},
	} {
		addBytesToTar(tw, entry.dest,
			runCommand(ctx, "reg", "query", entry.key, "/s"))
	}

	// Hive exports — reg export requires a real file path, not NUL.
	for _, hive := range []struct{ key, dest string }{
		{`HKLM\SYSTEM\CurrentControlSet\Services`, "artifacts/hive_services.reg"},
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "artifacts/hive_ifeo.reg"},
	} {
		tmp, err := os.CreateTemp("", "tg_hive_*.reg")
		if err != nil {
			continue
		}
		tmpPath := tmp.Name()
		tmp.Close()
		runCommand(ctx, "reg", "export", hive.key, tmpPath, "/y")
		if data, err := os.ReadFile(tmpPath); err == nil {
			addBytesToTar(tw, hive.dest, data)
		}
		os.Remove(tmpPath)
	}

	// Windows Event Log — last 1000 events as text.
	for _, ch := range []string{"Security", "System", "Application"} {
		addBytesToTar(tw,
			"artifacts/evtx_"+strings.ToLower(ch)+".txt",
			runCommand(ctx, "wevtutil", "qe", ch, "/c:1000", "/rd:true", "/f:text"))
	}

	// Prefetch listing (directory listing only — binary files need SYSTEM).
	addBytesToTar(tw, "artifacts/prefetch_list.txt",
		runCommand(ctx, "cmd", "/c", `dir /tc /o:d "C:\Windows\Prefetch" 2>nul`))

	// Static files copied directly.
	for _, f := range []struct{ src, dest string }{
		{`C:\Windows\System32\drivers\etc\hosts`, "artifacts/hosts.txt"},
		{`C:\Windows\System32\drivers\etc\networks`, "artifacts/networks.txt"},
	} {
		_ = addFileToTar(tw, f.src, f.dest)
	}

	return nil
}

// ─── Process memory (MiniDump via dbghelp.dll) ───────────────────────────────

var (
	modDbghelp            = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump = modDbghelp.NewProc("MiniDumpWriteDump")
)

const miniDumpWithFullMemory uintptr = 0x00000002

func collectProcessMemory(ctx context.Context, tw *tar.Writer, pid int) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	// Write to a temp file — MiniDumpWriteDump requires a Win32 HANDLE, not an io.Writer.
	tmp, err := os.CreateTemp("", fmt.Sprintf("tg_dump_%d_*.dmp", pid))
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	// MiniDumpWriteDump(hProcess, processId, hFile, dumpType, ExceptionParam, UserStreamParam, CallbackParam)
	r1, _, e1 := procMiniDumpWriteDump.Call(
		uintptr(handle),
		uintptr(pid),
		uintptr(syscall.Handle(tmp.Fd())), // CRT fd → Win32 HANDLE
		miniDumpWithFullMemory,
		0, 0, 0,
	)
	tmp.Close()

	if r1 == 0 {
		return fmt.Errorf("MiniDumpWriteDump failed for pid %d: %w", pid, e1)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("read minidump pid %d: %w", pid, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("minidump empty for pid %d", pid)
	}

	return addFileDataToTar(tw, fmt.Sprintf("minidump/pid_%d.dmp", pid), data)
}

func collectAllProcessMemory(ctx context.Context, tw *tar.Writer) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snapshot, &pe); err != nil {
		return err
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid := int(pe.ProcessID)
		if pid > 4 { // skip Idle (0) and System (4)
			_ = collectProcessMemory(ctx, tw, pid) // per-process errors are non-fatal
		}
		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break // ERROR_NO_MORE_FILES is normal loop termination
		}
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

func addFileDataToTar(tw *tar.Writer, archivePath string, data []byte) error {
	hdr := &tar.Header{
		Name:    archivePath,
		Size:    int64(len(data)),
		Mode:    0600,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func runCommand(ctx context.Context, name string, args ...string) []byte {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()
	return out
}

func localHostname() string {
	h, _ := os.Hostname()
	return h
}
