// parse.go — pure-Go helpers for the process monitor. No OS-specific imports.
// Split out so tests can run on Linux CI without the Windows build tag.
package process

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// parseProcessEventData extracts PID, PPID, and short image name from the
// UserData of Microsoft-Windows-Kernel-Process Event 1 (ProcessStart) or
// Event 2 (ProcessStop).
//
// Layout (version 0/2, Windows 10+):
//
//	Offset  Size  Field
//	0       4     ProcessId       (uint32 LE)
//	4       4     ParentProcessId (uint32 LE)
//	8       ?     ImageFileName   (null-terminated UTF-16LE short name)
//	...     ...   [SessionId, Flags, SID fields — variable length, not parsed]
func parseProcessEventData(data []byte) (pid, ppid uint32, imageName string, ok bool) {
	if len(data) < 10 {
		return 0, 0, "", false
	}
	pid = binary.LittleEndian.Uint32(data[0:4])
	ppid = binary.LittleEndian.Uint32(data[4:8])
	imageName = readUTF16LE(data, 8)
	return pid, ppid, imageName, true
}

// readUTF16LE reads a null-terminated UTF-16LE string from data at offset.
func readUTF16LE(data []byte, offset int) string {
	var runes []rune
	for offset+1 < len(data) {
		w := uint16(data[offset]) | uint16(data[offset+1])<<8
		if w == 0 {
			break
		}
		runes = append(runes, rune(w))
		offset += 2
	}
	return string(runes)
}

// hashFile returns the SHA-256 hex digest and size of the file at path.
// Files larger than 50 MB are not hashed (returns size only).
func hashFile(path string) (string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", 0
	}
	if stat.Size() > 50*1024*1024 {
		return "", stat.Size()
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", stat.Size()
	}
	return hex.EncodeToString(h.Sum(nil)), stat.Size()
}

// splitArgs splits a Windows command line string into arguments, respecting double quotes.
func splitArgs(cmdline string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	for _, r := range cmdline {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// detectInterpreter returns the interpreter name and the script path argument
// when the process is a known script host; both are empty otherwise.
func detectInterpreter(exePath string, args []string) (interpreter, scriptPath string) {
	// Normalize Windows backslash paths so filepath.Base works on any platform.
	exePath = strings.ReplaceAll(exePath, `\`, "/")
	name := strings.ToLower(filepath.Base(exePath))
	name = strings.TrimSuffix(name, ".exe")

	known := map[string]bool{
		"python": true, "python3": true, "python2": true,
		"perl": true, "ruby": true, "php": true, "lua": true,
		"bash": true, "sh": true, "zsh": true,
		"node": true, "nodejs": true, "deno": true,
		"powershell": true, "pwsh": true,
		"cmd":     true,
		"wscript": true, "cscript": true,
		"mshta": true,
	}
	if !known[name] {
		return "", ""
	}
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "/") {
			return name, arg
		}
	}
	return name, ""
}

const maxScriptSize = 64 * 1024

// captureScriptContent returns the script payload, either from an inline flag
// or by reading the script file from disk. Returns "" for non-script processes.
func captureScriptContent(args []string, interpreter, scriptPath string) string {
	if interpreter == "" {
		return ""
	}

	inlineFlags := map[string][]string{
		"powershell": {"-Command", "-c", "-EncodedCommand", "-enc", "-e"},
		"pwsh":       {"-Command", "-c", "-EncodedCommand", "-enc", "-e"},
		"cmd":        {"/c", "/C"},
		"python":     {"-c"}, "python3": {"-c"}, "python2": {"-c"},
		"perl":       {"-e"}, "ruby": {"-e"},
		"node":       {"-e"}, "nodejs": {"-e"},
		"bash":       {"-c"}, "sh": {"-c"}, "zsh": {"-c"},
	}

	if flags, ok := inlineFlags[interpreter]; ok {
		for i, arg := range args[1:] {
			for _, flag := range flags {
				if strings.EqualFold(arg, flag) && i+2 < len(args) {
					content := args[i+2]
					// Decode base64 for PowerShell -EncodedCommand / -enc / -e.
					if (interpreter == "powershell" || interpreter == "pwsh") &&
						(strings.EqualFold(flag, "-EncodedCommand") ||
							strings.EqualFold(flag, "-enc") ||
							strings.EqualFold(flag, "-e")) {
						if decoded, err := decodeBase64Unicode(content); err == nil {
							content = decoded
						}
					}
					if len(content) > maxScriptSize {
						content = content[:maxScriptSize] + "\n... (truncated)"
					}
					return content
				}
			}
		}
	}

	if scriptPath == "" {
		return ""
	}
	fi, err := os.Stat(scriptPath)
	if err != nil || fi.IsDir() || fi.Size() == 0 || fi.Size() > int64(maxScriptSize*2) {
		return ""
	}
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return ""
	}
	content := string(data)
	if len(content) > maxScriptSize {
		content = content[:maxScriptSize] + "\n... (truncated)"
	}
	return content
}

// decodeBase64Unicode decodes a PowerShell -EncodedCommand payload (UTF-16LE base64).
func decodeBase64Unicode(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(raw)%2 != 0 {
		return string(raw), nil
	}
	runes := make([]rune, 0, len(raw)/2)
	for i := 0; i < len(raw)-1; i += 2 {
		runes = append(runes, rune(raw[i])|rune(raw[i+1])<<8)
	}
	return string(runes), nil
}

// extractComm returns the basename of an exe path (backslash or forward-slash separated).
func extractComm(exePath string) string {
	if exePath == "" {
		return ""
	}
	exePath = strings.ReplaceAll(exePath, `\`, "/")
	return filepath.Base(exePath)
}

// isSuspiciousExe reports whether the exe path matches a commonly-abused interpreter
// or living-off-the-land binary. Used to elevate event severity.
func isSuspiciousExe(exePath string) bool {
	lower := strings.ToLower(exePath)
	for _, pat := range suspiciousPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

var suspiciousPatterns = []string{
	"powershell", "cmd.exe", "wscript", "cscript", "mshta",
	"regsvr32", "rundll32", "certutil", "bitsadmin",
}
