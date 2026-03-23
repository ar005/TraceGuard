// Package containment implements network isolation for compromised endpoints.
// When activated, iptables rules block all traffic except:
//   - Backend gRPC communication (so the agent stays manageable)
//   - Loopback traffic
//   - Established connections to the backend
//
// Containment is reversible — Release() removes all rules.

package containment

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const chainName = "TraceGuard_CONTAIN"
const quarantineDir = "/var/lib/edr/quarantine"
const blockChain = "TraceGuard_BLOCK"

// QuarantineInfo holds metadata about a quarantined file.
type QuarantineInfo struct {
	OriginalPath   string `json:"original_path"`
	QuarantineName string `json:"quarantine_name"`
	QuarantineTime string `json:"quarantine_time"`
	FileSize       int64  `json:"file_size"`
	SHA256         string `json:"sha256"`
}

// Manager handles network containment state.
type Manager struct {
	mu          sync.Mutex
	contained   bool
	backendIP   string
	backendPort string
	blockedIPs  map[string]bool
	log         zerolog.Logger
}

// New creates a containment manager.
func New(backendURL string, log zerolog.Logger) *Manager {
	ip, port := parseBackendAddr(backendURL)
	return &Manager{
		backendIP:   ip,
		backendPort: port,
		blockedIPs:  make(map[string]bool),
		log:         log.With().Str("component", "containment").Logger(),
	}
}

// IsContained returns whether the host is currently network-isolated.
func (m *Manager) IsContained() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.contained
}

// Isolate activates network containment.
func (m *Manager) Isolate() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.contained {
		return fmt.Errorf("host is already contained")
	}

	cmds := [][]string{
		// Create our chain.
		{"iptables", "-N", chainName},
		// Allow loopback.
		{"iptables", "-A", chainName, "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-o", "lo", "-j", "ACCEPT"},
		// Allow established/related (keeps our gRPC stream alive).
		{"iptables", "-A", chainName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		// Allow traffic to/from backend.
		{"iptables", "-A", chainName, "-d", m.backendIP, "-p", "tcp", "--dport", m.backendPort, "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-s", m.backendIP, "-p", "tcp", "--sport", m.backendPort, "-j", "ACCEPT"},
		// Allow DNS (needed for backend hostname resolution).
		{"iptables", "-A", chainName, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"iptables", "-A", chainName, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		// Drop everything else.
		{"iptables", "-A", chainName, "-j", "DROP"},
		// Insert our chain at the top of INPUT and OUTPUT.
		{"iptables", "-I", "INPUT", "1", "-j", chainName},
		{"iptables", "-I", "OUTPUT", "1", "-j", chainName},
	}

	for _, args := range cmds {
		if err := run(args...); err != nil {
			// Rollback on failure.
			m.cleanup()
			return fmt.Errorf("containment failed at %q: %w", strings.Join(args, " "), err)
		}
	}

	m.contained = true
	m.log.Warn().
		Str("backend_ip", m.backendIP).
		Str("backend_port", m.backendPort).
		Msg("NETWORK CONTAINMENT ACTIVATED — all non-backend traffic blocked")
	return nil
}

// Release removes containment rules, restoring normal network access.
func (m *Manager) Release() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.contained {
		return fmt.Errorf("host is not contained")
	}

	m.cleanup()
	m.contained = false
	m.log.Warn().Msg("NETWORK CONTAINMENT RELEASED — normal traffic restored")
	return nil
}

// QuarantineFile moves a file to the quarantine directory, stripping execute permissions.
// Original path is preserved in a .meta sidecar file for potential restoration.
func (m *Manager) QuarantineFile(filePath string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate the file exists.
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", filePath, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot quarantine a directory: %s", filePath)
	}

	// Create quarantine dir if not exists.
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return "", fmt.Errorf("create quarantine dir: %w", err)
	}

	// Compute SHA256 of the file.
	hash, err := fileSHA256(filePath)
	if err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	// Generate quarantine name: sha256_timestamp.
	now := time.Now().UTC()
	qName := fmt.Sprintf("%s_%d", hash, now.UnixNano())
	qPath := filepath.Join(quarantineDir, qName)

	// Copy file to quarantine dir.
	if err := copyFile(filePath, qPath); err != nil {
		return "", fmt.Errorf("copy to quarantine: %w", err)
	}

	// Strip execute permissions on quarantined copy.
	if err := os.Chmod(qPath, 0600); err != nil {
		return "", fmt.Errorf("chmod quarantine file: %w", err)
	}

	// Write .meta sidecar file.
	meta := QuarantineInfo{
		OriginalPath:   filePath,
		QuarantineName: qName,
		QuarantineTime: now.Format(time.RFC3339),
		FileSize:       info.Size(),
		SHA256:         hash,
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("marshal meta: %w", err)
	}
	if err := os.WriteFile(qPath+".meta", metaBytes, 0600); err != nil {
		return "", fmt.Errorf("write meta: %w", err)
	}

	// Remove the original file.
	if err := os.Remove(filePath); err != nil {
		m.log.Warn().Err(err).Str("path", filePath).Msg("failed to remove original file after quarantine copy")
		return qPath, fmt.Errorf("quarantine copied but failed to remove original: %w", err)
	}

	m.log.Warn().
		Str("original", filePath).
		Str("quarantine", qPath).
		Str("sha256", hash).
		Msg("FILE QUARANTINED")
	return qPath, nil
}

// RestoreFile restores a quarantined file to its original path.
func (m *Manager) RestoreFile(quarantineName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	qPath := filepath.Join(quarantineDir, quarantineName)
	metaPath := qPath + ".meta"

	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read meta file: %w", err)
	}
	var meta QuarantineInfo
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return fmt.Errorf("parse meta: %w", err)
	}

	// Ensure parent directory of original path exists.
	if err := os.MkdirAll(filepath.Dir(meta.OriginalPath), 0755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	// Copy back to original path.
	if err := copyFile(qPath, meta.OriginalPath); err != nil {
		return fmt.Errorf("restore file: %w", err)
	}

	// Remove quarantine file and meta.
	os.Remove(qPath)
	os.Remove(metaPath)

	m.log.Warn().
		Str("original", meta.OriginalPath).
		Str("quarantine", quarantineName).
		Msg("FILE RESTORED from quarantine")
	return nil
}

// ListQuarantined returns metadata about all quarantined files.
func (m *Manager) ListQuarantined() ([]QuarantineInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(quarantineDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read quarantine dir: %w", err)
	}

	var results []QuarantineInfo
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(quarantineDir, e.Name()))
		if err != nil {
			continue
		}
		var info QuarantineInfo
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}
		results = append(results, info)
	}
	return results, nil
}

// ListQuarantinedJSON returns quarantine info as a JSON-encoded string.
// This is used by the transport layer to avoid type coupling between packages.
func (m *Manager) ListQuarantinedJSON() (string, error) {
	files, err := m.ListQuarantined()
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "[]", nil
	}
	data, err := json.Marshal(files)
	if err != nil {
		return "", fmt.Errorf("marshal quarantine list: %w", err)
	}
	return string(data), nil
}

// BlockIP adds iptables rules to block all traffic to/from a specific IP.
func (m *Manager) BlockIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate IP format.
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if already blocked.
	if m.blockedIPs[ip] {
		return fmt.Errorf("IP %s is already blocked", ip)
	}

	// Create TraceGuard_BLOCK chain if it doesn't exist (ignore error if already exists).
	_ = run("iptables", "-N", blockChain)

	// Add DROP rules for source and destination.
	if err := run("iptables", "-A", blockChain, "-s", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("add source block rule: %w", err)
	}
	if err := run("iptables", "-A", blockChain, "-d", ip, "-j", "DROP"); err != nil {
		// Rollback the source rule.
		_ = run("iptables", "-D", blockChain, "-s", ip, "-j", "DROP")
		return fmt.Errorf("add destination block rule: %w", err)
	}

	// Ensure chain is jumped to from INPUT and OUTPUT (idempotent — check first).
	m.ensureBlockChainJumps()

	m.blockedIPs[ip] = true
	m.log.Warn().Str("ip", ip).Msg("IP BLOCKED")
	return nil
}

// UnblockIP removes the iptables block for a specific IP.
func (m *Manager) UnblockIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if !m.blockedIPs[ip] {
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	// Remove the DROP rules.
	_ = run("iptables", "-D", blockChain, "-s", ip, "-j", "DROP")
	_ = run("iptables", "-D", blockChain, "-d", ip, "-j", "DROP")

	delete(m.blockedIPs, ip)
	m.log.Warn().Str("ip", ip).Msg("IP UNBLOCKED")

	// If no more blocked IPs, clean up the chain.
	if len(m.blockedIPs) == 0 {
		_ = run("iptables", "-D", "INPUT", "-j", blockChain)
		_ = run("iptables", "-D", "OUTPUT", "-j", blockChain)
		_ = run("iptables", "-F", blockChain)
		_ = run("iptables", "-X", blockChain)
	}

	return nil
}

// ListBlockedIPs returns all currently blocked IPs.
func (m *Manager) ListBlockedIPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ips := make([]string, 0, len(m.blockedIPs))
	for ip := range m.blockedIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

// ensureBlockChainJumps adds jumps from INPUT and OUTPUT to TraceGuard_BLOCK if not present.
func (m *Manager) ensureBlockChainJumps() {
	// Check if jump already exists by trying to add — iptables -C checks existence.
	if run("iptables", "-C", "INPUT", "-j", blockChain) != nil {
		_ = run("iptables", "-I", "INPUT", "1", "-j", blockChain)
	}
	if run("iptables", "-C", "OUTPUT", "-j", blockChain) != nil {
		_ = run("iptables", "-I", "OUTPUT", "1", "-j", blockChain)
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func (m *Manager) cleanup() {
	// Remove jumps from INPUT/OUTPUT, then flush and delete our chain.
	_ = run("iptables", "-D", "INPUT", "-j", chainName)
	_ = run("iptables", "-D", "OUTPUT", "-j", chainName)
	_ = run("iptables", "-F", chainName)
	_ = run("iptables", "-X", chainName)
}

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseBackendAddr(url string) (string, string) {
	// Strip scheme.
	addr := url
	for _, prefix := range []string{"https://", "http://", "grpc://"} {
		addr = strings.TrimPrefix(addr, prefix)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port — default gRPC port.
		host = addr
		port = "50051"
	}

	// Resolve hostname to IP.
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return host, port
	}
	return ips[0], port
}
