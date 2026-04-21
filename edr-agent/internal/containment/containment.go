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

const chainName = "OEDR_CONTAIN"
const quarantineDir = "/var/lib/edr/quarantine"
const blockChain = "OEDR_BLOCK"
const stateFile = "/var/lib/edr/containment_state.json"

// persistedState holds containment state that survives agent restarts.
type persistedState struct {
	Contained         bool                `json:"contained"`
	BlockedIPs        []string            `json:"blocked_ips"`
	BlockedDomains    map[string][]string `json:"blocked_domains"`
	PersistentIPs     map[string]bool     `json:"persistent_ips"`
	PersistentDomains map[string]bool     `json:"persistent_domains"`
}

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
	mu                sync.Mutex
	contained         bool
	backendIP         string
	backendPort       string
	blockedIPs        map[string]bool
	blockedDomains    map[string][]string // domain -> resolved IPs
	persistentIPs     map[string]bool     // IPs that survive agent restart
	persistentDomains map[string]bool     // domains that survive agent restart
	log               zerolog.Logger
}

// New creates a containment manager.
func New(backendURL string, log zerolog.Logger) *Manager {
	ip, port := parseBackendAddr(backendURL)
	return &Manager{
		backendIP:         ip,
		backendPort:       port,
		blockedIPs:        make(map[string]bool),
		blockedDomains:    make(map[string][]string),
		persistentIPs:     make(map[string]bool),
		persistentDomains: make(map[string]bool),
		log:               log.With().Str("component", "containment").Logger(),
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
	m.persistStateLocked()
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
	m.persistStateLocked()
	m.log.Warn().Msg("NETWORK CONTAINMENT RELEASED — normal traffic restored")
	return nil
}

// quarantineBlocklist contains paths that must never be quarantined (deleting them
// would immediately break the system).
var quarantineBlocklist = []string{
	"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/",
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
	"/etc/hosts", "/etc/resolv.conf", "/etc/fstab",
	"/boot/", "/proc/", "/sys/", "/dev/",
	"/usr/lib/systemd/", "/lib/systemd/",
}

// QuarantineFile moves a file to the quarantine directory, stripping execute permissions.
// Original path is preserved in a .meta sidecar file for potential restoration.
func (m *Manager) QuarantineFile(filePath string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reject paths that would break the system if removed.
	clean := filepath.Clean(filePath)
	for _, blocked := range quarantineBlocklist {
		if clean == strings.TrimSuffix(blocked, "/") || strings.HasPrefix(clean, blocked) {
			return "", fmt.Errorf("quarantine of system path %q is not permitted", clean)
		}
	}

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
// If persistent is true, the block will be restored on agent restart.
func (m *Manager) BlockIP(ip string, persistent bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blockIPLocked(ip, persistent)
}

// blockIPLocked is the internal implementation that assumes the lock is held.
func (m *Manager) blockIPLocked(ip string, persistent bool) error {
	// Validate IP format.
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if already blocked.
	if m.blockedIPs[ip] {
		return fmt.Errorf("IP %s is already blocked", ip)
	}

	// Create OEDR_BLOCK chain if it doesn't exist (ignore error if already exists).
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
	if persistent {
		m.persistentIPs[ip] = true
	}
	m.persistStateLocked()
	m.log.Warn().Str("ip", ip).Bool("persistent", persistent).Msg("IP BLOCKED")
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
	delete(m.persistentIPs, ip)
	m.log.Warn().Str("ip", ip).Msg("IP UNBLOCKED")

	// If no more blocked IPs and no domain blocks use the chain, clean up.
	if len(m.blockedIPs) == 0 && len(m.blockedDomains) == 0 {
		_ = run("iptables", "-D", "INPUT", "-j", blockChain)
		_ = run("iptables", "-D", "OUTPUT", "-j", blockChain)
		_ = run("iptables", "-F", blockChain)
		_ = run("iptables", "-X", blockChain)
	}

	m.persistStateLocked()
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

// BlockDomain resolves a domain to IPs, blocks each IP and adds a DNS string match rule.
// If persistent is true, the domain block will be restored on agent restart.
func (m *Manager) BlockDomain(domain string, persistent bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedDomains[domain]; exists {
		return fmt.Errorf("domain %s is already blocked", domain)
	}

	// Resolve domain to IPs.
	ips, err := net.LookupHost(domain)
	if err != nil {
		return fmt.Errorf("resolve domain %s: %w", domain, err)
	}

	// Block each resolved IP (skip already-blocked ones silently).
	var blockedIPs []string
	for _, ip := range ips {
		if m.blockedIPs[ip] {
			blockedIPs = append(blockedIPs, ip)
			continue
		}
		if err := m.blockIPLocked(ip, false); err != nil {
			// Rollback IPs we just blocked for this domain.
			for _, rollbackIP := range blockedIPs {
				if !m.wasBlockedBefore(rollbackIP, domain) {
					m.unblockIPLocked(rollbackIP)
				}
			}
			return fmt.Errorf("block resolved IP %s for domain %s: %w", ip, domain, err)
		}
		blockedIPs = append(blockedIPs, ip)
	}

	// Add DNS string match rule to block DNS queries for this domain.
	_ = run("iptables", "-N", blockChain)
	if err := run("iptables", "-A", blockChain, "-p", "udp", "--dport", "53",
		"-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP"); err != nil {
		m.log.Warn().Err(err).Str("domain", domain).Msg("failed to add DNS string match rule (iptables string module may not be available)")
	}
	m.ensureBlockChainJumps()

	m.blockedDomains[domain] = blockedIPs
	if persistent {
		m.persistentDomains[domain] = true
	}
	m.persistStateLocked()
	m.log.Warn().Str("domain", domain).Strs("ips", blockedIPs).Bool("persistent", persistent).Msg("DOMAIN BLOCKED")
	return nil
}

// UnblockDomain removes all blocks associated with a domain.
func (m *Manager) UnblockDomain(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ips, exists := m.blockedDomains[domain]
	if !exists {
		return fmt.Errorf("domain %s is not blocked", domain)
	}

	// Unblock each IP that was resolved for this domain.
	for _, ip := range ips {
		// Only unblock if no other domain also blocks this IP.
		if !m.ipBlockedByOtherDomain(ip, domain) {
			m.unblockIPLocked(ip)
		}
	}

	// Remove the DNS string match rule.
	_ = run("iptables", "-D", blockChain, "-p", "udp", "--dport", "53",
		"-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP")

	delete(m.blockedDomains, domain)
	delete(m.persistentDomains, domain)

	// If no more blocks, clean up the chain.
	if len(m.blockedIPs) == 0 && len(m.blockedDomains) == 0 {
		_ = run("iptables", "-D", "INPUT", "-j", blockChain)
		_ = run("iptables", "-D", "OUTPUT", "-j", blockChain)
		_ = run("iptables", "-F", blockChain)
		_ = run("iptables", "-X", blockChain)
	}

	m.persistStateLocked()
	m.log.Warn().Str("domain", domain).Msg("DOMAIN UNBLOCKED")
	return nil
}

// ListBlockedDomains returns all currently blocked domain names, sorted.
func (m *Manager) ListBlockedDomains() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	domains := make([]string, 0, len(m.blockedDomains))
	for d := range m.blockedDomains {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

// RestoreState loads persisted containment state and re-applies persistent blocks.
// Should be called once after the Manager is created during agent startup.
func (m *Manager) RestoreState() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadAndRestoreState()
}

// loadAndRestoreState reads the state file and re-applies state. Caller must hold m.mu.
func (m *Manager) loadAndRestoreState() {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			m.log.Warn().Err(err).Msg("failed to read containment state file")
		}
		return
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		m.log.Warn().Err(err).Msg("failed to parse containment state file")
		return
	}

	m.log.Info().
		Bool("contained", state.Contained).
		Int("blocked_ips", len(state.BlockedIPs)).
		Int("blocked_domains", len(state.BlockedDomains)).
		Int("persistent_ips", len(state.PersistentIPs)).
		Int("persistent_domains", len(state.PersistentDomains)).
		Msg("restoring containment state from disk")

	// Restore persistent IP blocks (re-run iptables rules).
	for ip := range state.PersistentIPs {
		if err := m.blockIPLocked(ip, true); err != nil {
			m.log.Warn().Err(err).Str("ip", ip).Msg("failed to restore persistent IP block")
		}
	}

	// Restore non-persistent IP tracking (iptables rules survive in kernel).
	for _, ip := range state.BlockedIPs {
		if !m.blockedIPs[ip] { // skip if already restored as persistent
			m.blockedIPs[ip] = true
		}
	}

	// Restore persistent domain blocks (re-resolve and re-run iptables).
	for domain := range state.PersistentDomains {
		// Use the public-facing logic but we already hold the lock,
		// so we inline the domain blocking here.
		ips, err := net.LookupHost(domain)
		if err != nil {
			m.log.Warn().Err(err).Str("domain", domain).Msg("failed to resolve domain during state restore")
			// Keep stale IPs from state.
			if staleIPs, ok := state.BlockedDomains[domain]; ok {
				ips = staleIPs
			} else {
				continue
			}
		}
		var blockedIPs []string
		for _, ip := range ips {
			if !m.blockedIPs[ip] {
				if err := m.blockIPLocked(ip, false); err != nil {
					m.log.Warn().Err(err).Str("ip", ip).Str("domain", domain).Msg("failed to restore domain IP block")
					continue
				}
			}
			blockedIPs = append(blockedIPs, ip)
		}
		// Re-add DNS string match rule.
		_ = run("iptables", "-N", blockChain)
		_ = run("iptables", "-A", blockChain, "-p", "udp", "--dport", "53",
			"-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP")
		m.ensureBlockChainJumps()
		m.blockedDomains[domain] = blockedIPs
		m.persistentDomains[domain] = true
	}

	// Restore non-persistent domain tracking.
	for domain, ips := range state.BlockedDomains {
		if _, exists := m.blockedDomains[domain]; !exists {
			m.blockedDomains[domain] = ips
			// Ensure IPs are tracked.
			for _, ip := range ips {
				if !m.blockedIPs[ip] {
					m.blockedIPs[ip] = true
				}
			}
		}
	}

	// Restore isolation if it was active.
	if state.Contained && !m.contained {
		m.log.Info().Msg("re-applying network containment from persisted state")
		// We need to unlock temporarily since Isolate takes the lock.
		// Instead, inline the isolation logic here.
		cmds := [][]string{
			{"iptables", "-N", chainName},
			{"iptables", "-A", chainName, "-i", "lo", "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-o", "lo", "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-d", m.backendIP, "-p", "tcp", "--dport", m.backendPort, "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-s", m.backendIP, "-p", "tcp", "--sport", m.backendPort, "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
			{"iptables", "-A", chainName, "-j", "DROP"},
			{"iptables", "-I", "INPUT", "1", "-j", chainName},
			{"iptables", "-I", "OUTPUT", "1", "-j", chainName},
		}
		for _, args := range cmds {
			if err := run(args...); err != nil {
				m.log.Warn().Err(err).Strs("cmd", args).Msg("failed to restore containment rule")
				m.cleanup()
				return
			}
		}
		m.contained = true
	}
}

// persistStateLocked writes current containment state to disk. Caller must hold m.mu.
func (m *Manager) persistStateLocked() {
	state := persistedState{
		Contained:         m.contained,
		BlockedIPs:        make([]string, 0, len(m.blockedIPs)),
		BlockedDomains:    make(map[string][]string, len(m.blockedDomains)),
		PersistentIPs:     make(map[string]bool, len(m.persistentIPs)),
		PersistentDomains: make(map[string]bool, len(m.persistentDomains)),
	}

	for ip := range m.blockedIPs {
		state.BlockedIPs = append(state.BlockedIPs, ip)
	}
	sort.Strings(state.BlockedIPs)

	for domain, ips := range m.blockedDomains {
		state.BlockedDomains[domain] = ips
	}
	for ip := range m.persistentIPs {
		state.PersistentIPs[ip] = true
	}
	for domain := range m.persistentDomains {
		state.PersistentDomains[domain] = true
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		m.log.Warn().Err(err).Msg("failed to marshal containment state")
		return
	}

	// Ensure directory exists.
	if err := os.MkdirAll(filepath.Dir(stateFile), 0700); err != nil {
		m.log.Warn().Err(err).Msg("failed to create state directory")
		return
	}

	if err := os.WriteFile(stateFile, data, 0600); err != nil {
		m.log.Warn().Err(err).Msg("failed to write containment state file")
	}
}

// unblockIPLocked removes iptables block for an IP. Caller must hold m.mu.
func (m *Manager) unblockIPLocked(ip string) {
	_ = run("iptables", "-D", blockChain, "-s", ip, "-j", "DROP")
	_ = run("iptables", "-D", blockChain, "-d", ip, "-j", "DROP")
	delete(m.blockedIPs, ip)
	delete(m.persistentIPs, ip)
}

// ipBlockedByOtherDomain checks if an IP is referenced by another blocked domain.
func (m *Manager) ipBlockedByOtherDomain(ip, excludeDomain string) bool {
	for domain, ips := range m.blockedDomains {
		if domain == excludeDomain {
			continue
		}
		for _, dip := range ips {
			if dip == ip {
				return true
			}
		}
	}
	return false
}

// wasBlockedBefore checks if an IP was already blocked before the given domain was added.
// Used during rollback — if the IP was only blocked as part of this domain, it should be rolled back.
func (m *Manager) wasBlockedBefore(ip, domain string) bool {
	return m.ipBlockedByOtherDomain(ip, domain)
}

// ensureBlockChainJumps adds jumps from INPUT and OUTPUT to OEDR_BLOCK if not present.
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
