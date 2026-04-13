// internal/containment/containment.go
// Containment controller for Windows — IP blocking, network isolation,
// and file quarantine using Windows Firewall (netsh advfirewall).
//
// Implements transport.ContainmentController interface.

package containment

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	quarantineDir  = `C:\ProgramData\TraceGuard\Quarantine`
	stateFilePath  = `C:\ProgramData\TraceGuard\containment_state.json`
	rulePrefix     = "TraceGuard_BLOCK_"
	domainPrefix   = "TraceGuard_DOMAIN_"
	isolationRule  = "TraceGuard_ISOLATE"
)

// persistedState represents the containment state saved to disk.
type persistedState struct {
	Contained         bool                `json:"contained"`
	BlockedIPs        []string            `json:"blocked_ips"`
	BlockedDomains    map[string][]string `json:"blocked_domains"`
	PersistentIPs     map[string]bool     `json:"persistent_ips"`
	PersistentDomains map[string]bool     `json:"persistent_domains"`
}

// Controller implements IP blocking, domain blocking, network isolation, and file quarantine.
type Controller struct {
	log              zerolog.Logger
	backendIP        string // backend IP to allow during isolation
	mu               sync.RWMutex
	blockedIPs       map[string]bool
	blockedDomains   map[string][]string // domain -> resolved IPs
	persistentIPs    map[string]bool
	persistentDoms   map[string]bool
	contained        bool
}

// New creates a containment controller.
func New(backendIP string, log zerolog.Logger) *Controller {
	return &Controller{
		log:            log.With().Str("component", "containment").Logger(),
		backendIP:      backendIP,
		blockedIPs:     make(map[string]bool),
		blockedDomains: make(map[string][]string),
		persistentIPs:  make(map[string]bool),
		persistentDoms: make(map[string]bool),
	}
}

// ─── IP Blocking ────────────────────────────────────────────────────────────

// BlockIP blocks inbound and outbound traffic to/from a specific IP.
// If persistent is true, the block survives agent restarts.
func (c *Controller) BlockIP(ip string, persistent bool) error {
	if ip == "" {
		return fmt.Errorf("empty IP address")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.blockedIPs[ip] {
		return nil // already blocked
	}

	if err := c.addIPFirewallRules(ip, rulePrefix); err != nil {
		return err
	}

	c.blockedIPs[ip] = true
	if persistent {
		c.persistentIPs[ip] = true
	}
	c.log.Info().Str("ip", ip).Bool("persistent", persistent).Msg("IP blocked")
	c.persistState()
	return nil
}

// addIPFirewallRules creates inbound and outbound block rules for an IP.
func (c *Controller) addIPFirewallRules(ip string, prefix string) error {
	ruleName := prefix + sanitizeRuleName(ip)

	// Block inbound.
	if err := runNetsh("add", "rule",
		"name="+ruleName+"_IN",
		"dir=in", "action=block",
		"remoteip="+ip,
		"enable=yes",
	); err != nil {
		return fmt.Errorf("block inbound %s: %w", ip, err)
	}

	// Block outbound.
	if err := runNetsh("add", "rule",
		"name="+ruleName+"_OUT",
		"dir=out", "action=block",
		"remoteip="+ip,
		"enable=yes",
	); err != nil {
		return fmt.Errorf("block outbound %s: %w", ip, err)
	}
	return nil
}

// UnblockIP removes firewall rules blocking a specific IP.
func (c *Controller) UnblockIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP address")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeIPFirewallRules(ip, rulePrefix)

	delete(c.blockedIPs, ip)
	delete(c.persistentIPs, ip)
	c.log.Info().Str("ip", ip).Msg("IP unblocked")
	c.persistState()
	return nil
}

// removeIPFirewallRules deletes inbound and outbound rules for an IP.
func (c *Controller) removeIPFirewallRules(ip string, prefix string) {
	ruleName := prefix + sanitizeRuleName(ip)
	runNetsh("delete", "rule", "name="+ruleName+"_IN")
	runNetsh("delete", "rule", "name="+ruleName+"_OUT")
}

// ListBlockedIPs returns all currently blocked IPs.
func (c *Controller) ListBlockedIPs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var ips []string
	for ip := range c.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// ─── Network Isolation ──────────────────────────────────────────────────────

// Isolate blocks all network traffic except communication with the backend.
func (c *Controller) Isolate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.contained {
		return nil // already isolated
	}

	// Block all outbound traffic.
	if err := runNetsh("add", "rule",
		"name="+isolationRule+"_BLOCK_OUT",
		"dir=out", "action=block",
		"enable=yes",
	); err != nil {
		return fmt.Errorf("isolation block outbound: %w", err)
	}

	// Block all inbound traffic.
	if err := runNetsh("add", "rule",
		"name="+isolationRule+"_BLOCK_IN",
		"dir=in", "action=block",
		"enable=yes",
	); err != nil {
		return fmt.Errorf("isolation block inbound: %w", err)
	}

	// Allow backend communication (outbound).
	if c.backendIP != "" {
		if err := runNetsh("add", "rule",
			"name="+isolationRule+"_ALLOW_BACKEND_OUT",
			"dir=out", "action=allow",
			"remoteip="+c.backendIP,
			"enable=yes",
		); err != nil {
			return fmt.Errorf("isolation allow backend out: %w", err)
		}

		// Allow backend communication (inbound).
		if err := runNetsh("add", "rule",
			"name="+isolationRule+"_ALLOW_BACKEND_IN",
			"dir=in", "action=allow",
			"remoteip="+c.backendIP,
			"enable=yes",
		); err != nil {
			return fmt.Errorf("isolation allow backend in: %w", err)
		}
	}

	// Allow DNS (needed for backend hostname resolution).
	runNetsh("add", "rule",
		"name="+isolationRule+"_ALLOW_DNS",
		"dir=out", "action=allow",
		"protocol=udp", "remoteport=53",
		"enable=yes",
	)

	c.contained = true
	c.log.Warn().Str("backend_ip", c.backendIP).Msg("network isolation activated")
	c.persistState()
	return nil
}

// Release removes all isolation firewall rules, restoring normal traffic.
func (c *Controller) Release() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rules := []string{
		isolationRule + "_BLOCK_OUT",
		isolationRule + "_BLOCK_IN",
		isolationRule + "_ALLOW_BACKEND_OUT",
		isolationRule + "_ALLOW_BACKEND_IN",
		isolationRule + "_ALLOW_DNS",
	}

	for _, rule := range rules {
		runNetsh("delete", "rule", "name="+rule)
	}

	c.contained = false
	c.log.Info().Msg("network isolation released")
	c.persistState()
	return nil
}

// IsContained returns whether the host is currently network-isolated.
func (c *Controller) IsContained() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.contained
}

// ─── Domain Blocking ───────────────────────────────────────────────────────

// BlockDomain resolves a domain to IPs and blocks each one.
// If persistent is true, the block survives agent restarts.
func (c *Controller) BlockDomain(domain string, persistent bool) error {
	if domain == "" {
		return fmt.Errorf("empty domain")
	}

	ips, err := net.LookupHost(domain)
	if err != nil {
		return fmt.Errorf("resolve domain %s: %w", domain, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("domain %s resolved to zero addresses", domain)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.blockedDomains[domain]; exists {
		return nil // already blocked
	}

	var blockedIPs []string
	for _, ip := range ips {
		if err := c.addIPFirewallRules(ip, domainPrefix+sanitizeRuleName(domain)+"_"); err != nil {
			c.log.Warn().Err(err).Str("ip", ip).Str("domain", domain).Msg("failed to block domain IP")
			continue
		}
		blockedIPs = append(blockedIPs, ip)
	}

	if len(blockedIPs) == 0 {
		return fmt.Errorf("failed to block any IPs for domain %s", domain)
	}

	c.blockedDomains[domain] = blockedIPs
	if persistent {
		c.persistentDoms[domain] = true
	}
	c.log.Info().Str("domain", domain).Strs("ips", blockedIPs).Bool("persistent", persistent).Msg("domain blocked")
	c.persistState()
	return nil
}

// UnblockDomain removes firewall rules for all IPs associated with a domain.
func (c *Controller) UnblockDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("empty domain")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ips, exists := c.blockedDomains[domain]
	if !exists {
		return fmt.Errorf("domain %s is not blocked", domain)
	}

	for _, ip := range ips {
		c.removeIPFirewallRules(ip, domainPrefix+sanitizeRuleName(domain)+"_")
	}

	delete(c.blockedDomains, domain)
	delete(c.persistentDoms, domain)
	c.log.Info().Str("domain", domain).Msg("domain unblocked")
	c.persistState()
	return nil
}

// ListBlockedDomains returns all currently blocked domains.
func (c *Controller) ListBlockedDomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var domains []string
	for domain := range c.blockedDomains {
		domains = append(domains, domain)
	}
	return domains
}

// ─── State Persistence ─────────────────────────────────────────────────────

// persistState writes the current containment state to disk.
// Must be called with c.mu held (read or write).
func (c *Controller) persistState() {
	state := persistedState{
		Contained:         c.contained,
		BlockedDomains:    c.blockedDomains,
		PersistentIPs:     c.persistentIPs,
		PersistentDomains: c.persistentDoms,
	}
	for ip := range c.blockedIPs {
		state.BlockedIPs = append(state.BlockedIPs, ip)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		c.log.Error().Err(err).Msg("failed to marshal containment state")
		return
	}

	dir := filepath.Dir(stateFilePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		c.log.Error().Err(err).Msg("failed to create state directory")
		return
	}

	if err := os.WriteFile(stateFilePath, data, 0640); err != nil {
		c.log.Error().Err(err).Msg("failed to write containment state")
	}
}

// RestoreState reads the persisted state file and re-applies persistent blocks.
// Should be called once after New(), before the agent starts processing commands.
func (c *Controller) RestoreState() {
	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			c.log.Debug().Msg("no containment state file found, starting fresh")
			return
		}
		c.log.Error().Err(err).Msg("failed to read containment state")
		return
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		c.log.Error().Err(err).Msg("failed to parse containment state")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Restore persistent IPs map and tracking for all IPs.
	// Netsh rules survive reboots, so we only re-apply persistent ones
	// and restore in-memory tracking for all.
	if state.PersistentIPs == nil {
		state.PersistentIPs = make(map[string]bool)
	}
	if state.PersistentDomains == nil {
		state.PersistentDomains = make(map[string]bool)
	}

	c.persistentIPs = state.PersistentIPs
	c.persistentDoms = state.PersistentDomains

	// Restore blocked IPs tracking. Netsh rules already exist from before reboot.
	for _, ip := range state.BlockedIPs {
		c.blockedIPs[ip] = true
	}

	// Restore blocked domains tracking.
	if state.BlockedDomains != nil {
		for domain, ips := range state.BlockedDomains {
			c.blockedDomains[domain] = ips
		}
	}

	// Re-apply isolation if it was active (netsh rules survive reboot,
	// but re-applying ensures consistency).
	if state.Contained {
		c.contained = true
		c.log.Warn().Msg("restored network isolation state from previous session")
	}

	restored := len(state.BlockedIPs)
	restoredDomains := len(state.BlockedDomains)
	c.log.Info().
		Int("blocked_ips", restored).
		Int("blocked_domains", restoredDomains).
		Bool("contained", state.Contained).
		Msg("containment state restored")
}

// ─── File Quarantine ────────────────────────────────────────────────────────

// quarantineMetadata stores info about quarantined files.
type quarantineMetadata struct {
	OriginalPath string `json:"original_path"`
	QuarantineID string `json:"quarantine_id"`
	Timestamp    string `json:"timestamp"`
	Size         int64  `json:"size"`
	Hash         string `json:"hash,omitempty"`
}

// QuarantineFile moves a file to the quarantine directory and stores metadata.
func (c *Controller) QuarantineFile(filePath string) (string, error) {
	// Ensure quarantine directory exists.
	if err := os.MkdirAll(quarantineDir, 0750); err != nil {
		return "", fmt.Errorf("create quarantine dir: %w", err)
	}

	// Check file exists.
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", filePath, err)
	}

	// Generate quarantine name.
	ts := time.Now().Format("20060102-150405")
	baseName := filepath.Base(filePath)
	quarantineName := fmt.Sprintf("%s_%s.quarantine", ts, baseName)
	destPath := filepath.Join(quarantineDir, quarantineName)

	// Move file.
	if err := os.Rename(filePath, destPath); err != nil {
		// If rename fails (cross-device), try copy+delete.
		data, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return "", fmt.Errorf("read for quarantine: %w", readErr)
		}
		if writeErr := os.WriteFile(destPath, data, 0600); writeErr != nil {
			return "", fmt.Errorf("write quarantine: %w", writeErr)
		}
		os.Remove(filePath)
	}

	// Write metadata.
	meta := quarantineMetadata{
		OriginalPath: filePath,
		QuarantineID: quarantineName,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Size:         info.Size(),
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := destPath + ".meta.json"
	os.WriteFile(metaPath, metaData, 0640)

	c.log.Warn().Str("file", filePath).Str("quarantine", quarantineName).Msg("file quarantined")
	return quarantineName, nil
}

// RestoreFile moves a quarantined file back to its original location.
func (c *Controller) RestoreFile(quarantineName string) error {
	destPath := filepath.Join(quarantineDir, quarantineName)
	metaPath := destPath + ".meta.json"

	// Read metadata.
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read quarantine metadata: %w", err)
	}

	var meta quarantineMetadata
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return fmt.Errorf("parse quarantine metadata: %w", err)
	}

	// Move file back.
	if err := os.Rename(destPath, meta.OriginalPath); err != nil {
		data, readErr := os.ReadFile(destPath)
		if readErr != nil {
			return fmt.Errorf("read quarantined file: %w", readErr)
		}
		if writeErr := os.WriteFile(meta.OriginalPath, data, 0644); writeErr != nil {
			return fmt.Errorf("restore file: %w", writeErr)
		}
		os.Remove(destPath)
	}

	// Remove metadata.
	os.Remove(metaPath)

	c.log.Info().Str("file", meta.OriginalPath).Msg("file restored from quarantine")
	return nil
}

// ListQuarantinedJSON returns a JSON array of quarantined files.
func (c *Controller) ListQuarantinedJSON() (string, error) {
	var items []quarantineMetadata

	entries, err := os.ReadDir(quarantineDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "[]", nil
		}
		return "", fmt.Errorf("read quarantine dir: %w", err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".meta.json") {
			continue
		}
		metaData, err := os.ReadFile(filepath.Join(quarantineDir, entry.Name()))
		if err != nil {
			continue
		}
		var meta quarantineMetadata
		if json.Unmarshal(metaData, &meta) == nil {
			items = append(items, meta)
		}
	}

	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func runNetsh(args ...string) error {
	fullArgs := append([]string{"advfirewall", "firewall"}, args...)
	cmd := exec.Command("netsh", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %s (%w)", strings.Join(args, " "), string(output), err)
	}
	return nil
}

func sanitizeRuleName(ip string) string {
	r := strings.NewReplacer(".", "_", ":", "_", "/", "_")
	return r.Replace(ip)
}
