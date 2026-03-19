// Package containment implements network isolation for compromised endpoints.
// When activated, iptables rules block all traffic except:
//   - Backend gRPC communication (so the agent stays manageable)
//   - Loopback traffic
//   - Established connections to the backend
//
// Containment is reversible — Release() removes all rules.

package containment

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

const chainName = "TraceGuard_CONTAIN"

// Manager handles network containment state.
type Manager struct {
	mu         sync.Mutex
	contained  bool
	backendIP  string
	backendPort string
	log        zerolog.Logger
}

// New creates a containment manager.
func New(backendURL string, log zerolog.Logger) *Manager {
	ip, port := parseBackendAddr(backendURL)
	return &Manager{
		backendIP:   ip,
		backendPort: port,
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
