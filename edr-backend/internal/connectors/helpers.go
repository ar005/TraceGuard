// internal/connectors/helpers.go — shared utilities for connector implementations.

package connectors

import "net"

// parseIP parses an IP string into net.IP, returning nil for invalid input.
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}
