// parse.go — pure-Go DNS cache output parser. No OS-specific imports.
// Split out so it can be unit-tested on Linux CI without the ETW build tag.
package dns

import (
	"bufio"
	"bytes"
	"strings"
)

type dnsEntry struct {
	Domain string
	IPs    []string
}

// parseDNSOutput parses the text output of `ipconfig /displaydns` into entries.
//
// Format (per entry):
//
//	Record Name . . . . . : example.com
//	A (Host) Record . . . : 93.184.216.34
//	AAAA Record . . . . . : 2606:…
//	<blank line separates entries>
func parseDNSOutput(data []byte) []dnsEntry {
	var entries []dnsEntry
	var current *dnsEntry

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.Contains(line, "Record Name"):
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				if d := strings.TrimSpace(parts[1]); d != "" {
					current = &dnsEntry{Domain: d}
				}
			}
		case current != nil && (strings.Contains(line, "A (Host) Record") || strings.Contains(line, "AAAA Record")):
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				if ip := strings.TrimSpace(parts[1]); ip != "" {
					current.IPs = append(current.IPs, ip)
				}
			}
		case line == "" && current != nil:
			if current.Domain != "" {
				entries = append(entries, *current)
			}
			current = nil
		}
	}
	if current != nil && current.Domain != "" {
		entries = append(entries, *current)
	}
	return entries
}
