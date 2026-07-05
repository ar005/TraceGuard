package dns

import (
	"testing"
)

func TestParseDNSOutput(t *testing.T) {
	// Typical ipconfig /displaydns output (English locale).
	input := []byte(`
    ----------------------------------------
    example.com
    ----------------------------------------
    Record Name . . . . . : example.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 29
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 93.184.216.34

    ----------------------------------------
    ipv6.example.com
    ----------------------------------------
    Record Name . . . . . : ipv6.example.com
    Record Type . . . . . : 28
    Time To Live  . . . . : 3600
    Data Length . . . . . : 16
    Section . . . . . . . : Answer
    AAAA Record . . . . . : 2606:2800:220:1:248:1893:25c8:1946

    ----------------------------------------
    multi.example.com
    ----------------------------------------
    Record Name . . . . . : multi.example.com
    A (Host) Record . . . : 1.2.3.4
    A (Host) Record . . . : 5.6.7.8

`)

	entries := parseDNSOutput(input)

	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	tests := []struct {
		domain string
		ips    []string
	}{
		{"example.com", []string{"93.184.216.34"}},
		{"ipv6.example.com", []string{"2606:2800:220:1:248:1893:25c8:1946"}},
		{"multi.example.com", []string{"1.2.3.4", "5.6.7.8"}},
	}

	for i, tt := range tests {
		e := entries[i]
		if e.Domain != tt.domain {
			t.Errorf("entry[%d] domain: got %q, want %q", i, e.Domain, tt.domain)
		}
		if len(e.IPs) != len(tt.ips) {
			t.Errorf("entry[%d] ips count: got %d, want %d", i, len(e.IPs), len(tt.ips))
			continue
		}
		for j, ip := range tt.ips {
			if e.IPs[j] != ip {
				t.Errorf("entry[%d].IPs[%d]: got %q, want %q", i, j, e.IPs[j], ip)
			}
		}
	}
}

func TestParseDNSOutput_Empty(t *testing.T) {
	if got := parseDNSOutput([]byte("")); len(got) != 0 {
		t.Fatalf("empty input: got %d entries, want 0", len(got))
	}
}

func TestParseDNSOutput_NoIPs(t *testing.T) {
	// Entry with a domain but no A/AAAA records (e.g. CNAME-only).
	input := []byte(`
    Record Name . . . . . : cname.example.com

`)
	entries := parseDNSOutput(input)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Domain != "cname.example.com" {
		t.Errorf("domain: got %q, want %q", entries[0].Domain, "cname.example.com")
	}
	if len(entries[0].IPs) != 0 {
		t.Errorf("IPs: got %v, want empty", entries[0].IPs)
	}
}
