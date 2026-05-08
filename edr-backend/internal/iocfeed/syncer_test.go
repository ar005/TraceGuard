package iocfeed

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseFeodoTracker(t *testing.T) {
	body := `################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)  #
################################################################
#
# DstIP
50.16.16.211
1.2.3.4
not-an-ip
# END 2 entries`

	parser := parsePlainTextIPs("test", []string{"c2"})
	iocs := parser(strings.NewReader(body))

	if len(iocs) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].Value != "50.16.16.211" {
		t.Errorf("expected 50.16.16.211, got %s", iocs[0].Value)
	}
	if iocs[1].Value != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", iocs[1].Value)
	}
}

func TestParseMalwareBazaar(t *testing.T) {
	body := `################################################################
# MalwareBazaar recent malware samples (SHA256 hashes)         #
################################################################
#
# sha256_hash
70248962c3eeee9d74c4637c46b0356689c21315910d746894cd8e8086c7192a
1234b313e10a9a92dadb9644e03d5dae24a6bea0c209866bb2debdedffa28b9c
tooshort
not-hex-gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg1234`

	parser := parsePlainTextHashes("test", []string{"malware"})
	iocs := parser(strings.NewReader(body))

	if len(iocs) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(iocs))
	}
	if iocs[0].Value != "70248962c3eeee9d74c4637c46b0356689c21315910d746894cd8e8086c7192a" {
		t.Errorf("unexpected hash: %s", iocs[0].Value)
	}
}

func TestParseURLhaus(t *testing.T) {
	body := `################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3800665","2026-03-20","https://dc2power.platformendpoint.in.net/verification.google","online","2026-03-20","malware_download","ACRStealer,ClearFake","https://urlhaus.abuse.ch/url/3800665/","anonymous"
"3800664","2026-03-20","http://115.55.131.250:55513/i","online","2026-03-20","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3800664/","geenensp"
"3800663","2026-03-20","http://222.140.237.78:47344/bin.sh","offline","","malware_download","None","https://urlhaus.abuse.ch/url/3800663/","aLittleBitGrey"`

	iocs := parseURLhausCSV(strings.NewReader(body))

	if len(iocs) != 3 {
		t.Fatalf("expected 3 IOCs, got %d", len(iocs))
	}

	// First should be a domain.
	if iocs[0].Value != "dc2power.platformendpoint.in.net" {
		t.Errorf("expected domain, got %s", iocs[0].Value)
	}
	if iocs[0].IOCType != "domain" {
		t.Errorf("expected type=domain, got %s", iocs[0].IOCType)
	}

	// Second should be an IP (extracted from URL with port).
	if iocs[1].Value != "115.55.131.250" {
		t.Errorf("expected IP 115.55.131.250, got %s", iocs[1].Value)
	}
	if iocs[1].IOCType != "ip" {
		t.Errorf("expected type=ip, got %s", iocs[1].IOCType)
	}

	// Third should also be an IP.
	if iocs[2].Value != "222.140.237.78" {
		t.Errorf("expected IP 222.140.237.78, got %s", iocs[2].Value)
	}

	// Check tags include urlhaus + feed tags.
	foundACR := false
	for _, tag := range iocs[0].Tags {
		if tag == "ACRStealer" {
			foundACR = true
		}
	}
	if !foundACR {
		t.Errorf("expected tag ACRStealer in %v", iocs[0].Tags)
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://evil.com/malware.exe", "evil.com"},
		{"http://1.2.3.4:8080/payload", "1.2.3.4"},
		{"http://1.2.3.4/foo", "1.2.3.4"},
		{"ftp://files.bad.org/thing", "files.bad.org"},
		{"https://localhost/test", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractHost(tt.input)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsHex(t *testing.T) {
	if !isHex("abcdef0123456789") {
		t.Error("expected true for valid hex")
	}
	if isHex("xyz123") {
		t.Error("expected false for invalid hex")
	}
}

// TestLiveFeeds actually downloads from the real feeds and verifies parsing.
// Skip in CI with -short flag.
func TestLiveFeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live feed test in short mode")
	}

	feeds := defaultFeeds()
	client := &http.Client{Timeout: 30 * 1000000000} // 30s

	for _, feed := range feeds {
		t.Run(feed.Name, func(t *testing.T) {
			resp, err := client.Get(feed.URL)
			if err != nil {
				t.Fatalf("fetch %s: %v", feed.URL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Fatalf("HTTP %d from %s", resp.StatusCode, feed.URL)
			}

			iocs := feed.Parser(resp.Body)
			t.Logf("%s: parsed %d IOCs", feed.Name, len(iocs))

			if len(iocs) == 0 {
				t.Errorf("expected >0 IOCs from %s", feed.Name)
			}

			// Spot-check first IOC.
			if len(iocs) > 0 {
				first := iocs[0]
				if first.Value == "" {
					t.Error("first IOC has empty value")
				}
				t.Logf("  first: type=%s value=%s desc=%s tags=%v",
					first.IOCType, first.Value, first.Description, first.Tags)
			}
		})
	}
}
