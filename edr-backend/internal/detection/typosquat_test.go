package detection

import (
	"testing"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"google", "google", 0},
		{"google", "g00gle", 2},
		{"paypal", "paypa1", 1},
		{"", "abc", 3},
		{"abc", "", 3},
		{"", "", 0},
		{"kitten", "sitting", 3},
		{"flaw", "lawn", 2},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := LevenshteinDistance(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("LevenshteinDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCheckTyposquat(t *testing.T) {
	tests := []struct {
		domain    string
		wantBrand string
		wantMatch bool
	}{
		{"google.com", "", false},              // exact match, not a typosquat
		{"g00gle.com", "google", true},         // 2 edits (0→o twice)
		{"paypa1.com", "paypal", true},         // 1 edit (1→l)
		{"gooogle.com", "google", true},        // 1 edit (extra o)
		{"totally-random.com", "", false},      // not similar to anything
		{"www.google.com", "", false},          // exact with www prefix
		{"microsoftt.com", "microsoft", true},  // 1 edit (extra t)
		{"www.paypa1.com", "paypal", true},     // 1 edit with www prefix
		{"amaz0n.com", "amazon", true},         // 1 edit (0→o)
		{"facebook.com", "", false},            // exact match
		{"faceb00k.com", "facebook", true},     // 2 edits
		{"slack.com", "", false},               // exact match
		{"slakc.com", "slack", true},           // 2 edits (transposition-ish)
		{"xyzqwerty.com", "", false},           // nothing close
		{"github.com", "", false},              // exact
		{"githubb.com", "github", true},        // 1 edit
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			brand, dist := CheckTyposquat(tt.domain)
			gotMatch := brand != ""
			if gotMatch != tt.wantMatch {
				t.Errorf("CheckTyposquat(%q): match=%v (brand=%q, dist=%d), wantMatch=%v",
					tt.domain, gotMatch, brand, dist, tt.wantMatch)
			}
			if tt.wantMatch && brand != tt.wantBrand {
				t.Errorf("CheckTyposquat(%q): brand=%q, want %q", tt.domain, brand, tt.wantBrand)
			}
			if tt.wantMatch && (dist < 1 || dist > 2) {
				t.Errorf("CheckTyposquat(%q): distance=%d, want 1-2", tt.domain, dist)
			}
		})
	}
}

func TestCheckTyposquat_AdditionalCases(t *testing.T) {
	tests := []struct {
		domain    string
		wantBrand string
		wantMatch bool
	}{
		// Subdomains with typosquats.
		{"www.g00gle.com", "google", true},
		{"www.amaz0n.com", "amazon", true},
		{"www.faceb00k.com", "facebook", true},

		// Exact brand match should NOT fire (not a typosquat).
		{"amazon.com", "", false},
		{"paypal.com", "", false},
		{"netflix.com", "", false},
		{"spotify.com", "", false},
		{"zoom.com", "", false},

		// Completely unrelated domains.
		{"example.com", "", false},
		{"mycompany.io", "", false},
		{"localhost.dev", "", false},
		{"randomword123.com", "", false},
		{"abcdefghijklmnop.com", "", false},

		// Homoglyph-heavy substitutions.
		{"g0ogle.com", "google", true},   // single 0->o
		{"pa1pal.com", "paypal", true},    // 1->l plus y->missing? actually lev dist
		{"netf1ix.com", "netflix", true},  // 1->l

		// Deep subdomain with typo in the main part.
		{"www.micros0ft.com", "microsoft", true},

		// Short brand near-miss.
		{"slakc.com", "slack", true}, // transposition
	}
	for _, tt := range tests {
		t.Run("extra_"+tt.domain, func(t *testing.T) {
			brand, dist := CheckTyposquat(tt.domain)
			gotMatch := brand != ""
			if gotMatch != tt.wantMatch {
				t.Errorf("CheckTyposquat(%q): match=%v (brand=%q, dist=%d), wantMatch=%v",
					tt.domain, gotMatch, brand, dist, tt.wantMatch)
			}
			if tt.wantMatch && brand != tt.wantBrand {
				t.Errorf("CheckTyposquat(%q): brand=%q, want %q", tt.domain, brand, tt.wantBrand)
			}
		})
	}
}

func TestNormalizeHomoglyphs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"g00gle", "google"},
		{"paypa1", "paypal"},
		{"rnicrosoft", "microsoft"},
		{"amaz0n", "amazon"},
		{"g0og1e", "google"},         // mixed 0->o and 1->l (l->e is not a sub though)
		{"faceb00k", "facebook"},     // double 0->o
		{"vvindovvs", "windows"},     // vv->w twice
		{"app!e", "apple"},           // !->l
		{"netf1ix", "netflix"},       // 1->l
		{"@m@zon", "amazon"},         // @->a twice (first) but rest doesn't match; just testing replacement
		{"$lack", "slack"},           // $->s
		{"3bay", "ebay"},             // 3->e
		{"", ""},                     // empty string
		{"hello", "hello"},           // no substitutions needed
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHomoglyphs(tt.input)
			if got != tt.want {
				t.Errorf("normalizeHomoglyphs(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
