package detection

import (
	"strings"
)

// Known brand domains to protect against typosquatting.
// Only the base domain (no TLD) -- we match against any TLD.
var brandDomains = []string{
	"google", "microsoft", "apple", "amazon", "facebook", "netflix",
	"paypal", "instagram", "twitter", "linkedin", "github", "dropbox",
	"spotify", "yahoo", "outlook", "office365", "icloud", "adobe",
	"salesforce", "slack", "zoom", "whatsapp", "telegram", "signal",
	"chase", "bankofamerica", "wellsfargo", "citibank", "capitalone",
	"americanexpress", "visa", "mastercard",
}

// LevenshteinDistance computes the edit distance between two strings using
// the standard dynamic-programming algorithm.
func LevenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use a single row + prev variable to save memory.
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		cur := make([]int, lb+1)
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			ins := cur[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost
			min := ins
			if del < min {
				min = del
			}
			if sub < min {
				min = sub
			}
			cur[j] = min
		}
		prev = cur
	}
	return prev[lb]
}

// CheckTyposquat checks if a domain looks like a typosquat of a known brand.
// Returns the matched brand name and edit distance, or ("", 0) if no match.
func CheckTyposquat(domain string) (brand string, distance int) {
	// Strip www. prefix.
	domain = strings.TrimPrefix(domain, "www.")

	// Extract the domain name without TLD: take everything before the first dot.
	name := domain
	if idx := strings.Index(domain, "."); idx > 0 {
		name = domain[:idx]
	}
	name = strings.ToLower(name)

	// Normalize common character substitutions for a secondary check.
	normalized := normalizeHomoglyphs(name)

	bestDist := 999
	bestBrand := ""

	for _, b := range brandDomains {
		// Exact match on the raw name means it IS the real brand -- not a typosquat.
		if name == b {
			return "", 0
		}

		dist := LevenshteinDistance(name, b)
		if dist >= 1 && dist <= 2 && dist < bestDist {
			bestDist = dist
			bestBrand = b
		}

		// If the normalized form matches (or is very close to) the brand but
		// the raw name does NOT, this is a homoglyph-based typosquat
		// (e.g., g00gle -> google, paypa1 -> paypal).
		if normalized != name {
			ndist := LevenshteinDistance(normalized, b)
			if ndist <= 1 && dist < bestDist {
				bestDist = dist
				bestBrand = b
			}
		}
	}

	if bestBrand != "" {
		return bestBrand, bestDist
	}
	return "", 0
}

// normalizeHomoglyphs replaces common lookalike characters with their
// intended ASCII equivalents.
func normalizeHomoglyphs(s string) string {
	r := strings.NewReplacer(
		"0", "o",
		"1", "l",
		"!", "l",
		"@", "a",
		"$", "s",
		"3", "e",
		"5", "s",
	)
	result := r.Replace(s)
	// Common multi-char substitutions.
	result = strings.ReplaceAll(result, "rn", "m")
	result = strings.ReplaceAll(result, "vv", "w")
	return result
}
