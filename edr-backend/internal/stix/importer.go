// internal/stix/importer.go
//
// Parses STIX 2.1 bundles and converts indicators to TraceGuard IOC records.
//
// Supported STIX object types:
//   indicator  — pattern parsed for ipv4-addr, domain-name, file hashes
//   malware    — name used as tag on matched indicators
//
// Pattern syntax supported (STIX 2.1 subset):
//   [ipv4-addr:value = '1.2.3.4']
//   [domain-name:value = 'evil.com']
//   [file:hashes.'SHA-256' = 'abc...']
//   [file:hashes.MD5 = 'abc...']

package stix

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/youredr/edr-backend/internal/models"
	"github.com/lib/pq"
)

// Bundle is a STIX 2.1 bundle.
type Bundle struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Objects []json.RawMessage `json:"objects"`
}

type stixObject struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidUntil  *time.Time `json:"valid_until"`
	Confidence  int       `json:"confidence"` // 0–100
	Labels      []string  `json:"labels"`
}

// ImportResult holds the converted IOCs and any per-object errors.
type ImportResult struct {
	BundleID string
	IOCs     []models.IOC
	Errors   []string
}

// Import parses a STIX 2.1 bundle JSON and returns converted IOCs.
func Import(data []byte, source string) (*ImportResult, error) {
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if bundle.Type != "bundle" {
		return nil, fmt.Errorf("expected STIX bundle, got %q", bundle.Type)
	}

	result := &ImportResult{BundleID: bundle.ID}

	for _, raw := range bundle.Objects {
		var obj stixObject
		if err := json.Unmarshal(raw, &obj); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("parse object: %v", err))
			continue
		}
		if obj.Type != "indicator" {
			continue
		}
		iocs, errs := parseIndicator(obj, source)
		result.IOCs = append(result.IOCs, iocs...)
		result.Errors = append(result.Errors, errs...)
	}

	return result, nil
}

var (
	reIPv4   = regexp.MustCompile(`ipv4-addr:value\s*=\s*'([^']+)'`)
	reDomain = regexp.MustCompile(`domain-name:value\s*=\s*'([^']+)'`)
	reSHA256 = regexp.MustCompile(`file:hashes\.'?SHA-?256'?\s*=\s*'([0-9a-fA-F]{64})'`)
	reMD5    = regexp.MustCompile(`file:hashes\.MD5\s*=\s*'([0-9a-fA-F]{32})'`)
	reSHA1   = regexp.MustCompile(`file:hashes\.'?SHA-?1'?\s*=\s*'([0-9a-fA-F]{40})'`)
)

func parseIndicator(obj stixObject, source string) ([]models.IOC, []string) {
	severity := confidenceToSeverity(obj.Confidence)
	tags := append([]string{"stix"}, obj.Labels...)
	var iocs []models.IOC
	var errs []string

	add := func(iocType, value string) {
		iocs = append(iocs, models.IOC{
			ID:          "stix-" + sanitize(obj.ID) + "-" + iocType,
			Type:        iocType,
			Value:       strings.ToLower(strings.TrimSpace(value)),
			Source:      source,
			Severity:    severity,
			Description: obj.Description,
			Tags:        pq.StringArray(tags),
			Enabled:     true,
			ExpiresAt:   obj.ValidUntil,
			CreatedAt:   obj.ValidFrom,
		})
	}

	p := obj.Pattern
	if m := reIPv4.FindStringSubmatch(p); len(m) == 2 {
		add("ip", m[1])
	}
	if m := reDomain.FindStringSubmatch(p); len(m) == 2 {
		add("domain", m[1])
	}
	if m := reSHA256.FindStringSubmatch(p); len(m) == 2 {
		add("hash_sha256", strings.ToLower(m[1]))
	}
	if m := reMD5.FindStringSubmatch(p); len(m) == 2 {
		add("hash_md5", strings.ToLower(m[1]))
	}
	if m := reSHA1.FindStringSubmatch(p); len(m) == 2 {
		add("hash_sha1", strings.ToLower(m[1]))
	}

	if len(iocs) == 0 && p != "" {
		errs = append(errs, fmt.Sprintf("indicator %s: no parseable pattern: %s", obj.ID, p))
	}
	return iocs, errs
}

func confidenceToSeverity(confidence int) int16 {
	switch {
	case confidence >= 85:
		return 4
	case confidence >= 60:
		return 3
	case confidence >= 30:
		return 2
	default:
		return 1
	}
}

func sanitize(s string) string {
	return strings.NewReplacer("--", "-", ":", "-").Replace(
		strings.ToLower(strings.TrimPrefix(s, "indicator--")))
}
