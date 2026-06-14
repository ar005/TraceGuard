// internal/sigma/importer.go
//
// Converts Sigma YAML rules to TraceGuard Rule JSON.
//
// Supported Sigma constructs → TraceGuard mapping:
//   detection.keywords / selection    → match conditions (field:value)
//   detection.condition: 1 of them   → any-match (OR conditions)
//   detection.condition: all of them → all-match (AND conditions)
//   level: critical/high/medium/low  → severity 4/3/2/1
//   logsource.category               → event_types
//   tags: attack.TxNNN               → mitre_ids
//
// Unsupported constructs (pipes, near, ...) are skipped with a warning.

package sigma

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/lib/pq"
)

// SigmaRule is a minimal parse of the Sigma YAML schema.
type SigmaRule struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Status      string                 `yaml:"status"`
	Description string                 `yaml:"description"`
	Author      string                 `yaml:"author"`
	Level       string                 `yaml:"level"` // critical, high, medium, low
	Tags        []string               `yaml:"tags"`
	Logsource   SigmaLogsource         `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
	FalsePositives []string            `yaml:"falsepositives"`
}

type SigmaLogsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// ImportResult is returned per converted rule.
type ImportResult struct {
	Rule  *models.Rule
	Error string
}

// Import converts Sigma YAML (one or more documents) to TraceGuard rules.
// Multiple rules may be separated by `---` YAML document boundaries.
func Import(yamlBytes []byte) []ImportResult {
	var results []ImportResult
	// Split on YAML document separators.
	docs := strings.Split(string(yamlBytes), "\n---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" || strings.TrimPrefix(doc, "---") == "" {
			continue
		}
		var sr SigmaRule
		if err := yaml.Unmarshal([]byte(doc), &sr); err != nil {
			results = append(results, ImportResult{Error: fmt.Sprintf("yaml parse: %v", err)})
			continue
		}
		if sr.Title == "" {
			continue
		}
		rule, err := convert(&sr)
		if err != nil {
			results = append(results, ImportResult{Error: fmt.Sprintf("rule %q: %v", sr.Title, err)})
			continue
		}
		results = append(results, ImportResult{Rule: rule})
	}
	return results
}

func convert(sr *SigmaRule) (*models.Rule, error) {
	id := "sigma-" + sanitizeID(sr.ID)
	if sr.ID == "" {
		id = "sigma-" + sanitizeID(sr.Title)
	}

	severity := levelToSeverity(sr.Level)
	mitreIDs := extractMitre(sr.Tags)
	eventTypes := logsourceToEventTypes(sr.Logsource)
	conditions, err := buildConditions(sr.Detection)
	if err != nil {
		return nil, err
	}

	condJSON, err := json.Marshal(conditions)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &models.Rule{
		ID:          id,
		Name:        sr.Title,
		Description: sr.Description,
		Enabled:     sr.Status == "stable" || sr.Status == "test" || sr.Status == "",
		Severity:    severity,
		EventTypes:  pq.StringArray(eventTypes),
		Conditions:  json.RawMessage(condJSON),
		MitreIDs:    pq.StringArray(mitreIDs),
		Author:      sr.Author,
		RuleType:    "match",
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func levelToSeverity(level string) int16 {
	switch strings.ToLower(level) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func extractMitre(tags []string) []string {
	var ids []string
	for _, t := range tags {
		t = strings.TrimPrefix(t, "attack.")
		if strings.HasPrefix(strings.ToUpper(t), "T") && len(t) >= 5 {
			ids = append(ids, strings.ToUpper(t))
		}
	}
	return ids
}

func logsourceToEventTypes(ls SigmaLogsource) []string {
	switch strings.ToLower(ls.Category) {
	case "process_creation", "process-creation":
		return []string{"PROCESS_EXEC"}
	case "network_connection", "network-connection":
		return []string{"NETWORK_CONN"}
	case "file_event", "file-event", "file_creation":
		return []string{"FILE_CREATE", "FILE_WRITE"}
	case "dns_query", "dns-query":
		return []string{"DNS_QUERY"}
	case "image_load", "image-load":
		return []string{"MODULE_LOAD"}
	default:
		if ls.Product == "windows" {
			return []string{"WINDOWS_EVENT"}
		}
		return []string{"ANY"}
	}
}

// buildConditions converts a Sigma `detection:` block into TraceGuard rule
// conditions, honouring the `condition:` expression for AND/OR semantics.
//
//   - `all of them` / absent / "selA and selB"   → AND (flat conditions list).
//   - `1 of them` / "any of *" / "selA or selB"  → OR (single RuleCondition
//     whose Any field holds one AND-group per selection).
//
// Top-level keyword lists (Sigma `keywords:` etc.) are OR'd against
// `process.cmdline` per Sigma semantics, regardless of the outer expression.
func buildConditions(detection map[string]interface{}) ([]models.RuleCondition, error) {
	conditionExpr := ""
	if c, ok := detection["condition"]; ok {
		conditionExpr = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", c)))
	}

	// Collect each selection's AND-group, keyed by selection name.
	type selection struct {
		name  string
		group []models.RuleCondition
	}
	var selections []selection
	for key, val := range detection {
		if key == "condition" || key == "timeframe" || key == "fields" {
			continue
		}
		group := selectionToConditions(val)
		if len(group) > 0 {
			selections = append(selections, selection{name: strings.ToLower(key), group: group})
		}
	}

	if len(selections) == 0 {
		return nil, fmt.Errorf("no translatable conditions")
	}

	// Decide how to combine multiple selections.
	isOR := false
	switch {
	case strings.Contains(conditionExpr, " or "):
		isOR = true
	case strings.HasPrefix(conditionExpr, "1 of "),
		strings.HasPrefix(conditionExpr, "any of "):
		isOR = true
	}

	if isOR && len(selections) > 1 {
		groups := make([][]models.RuleCondition, 0, len(selections))
		for _, s := range selections {
			groups = append(groups, s.group)
		}
		return []models.RuleCondition{{Any: groups}}, nil
	}

	// AND across selections (default / "all of them" / "selA and selB").
	var out []models.RuleCondition
	for _, s := range selections {
		out = append(out, s.group...)
	}
	return out, nil
}

// selectionToConditions builds the AND-group for a single Sigma selection.
// A map selection becomes one condition per field (each one a leaf or, for
// list-valued fields, an "in" leaf). A list selection (keywords) becomes a
// single OR-group of contains-leaves against process.cmdline.
func selectionToConditions(val interface{}) []models.RuleCondition {
	switch v := val.(type) {
	case map[string]interface{}:
		var out []models.RuleCondition
		for field, fval := range v {
			if c := fieldCondition(field, fval); c != nil {
				out = append(out, *c)
			}
		}
		return out
	case []interface{}:
		var leaves []models.RuleCondition
		for _, kw := range v {
			if s, ok := kw.(string); ok {
				leaves = append(leaves, models.RuleCondition{
					Field: "process.cmdline",
					Op:    "contains",
					Value: s,
				})
			}
		}
		if len(leaves) == 0 {
			return nil
		}
		if len(leaves) == 1 {
			return leaves
		}
		// Multiple keywords are OR'd per Sigma semantics.
		groups := make([][]models.RuleCondition, 0, len(leaves))
		for _, l := range leaves {
			groups = append(groups, []models.RuleCondition{l})
		}
		return []models.RuleCondition{{Any: groups}}
	}
	return nil
}

func fieldCondition(field string, val interface{}) *models.RuleCondition {
	// Sigma field modifiers: field|contains, field|endswith, field|startswith
	op := "eq"
	if strings.Contains(field, "|") {
		parts := strings.SplitN(field, "|", 2)
		field = parts[0]
		switch parts[1] {
		case "contains":
			op = "contains"
		case "startswith":
			op = "startswith"
		case "endswith":
			op = "endswith"
		case "re", "regex":
			op = "regex"
		default:
			op = "contains"
		}
	}

	// Map Sigma field names to TraceGuard event field paths.
	field = sigmaFieldMap(field)

	switch v := val.(type) {
	case string:
		return &models.RuleCondition{Field: field, Op: op, Value: v}
	case []interface{}:
		// Multi-value Sigma field: each value is OR'd. For "eq" we use the
		// "in" operator (set membership); for substring-style modifiers we
		// have to expand into an Any-group of single-value leaves so each
		// value is checked with its modifier.
		var vals []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				vals = append(vals, s)
			}
		}
		if len(vals) == 0 {
			return nil
		}
		if op == "eq" {
			return &models.RuleCondition{Field: field, Op: "in", Value: vals}
		}
		if len(vals) == 1 {
			return &models.RuleCondition{Field: field, Op: op, Value: vals[0]}
		}
		groups := make([][]models.RuleCondition, 0, len(vals))
		for _, s := range vals {
			groups = append(groups, []models.RuleCondition{{Field: field, Op: op, Value: s}})
		}
		return &models.RuleCondition{Any: groups}
	}
	return nil
}

func sigmaFieldMap(f string) string {
	m := map[string]string{
		"Image":              "process.exe",
		"CommandLine":        "process.cmdline",
		"ParentImage":        "process.parent_exe",
		"OriginalFileName":   "process.exe",
		"DestinationIp":      "net.dst_ip",
		"DestinationPort":    "net.dst_port",
		"SourceIp":           "net.src_ip",
		"Initiated":          "net.initiated",
		"TargetFilename":     "file.path",
		"TargetObject":       "registry.key",
		"QueryName":          "dns.query",
		"EventID":            "event.id",
		"ServiceName":        "service.name",
	}
	if mapped, ok := m[f]; ok {
		return mapped
	}
	return strings.ToLower(f)
}

func sanitizeID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
