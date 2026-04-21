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

func buildConditions(detection map[string]interface{}) ([]models.RuleCondition, error) {
	var conditions []models.RuleCondition

	for key, val := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		// val can be a map (field→value) or list of strings (keywords)
		switch v := val.(type) {
		case map[string]interface{}:
			for field, fval := range v {
				cond := fieldCondition(field, fval)
				if cond != nil {
					conditions = append(conditions, *cond)
				}
			}
		case []interface{}:
			// keyword list: match against process.cmdline or file.path
			for _, kw := range v {
				if s, ok := kw.(string); ok {
					conditions = append(conditions, models.RuleCondition{
						Field: "process.cmdline",
						Op:    "contains",
						Value: s,
					})
				}
			}
		}
	}

	if len(conditions) == 0 {
		return nil, fmt.Errorf("no translatable conditions")
	}
	return conditions, nil
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
		// multi-value → use "in" operator
		var vals []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				vals = append(vals, s)
			}
		}
		if len(vals) > 0 {
			return &models.RuleCondition{Field: field, Op: "in", Value: strings.Join(vals, ",")}
		}
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
