package stix

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/youredr/edr-backend/internal/models"
)

// tlpMarkingIDs maps TLP level to the STIX 2.1 marking-definition IDs.
var tlpMarkingIDs = map[string]string{
	"WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
	"GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
	"AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
	"RED":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

// ExportBundle builds a STIX 2.1 bundle from a slice of IOCs.
// tlp is the marking to apply to each indicator ("WHITE","GREEN","AMBER","RED").
func ExportBundle(iocs []models.IOC, tlp string) ([]byte, error) {
	if tlp == "" {
		tlp = "AMBER"
	}
	markingID, ok := tlpMarkingIDs[tlp]
	if !ok {
		markingID = tlpMarkingIDs["AMBER"]
	}

	var objects []json.RawMessage

	// Include the TLP marking definition itself.
	markingDef := map[string]interface{}{
		"type":          "marking-definition",
		"spec_version":  "2.1",
		"id":            markingID,
		"created":       "2017-01-20T00:00:00.000Z",
		"definition_type": "tlp",
		"definition": map[string]string{
			"tlp": strings.ToLower(tlp),
		},
	}
	mdBytes, _ := json.Marshal(markingDef)
	objects = append(objects, mdBytes)

	now := time.Now().UTC().Format(time.RFC3339)

	for _, ioc := range iocs {
		pattern, patternType := stixPattern(ioc)
		if pattern == "" {
			continue
		}

		indicator := map[string]interface{}{
			"type":                "indicator",
			"spec_version":        "2.1",
			"id":                  "indicator--" + uuid.New().String(),
			"created":             now,
			"modified":            now,
			"name":                fmt.Sprintf("[%s] %s", strings.ToUpper(ioc.Type), ioc.Value),
			"description":         ioc.Description,
			"pattern":             pattern,
			"pattern_type":        patternType,
			"valid_from":          ioc.CreatedAt.UTC().Format(time.RFC3339),
			"indicator_types":     []string{"malicious-activity"},
			"object_marking_refs": []string{markingID},
			"labels":              ioc.Tags,
		}
		if indicator["description"] == "" {
			delete(indicator, "description")
		}
		if len(ioc.Tags) == 0 {
			delete(indicator, "labels")
		}

		b, err := json.Marshal(indicator)
		if err != nil {
			continue
		}
		objects = append(objects, b)
	}

	bundle := map[string]interface{}{
		"type":         "bundle",
		"id":           "bundle--" + uuid.New().String(),
		"spec_version": "2.1",
		"objects":      objects,
	}
	return json.MarshalIndent(bundle, "", "  ")
}

func stixPattern(ioc models.IOC) (pattern, patternType string) {
	switch ioc.Type {
	case "ip":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", sanitize(ioc.Value)), "stix"
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", sanitize(ioc.Value)), "stix"
	case "hash_sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", sanitize(ioc.Value)), "stix"
	case "hash_md5":
		return fmt.Sprintf("[file:hashes.'MD5' = '%s']", sanitize(ioc.Value)), "stix"
	}
	return "", ""
}
