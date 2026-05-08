// internal/compliance/coverage.go
//
// Static mapping of detection rule IDs and MITRE technique IDs to
// NIST CSF 2.0, ISO 27001:2022, and PCI-DSS 4.0 controls.
// Generates a coverage report against the tenant's active rules.

package compliance

import (
	"context"
	"sort"
	"strings"

	"github.com/youredr/edr-backend/internal/models"
)

// Framework identifies a compliance framework.
type Framework string

const (
	FrameworkNIST   Framework = "nist-csf"
	FrameworkISO    Framework = "iso-27001"
	FrameworkPCIDSS Framework = "pci-dss"
)

// Control is a single compliance control.
type Control struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// CoverageItem is a control with coverage status.
type CoverageItem struct {
	Control
	Covered  bool     `json:"covered"`
	RuleIDs  []string `json:"rule_ids,omitempty"`
	MitreIDs []string `json:"mitre_ids,omitempty"`
}

// Report is the full coverage report for a framework.
type Report struct {
	Framework  Framework      `json:"framework"`
	Total      int            `json:"total"`
	Covered    int            `json:"covered"`
	Percentage int            `json:"percentage"`
	Controls   []CoverageItem `json:"controls"`
}

// ── NIST CSF 2.0 controls ─────────────────────────────────────────────────────

var nistControls = []Control{
	// Govern
	{"GV.OC-01", "Organizational context", "Govern", "Mission objectives, stakeholder expectations, and legal requirements"},
	{"GV.RM-01", "Risk management strategy", "Govern", "Risk appetite and tolerance statements"},
	// Identify
	{"ID.AM-01", "Asset inventory", "Identify", "IT and OT assets inventoried"},
	{"ID.AM-02", "Software inventory", "Identify", "Software platforms and applications inventoried"},
	{"ID.RA-01", "Vulnerability identification", "Identify", "Vulnerabilities identified and documented"},
	{"ID.RA-05", "Threat intelligence", "Identify", "Threats, vulnerabilities, likelihoods, and impacts used to understand inherent risk"},
	// Protect
	{"PR.AA-01", "Identity management", "Protect", "Identities and credentials managed"},
	{"PR.AA-05", "Access permissions", "Protect", "Access permissions managed, incorporating least privilege"},
	{"PR.DS-01", "Data-at-rest protection", "Protect", "Data-at-rest protected"},
	{"PR.DS-02", "Data-in-transit protection", "Protect", "Data-in-transit protected"},
	{"PR.IR-01", "Network integrity", "Protect", "Networks and environments protected from unauthorized access"},
	{"PR.PS-01", "Configuration management", "Protect", "Configurations established and maintained"},
	// Detect
	{"DE.AE-02", "Event analysis", "Detect", "Potentially adverse events analyzed to better characterize them"},
	{"DE.AE-03", "Event aggregation", "Detect", "Information is correlated from multiple sources"},
	{"DE.AE-06", "Alert generation", "Detect", "Information on adverse events is provided to authorized staff"},
	{"DE.CM-01", "Network monitoring", "Detect", "Networks monitored to detect potential adverse events"},
	{"DE.CM-03", "User activity monitoring", "Detect", "User activity monitored to detect potential adverse events"},
	{"DE.CM-06", "External service monitoring", "Detect", "External service provider activities monitored"},
	{"DE.CM-09", "Computing hardware monitoring", "Detect", "Computing hardware and software monitored"},
	// Respond
	{"RS.AN-03", "Incident analysis", "Respond", "Analysis performed to establish what occurred and why"},
	{"RS.AN-06", "Actions documented", "Respond", "Actions performed during investigation documented"},
	{"RS.CO-02", "Incident reporting", "Respond", "Incidents reported to appropriate authorities"},
	{"RS.MI-01", "Incident containment", "Respond", "Incidents contained"},
	{"RS.MI-02", "Incident eradication", "Respond", "Incidents eradicated"},
	// Recover
	{"RC.RP-01", "Recovery plan", "Recover", "Recovery plan executed during or after incident"},
}

// ── ISO 27001:2022 controls ───────────────────────────────────────────────────

var isoControls = []Control{
	{"5.7",  "Threat intelligence",               "Organizational", "Information about threats collected and analyzed"},
	{"5.25", "Information security incident mgmt","Organizational", "Incident management policies and responsibilities"},
	{"5.26", "Response to incidents",             "Organizational", "Incidents responded to in accordance with procedures"},
	{"5.28", "Evidence collection",               "Organizational", "Evidence identified, collected, acquired, and preserved"},
	{"6.8",  "Information security event reporting","People",       "Incidents and weaknesses reported through appropriate channels"},
	{"8.7",  "Malware protection",                "Technological",  "Protection against malware implemented and supported by appropriate user awareness"},
	{"8.8",  "Management of technical vulnerabilities","Technological","Technical vulnerabilities managed"},
	{"8.15", "Logging",                           "Technological",  "Logs produced, stored, protected, and analyzed"},
	{"8.16", "Monitoring activities",             "Technological",  "Networks, systems and applications monitored"},
	{"8.22", "Network segregation",               "Technological",  "Groups of information services, users, and systems segregated"},
	{"8.23", "Web filtering",                     "Technological",  "Access to external websites managed to reduce risk"},
}

// ── PCI-DSS 4.0 controls ─────────────────────────────────────────────────────

var pciControls = []Control{
	{"1.3",  "Network access controls",      "Network Security",        "Network access to and from the cardholder data environment is restricted"},
	{"5.2",  "Malware protection",           "Vulnerability Management", "Malware prevention mechanisms deployed and maintained"},
	{"5.3",  "Anti-malware active",          "Vulnerability Management", "Anti-malware mechanisms active, maintained, and monitored"},
	{"6.3",  "Security vulnerabilities",     "Software Development",    "Security vulnerabilities identified and addressed"},
	{"10.2", "Audit log generation",         "Logging & Monitoring",    "Audit logs that capture user activities and events created"},
	{"10.3", "Audit log protection",         "Logging & Monitoring",    "Audit logs protected from destruction and unauthorized modifications"},
	{"10.4", "Audit log review",             "Logging & Monitoring",    "Audit logs reviewed to identify anomalies or suspicious activity"},
	{"10.7", "Failure detection",            "Logging & Monitoring",    "Failures of critical security controls detected, reported, and responded to"},
	{"11.4", "Penetration testing",          "Testing",                 "External and internal penetration testing regularly performed"},
	{"11.5", "Intrusion detection",          "Testing",                 "Intrusion-detection or intrusion-prevention techniques detect and/or prevent intrusions"},
	{"12.10","Incident response plan",       "Incident Response",       "Suspected and confirmed security incidents responded to immediately"},
}

// ── MITRE → framework control mapping ────────────────────────────────────────

// mitreToNIST maps MITRE technique prefixes to NIST CSF control IDs.
var mitreToNIST = map[string][]string{
	"T1059": {"DE.CM-09", "DE.AE-02"},       // Command and Scripting Interpreter
	"T1055": {"DE.CM-09", "DE.AE-02"},       // Process Injection
	"T1027": {"DE.CM-09"},                   // Obfuscated Files
	"T1003": {"DE.CM-03", "PR.AA-01"},       // Credential Dumping
	"T1078": {"PR.AA-01", "PR.AA-05", "DE.CM-03"}, // Valid Accounts
	"T1021": {"DE.CM-01", "PR.IR-01"},       // Remote Services
	"T1046": {"DE.CM-01"},                   // Network Service Scanning
	"T1048": {"DE.CM-01", "DE.AE-02"},       // Exfiltration
	"T1041": {"DE.CM-01"},                   // Exfiltration Over C2
	"T1566": {"DE.CM-09", "DE.AE-02"},       // Phishing
	"T1204": {"DE.CM-09"},                   // User Execution
	"T1083": {"DE.CM-09"},                   // File and Directory Discovery
	"T1082": {"DE.CM-09", "ID.AM-01"},       // System Info Discovery
	"T1190": {"DE.CM-01", "ID.RA-01"},       // Exploit Public-Facing App
	"T1550": {"PR.AA-01", "DE.CM-03"},       // Use Alternate Auth Material
}

var mitreToISO = map[string][]string{
	"T1059": {"8.7", "8.16"},
	"T1055": {"8.7", "8.16"},
	"T1078": {"8.15", "8.16"},
	"T1021": {"8.22", "8.16"},
	"T1046": {"8.22", "8.16"},
	"T1048": {"8.22", "8.7"},
	"T1566": {"8.7"},
	"T1190": {"8.8", "8.16"},
	"T1003": {"8.15", "8.16"},
	"T1550": {"8.15", "8.16"},
}

var mitreToPCI = map[string][]string{
	"T1059": {"5.2", "5.3", "10.2"},
	"T1055": {"5.2", "5.3"},
	"T1078": {"10.2", "10.4"},
	"T1021": {"1.3", "11.5"},
	"T1046": {"1.3", "11.5"},
	"T1048": {"1.3", "10.4"},
	"T1003": {"10.2", "10.4"},
	"T1190": {"1.3", "6.3"},
	"T1550": {"10.2", "10.4"},
	"T1566": {"5.2", "5.3"},
}

// ruleToNIST maps specific rule IDs to additional NIST CSF controls.
var ruleToNIST = map[string][]string{
	"rule-lateral-movement":      {"DE.CM-01", "DE.CM-03", "RS.MI-01"},
	"rule-port-scan":             {"DE.CM-01", "DE.AE-02"},
	"rule-data-exfil":            {"DE.CM-01", "RS.AN-03"},
	"rule-host-process-anomaly":  {"DE.CM-09", "DE.AE-02"},
	"rule-dns-tunnel":            {"DE.CM-01"},
	"rule-ransomware":            {"DE.CM-09", "RS.MI-01", "RS.MI-02"},
}

// ── Coverage calculator ────────────────────────────────────────────────────────

type RuleStore interface {
	ListRules(ctx context.Context, tenantID string) ([]models.Rule, error)
}

// Generate produces a coverage report for the given framework, using the
// tenant's enabled detection rules as the coverage source.
func Generate(ctx context.Context, st RuleStore, tenantID string, fw Framework) (*Report, error) {
	rules, err := st.ListRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var controls []Control
	var mitreMap map[string][]string
	var ruleMap map[string][]string

	switch fw {
	case FrameworkISO:
		controls = isoControls
		mitreMap = mitreToISO
		ruleMap = nil
	case FrameworkPCIDSS:
		controls = pciControls
		mitreMap = mitreToPCI
		ruleMap = nil
	default:
		controls = nistControls
		mitreMap = mitreToNIST
		ruleMap = ruleToNIST
	}

	// Build reverse index: controlID → {ruleIDs, mitreIDs}
	type entry struct {
		rules  map[string]struct{}
		mitres map[string]struct{}
	}
	index := map[string]*entry{}
	ensure := func(cid string) *entry {
		if index[cid] == nil {
			index[cid] = &entry{rules: map[string]struct{}{}, mitres: map[string]struct{}{}}
		}
		return index[cid]
	}

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		// Rule-ID direct mapping
		if ruleMap != nil {
			for _, cid := range ruleMap[rule.ID] {
				e := ensure(cid)
				e.rules[rule.ID] = struct{}{}
			}
		}
		// MITRE-based mapping
		for _, mid := range rule.MitreIDs {
			prefix := mitrePrefix(mid)
			for _, cid := range mitreMap[prefix] {
				e := ensure(cid)
				e.rules[rule.ID] = struct{}{}
				e.mitres[mid] = struct{}{}
			}
		}
	}

	items := make([]CoverageItem, 0, len(controls))
	coveredCount := 0
	for _, ctrl := range controls {
		item := CoverageItem{Control: ctrl}
		if e, ok := index[ctrl.ID]; ok {
			item.Covered = true
			coveredCount++
			for r := range e.rules {
				item.RuleIDs = append(item.RuleIDs, r)
			}
			for m := range e.mitres {
				item.MitreIDs = append(item.MitreIDs, m)
			}
			sort.Strings(item.RuleIDs)
			sort.Strings(item.MitreIDs)
		}
		items = append(items, item)
	}

	pct := 0
	if len(controls) > 0 {
		pct = coveredCount * 100 / len(controls)
	}

	return &Report{
		Framework:  fw,
		Total:      len(controls),
		Covered:    coveredCount,
		Percentage: pct,
		Controls:   items,
	}, nil
}

func mitrePrefix(mid string) string {
	// Normalize T1234.001 → T1234
	mid = strings.ToUpper(strings.TrimSpace(mid))
	if idx := strings.IndexByte(mid, '.'); idx != -1 {
		return mid[:idx]
	}
	return mid
}
