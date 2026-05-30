// internal/yara/engine.go
//
// Pure-Go YARA subset engine — no CGO, no libyara dependency.
//
// Supported rule features:
//   - String patterns:  ascii (default), wide (UTF-16LE), nocase, fullword
//   - Hex patterns:     { AA BB ?? CC } with single-byte wildcards
//   - Regex patterns:   /pattern/flags  (uses Go's regexp package)
//   - Conditions:       any of them | all of them | N of them | $name [and $name2...]
//   - Meta:             description, author, severity (parsed but informational only)
//
// Unsupported (silently ignored): rule imports, external variables, pe/elf modules,
// at/in offsets, for-of loops, entrypoint.

package yara

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MatchResult describes one YARA rule that matched a file.
type MatchResult struct {
	RuleName      string
	MatchedStrings []string // names of the string variables that matched
}

// Engine holds compiled YARA rules ready for scanning.
type Engine struct {
	rules []*compiledRule
}

type compiledRule struct {
	name      string
	meta      map[string]string
	patterns  []*pattern
	condition conditionExpr
}

type patternType int

const (
	patternString patternType = iota
	patternHex
	patternRegex
)

type pattern struct {
	name     string // e.g. "$s1"
	kind     patternType
	// string/wide patterns
	ascii    []byte
	wide     []byte
	nocase   bool
	fullword bool
	// hex pattern: sequence of (byte value, wildcard bool)
	hexBytes []hexByte
	// regex
	re *regexp.Regexp
}

type hexByte struct {
	val      byte
	wildcard bool
}

// conditionExpr evaluates whether a rule should fire.
type conditionExpr interface {
	eval(matched map[string]bool) bool
}

type condAny struct{}
type condAll struct{}
type condN struct{ n int }
type condAnd struct{ names []string }

func (c condAny) eval(m map[string]bool) bool {
	for _, v := range m { if v { return true } }
	return false
}
func (c condAll) eval(m map[string]bool) bool {
	for _, v := range m { if !v { return false } }
	return len(m) > 0
}
func (c condN) eval(m map[string]bool) bool {
	n := 0
	for _, v := range m { if v { n++ } }
	return n >= c.n
}
func (c condAnd) eval(m map[string]bool) bool {
	for _, name := range c.names {
		if !m[name] { return false }
	}
	return true
}

// New compiles a slice of YARA rule sources into an Engine.
// Invalid rules are skipped with a warning; compilation continues.
func New(ruleTexts []string) (*Engine, []error) {
	e := &Engine{}
	var errs []error
	for _, txt := range ruleTexts {
		cr, err := compileRule(txt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		e.rules = append(e.rules, cr)
	}
	return e, errs
}

// ScanBytes runs all compiled rules against the provided byte slice.
func (e *Engine) ScanBytes(data []byte) []MatchResult {
	var results []MatchResult
	for _, cr := range e.rules {
		matched := make(map[string]bool, len(cr.patterns))
		matchedNames := []string{}
		for _, p := range cr.patterns {
			if matchPattern(p, data) {
				matched[p.name] = true
				matchedNames = append(matchedNames, p.name)
			} else {
				matched[p.name] = false
			}
		}
		if cr.condition.eval(matched) {
			results = append(results, MatchResult{
				RuleName:       cr.name,
				MatchedStrings: matchedNames,
			})
		}
	}
	return results
}

// RuleCount returns the number of successfully compiled rules.
func (e *Engine) RuleCount() int { return len(e.rules) }

// ─── Compiler ─────────────────────────────────────────────────────────────────

func compileRule(src string) (*compiledRule, error) {
	src = strings.TrimSpace(src)
	// Find "rule <Name>" header.
	ruleIdx := strings.Index(src, "rule ")
	if ruleIdx < 0 {
		return nil, fmt.Errorf("no rule keyword found")
	}
	after := strings.TrimSpace(src[ruleIdx+5:])
	// Rule name ends at '{' or ':'
	nameEnd := strings.IndexAny(after, "{:")
	if nameEnd < 0 {
		return nil, fmt.Errorf("malformed rule header")
	}
	name := strings.TrimSpace(after[:nameEnd])

	// Find the rule body between the outermost { }.
	bodyStart := strings.Index(src, "{")
	bodyEnd := strings.LastIndex(src, "}")
	if bodyStart < 0 || bodyEnd <= bodyStart {
		return nil, fmt.Errorf("rule %q: missing braces", name)
	}
	body := src[bodyStart+1 : bodyEnd]

	cr := &compiledRule{name: name, meta: map[string]string{}}

	// Parse sections.
	sections := splitSections(body)
	for secName, secBody := range sections {
		switch secName {
		case "meta":
			parseMeta(secBody, cr.meta)
		case "strings":
			pats, err := parseStrings(secBody)
			if err != nil {
				return nil, fmt.Errorf("rule %q strings: %w", name, err)
			}
			cr.patterns = pats
		case "condition":
			cr.condition = parseCondition(strings.TrimSpace(secBody), cr.patterns)
		}
	}
	if cr.condition == nil {
		cr.condition = condAny{}
	}
	return cr, nil
}

// splitSections returns a map of section name → content for meta/strings/condition.
func splitSections(body string) map[string]string {
	sections := map[string]string{}
	sectionNames := []string{"meta", "strings", "condition"}
	lower := strings.ToLower(body)
	positions := []struct{ name string; pos int }{}
	for _, sn := range sectionNames {
		if i := strings.Index(lower, sn+":"); i >= 0 {
			positions = append(positions, struct{ name string; pos int }{sn, i})
		}
	}
	// Sort by position.
	for i := 1; i < len(positions); i++ {
		for j := i; j > 0 && positions[j].pos < positions[j-1].pos; j-- {
			positions[j], positions[j-1] = positions[j-1], positions[j]
		}
	}
	for i, p := range positions {
		start := p.pos + len(p.name) + 1
		var end int
		if i+1 < len(positions) {
			end = positions[i+1].pos
		} else {
			end = len(body)
		}
		sections[p.name] = body[start:end]
	}
	return sections
}

func parseMeta(body string, meta map[string]string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if eq := strings.Index(line, "="); eq > 0 {
			k := strings.TrimSpace(line[:eq])
			v := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
			meta[k] = v
		}
	}
}

func parseStrings(body string) ([]*pattern, error) {
	var patterns []*pattern
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		rest := strings.TrimSpace(line[eq+1:])
		if !strings.HasPrefix(name, "$") {
			continue
		}

		p := &pattern{name: name}
		if strings.HasPrefix(rest, "{") {
			// Hex pattern.
			p.kind = patternHex
			end := strings.Index(rest, "}")
			if end < 0 {
				return nil, fmt.Errorf("unclosed hex pattern for %s", name)
			}
			hb, err := parseHexPattern(rest[1:end])
			if err != nil {
				return nil, fmt.Errorf("hex pattern %s: %w", name, err)
			}
			p.hexBytes = hb
		} else if strings.HasPrefix(rest, "/") {
			// Regex pattern.
			p.kind = patternRegex
			end := strings.LastIndex(rest, "/")
			if end <= 0 {
				return nil, fmt.Errorf("unclosed regex for %s", name)
			}
			flags := rest[end+1:]
			pattern := rest[1:end]
			if strings.Contains(flags, "i") {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("regex %s: %w", name, err)
			}
			p.re = re
		} else {
			// String pattern.
			p.kind = patternString
			parts := strings.Fields(rest)
			if len(parts) == 0 {
				continue
			}
			raw := parts[0]
			mods := parts[1:]
			for _, m := range mods {
				switch m {
				case "nocase":
					p.nocase = true
				case "wide":
					// wide means UTF-16LE encoding
				case "fullword":
					p.fullword = true
				}
			}
			// Unquote the string value.
			unquoted, err := strconv.Unquote(raw)
			if err != nil {
				// Try as-is if not quoted.
				unquoted = strings.Trim(raw, `"`)
			}
			if p.nocase {
				unquoted = strings.ToLower(unquoted)
			}
			p.ascii = []byte(unquoted)
			// Compute wide (UTF-16LE) version.
			runes := []rune(unquoted)
			u16 := utf16.Encode(runes)
			wide := make([]byte, len(u16)*2)
			for i, r := range u16 {
				wide[i*2] = byte(r)
				wide[i*2+1] = byte(r >> 8)
			}
			p.wide = wide
			// Check for wide modifier.
			for _, m := range mods {
				if m == "wide" {
					// Only use wide bytes; ascii cleared unless "ascii" also present.
					p.ascii = nil
					for _, m2 := range mods {
						if m2 == "ascii" {
							p.ascii = []byte(unquoted)
						}
					}
					p.wide = wide
				}
			}
			if p.ascii == nil && p.wide == nil {
				p.ascii = []byte(unquoted)
			}
		}
		patterns = append(patterns, p)
	}
	return patterns, nil
}

func parseHexPattern(s string) ([]hexByte, error) {
	tokens := strings.Fields(s)
	var result []hexByte
	for _, tok := range tokens {
		if tok == "??" {
			result = append(result, hexByte{wildcard: true})
		} else if len(tok) == 2 {
			b, err := hex.DecodeString(tok)
			if err != nil {
				return nil, err
			}
			result = append(result, hexByte{val: b[0]})
		}
		// Ignore other tokens (comments, alternation — advanced features).
	}
	return result, nil
}

func parseCondition(cond string, patterns []*pattern) conditionExpr {
	lower := strings.ToLower(strings.TrimSpace(cond))
	switch {
	case lower == "any of them":
		return condAny{}
	case lower == "all of them":
		return condAll{}
	case strings.HasPrefix(lower, "any of ("):
		return condAny{}
	case strings.HasPrefix(lower, "all of ("):
		return condAll{}
	default:
		// Try "N of them".
		if strings.HasSuffix(lower, "of them") {
			parts := strings.Fields(lower)
			if len(parts) >= 1 {
				n, err := strconv.Atoi(parts[0])
				if err == nil {
					return condN{n: n}
				}
			}
		}
		// Try "$name and $name2 ..." style.
		if strings.Contains(cond, "$") {
			names := extractVarNames(cond)
			if len(names) > 0 {
				return condAnd{names: names}
			}
		}
		// Default to any of them.
		return condAny{}
	}
}

func extractVarNames(cond string) []string {
	var names []string
	words := strings.Fields(cond)
	for _, w := range words {
		if strings.HasPrefix(w, "$") {
			names = append(names, strings.TrimRight(w, ","))
		}
	}
	return names
}

// ─── Matcher ──────────────────────────────────────────────────────────────────

func matchPattern(p *pattern, data []byte) bool {
	switch p.kind {
	case patternRegex:
		return p.re != nil && p.re.Match(data)
	case patternHex:
		return matchHex(p.hexBytes, data)
	case patternString:
		haystack := data
		if p.nocase {
			lower := make([]byte, len(data))
			for i, b := range data {
				if b >= 'A' && b <= 'Z' {
					lower[i] = b + 32
				} else {
					lower[i] = b
				}
			}
			haystack = lower
		}
		if p.ascii != nil && len(p.ascii) > 0 {
			if p.fullword {
				if findFullword(haystack, p.ascii) {
					return true
				}
			} else if contains(haystack, p.ascii) {
				return true
			}
		}
		if p.wide != nil && len(p.wide) > 0 {
			if contains(data, p.wide) {
				return true
			}
		}
	}
	return false
}

// contains is a simple byte-slice search (Boyer-Moore not needed for our scale).
func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i] == needle[0] {
			match := true
			for j := 1; j < len(needle); j++ {
				if haystack[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func findFullword(haystack, needle []byte) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i] != needle[0] {
			continue
		}
		match := true
		for j := 1; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		// Check word boundaries.
		before := i == 0 || !isWordChar(haystack[i-1])
		after := i+len(needle) >= len(haystack) || !isWordChar(haystack[i+len(needle)])
		if before && after {
			return true
		}
	}
	return false
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

func matchHex(pattern []hexByte, data []byte) bool {
	if len(pattern) == 0 {
		return false
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j, hb := range pattern {
			if !hb.wildcard && data[i+j] != hb.val {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
