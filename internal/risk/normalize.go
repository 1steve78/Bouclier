package risk

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"bouclier/internal/heuristics"
)

const (
	SourceURL          = "url"
	SourceDomain       = "domain"
	SourceRegistration = "registration"
	SourceTLS          = "tls-certificate"
	SourceWeb          = "web"
)

// NormalizeFindings maps observations through the catalog, retains unknown
// codes as unclassified, and merges only identical (target, code, evidence)
// observations. Different evidence under one code remains distinct.
func NormalizeFindings(observations []Observation, target string) ([]NormalizedFinding, error) {
	canonical, err := canonicalTarget(target)
	if err != nil {
		return nil, err
	}
	ordered := append([]Observation(nil), observations...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if evidenceKey(left.Evidence) != evidenceKey(right.Evidence) {
			return evidenceKey(left.Evidence) < evidenceKey(right.Evidence)
		}
		if left.Evidence != right.Evidence {
			return left.Evidence < right.Evidence
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Title != right.Title {
			return left.Title < right.Title
		}
		if left.Description != right.Description {
			return left.Description < right.Description
		}
		return left.Category < right.Category
	})
	byKey := make(map[string]int, len(ordered))
	findings := make([]NormalizedFinding, 0, len(ordered))
	for _, observation := range ordered {
		code := strings.TrimSpace(observation.Code)
		key := identityKey(canonical, code, evidenceKey(observation.Evidence))
		if index, ok := byKey[key]; ok {
			if observation.Source != "" {
				findings[index].Sources = appendUnique(findings[index].Sources, observation.Source)
			}
			continue
		}
		item := NormalizedFinding{
			Code: code, Title: strings.TrimSpace(observation.Title), Description: strings.TrimSpace(observation.Description),
			Category: strings.TrimSpace(observation.Category), Evidence: strings.TrimSpace(observation.Evidence),
			Source: strings.TrimSpace(observation.Source), DeduplicationKey: key,
			Classification: FindingUnclassified,
		}
		if item.Source != "" {
			item.Sources = []string{item.Source}
		}
		if mapping, known := findingCatalog[code]; known {
			item.Severity = mapping.Severity
			item.Confidence = mapping.Confidence
			item.ScoringCategory = mapping.Category
			item.Remediation = mapping.Remediation
			item.ScoreEligible = mapping.ScoreEligible
			item.Classification = FindingClassified
		}
		if item.Code == "" {
			item.Code = "(missing-code)"
			item.Classification = FindingUnclassified
			item.ScoreEligible = false
		}
		byKey[key] = len(findings)
		findings = append(findings, item)
	}
	for index := range findings {
		sort.Strings(findings[index].Sources)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].DeduplicationKey < findings[j].DeduplicationKey })
	return findings, nil
}

func identityKey(parts ...string) string {
	var key strings.Builder
	for _, part := range parts {
		key.WriteString(strconv.Itoa(len(part)))
		key.WriteByte(':')
		key.WriteString(part)
	}
	return key.String()
}

func FromHeuristicFinding(f heuristics.Finding, source string) Observation {
	return Observation{Code: f.Code, Title: f.Title, Description: f.Description, Category: f.Category, Evidence: f.Evidence, Source: source}
}

func evidenceKey(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func canonicalTarget(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown-target", nil
	}
	raw := value
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	normalized, err := heuristics.NormalizeURL(raw)
	if err == nil && normalized.Hostname != "" {
		return strings.ToLower(strings.TrimSuffix(normalized.Hostname, ".")), nil
	}
	parsed, parseErr := url.Parse(value)
	if parseErr == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname()), nil
	}
	return "", fmt.Errorf("normalize risk target: invalid target")
}
