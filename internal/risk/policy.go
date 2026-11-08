package risk

import (
	"fmt"
	"sort"
	"strings"
)

// Policy is a versioned and bounded deterministic scoring configuration.
type Policy struct {
	ID                       string             `json:"id"`
	Version                  string             `json:"version"`
	SeverityWeights          map[Severity]int   `json:"severity_weights"`
	ConfidenceMultipliers    map[Confidence]int `json:"confidence_multipliers_percent"`
	MaximumScore             int                `json:"maximum_score"`
	FindingContributionCap   int                `json:"finding_contribution_cap"`
	CategoryContributionCaps map[string]int     `json:"category_contribution_caps"`
}

// DefaultPolicy returns the initial explainable policy. Small header and
// structure signals have low weights and related web findings share category caps.
func DefaultPolicy() Policy {
	return Policy{
		ID: "bouclier-default", Version: "1.0",
		SeverityWeights:       map[Severity]int{SeverityInformational: 0, SeverityLow: 6, SeverityMedium: 18, SeverityHigh: 35, SeverityCritical: 55},
		ConfidenceMultipliers: map[Confidence]int{ConfidenceLow: 30, ConfidenceMedium: 60, ConfidenceHigh: 100},
		MaximumScore:          100, FindingContributionCap: 50,
		CategoryContributionCaps: map[string]int{
			"url-structure": 15, "brand-impersonation": 50, "domain-suffix": 10, "url-shortener": 8, "phishing-language": 10,
			"domain-structure": 14, "certificate-identity": 45, "certificate-validity": 45, "certificate-trust": 45,
			"web-transport": 35, "web-navigation": 8, "web-content-policy": 15, "web-privacy": 10, "web-cookie": 22,
			"web-cors": 16, "web-html-mixed-content": 20, "web-html-link": 5, "web-html-form": 35, "web-html": 5,
			"threat-intelligence": 60,
		},
	}
}

func (p Policy) Validate() error {
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("policy ID and version are required")
	}
	if p.MaximumScore < 1 || p.MaximumScore > 100 {
		return fmt.Errorf("policy maximum score must be between 1 and 100")
	}
	if p.FindingContributionCap < 1 || p.FindingContributionCap > p.MaximumScore {
		return fmt.Errorf("finding contribution cap must be between 1 and maximum score")
	}
	order := []Severity{SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	previous := -1
	for _, severity := range order {
		weight, ok := p.SeverityWeights[severity]
		if !ok {
			return fmt.Errorf("policy has no weight for severity %q", severity)
		}
		if weight < 0 || weight > 100 || weight < previous {
			return fmt.Errorf("policy severity weights must be nonnegative, at most 100, and nondecreasing")
		}
		if severity == SeverityInformational && weight != 0 {
			return fmt.Errorf("informational findings must have zero severity weight")
		}
		previous = weight
	}
	previous = -1
	for _, confidence := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		multiplier, ok := p.ConfidenceMultipliers[confidence]
		if !ok || multiplier < 0 || multiplier > 100 || multiplier < previous {
			return fmt.Errorf("policy confidence multipliers must exist, be bounded, and nondecreasing")
		}
		previous = multiplier
	}
	for category, cap := range p.CategoryContributionCaps {
		if strings.TrimSpace(category) == "" || cap < 0 || cap > p.MaximumScore {
			return fmt.Errorf("policy category caps must have a category and be between 0 and maximum score")
		}
	}
	return nil
}

func clonePolicy(policy Policy) Policy {
	policy.SeverityWeights = cloneSeverityWeights(policy.SeverityWeights)
	policy.ConfidenceMultipliers = cloneConfidenceWeights(policy.ConfidenceMultipliers)
	policy.CategoryContributionCaps = cloneCaps(policy.CategoryContributionCaps)
	return policy
}

func cloneSeverityWeights(source map[Severity]int) map[Severity]int {
	target := make(map[Severity]int, len(source))
	for k, v := range source {
		target[k] = v
	}
	return target
}
func cloneConfidenceWeights(source map[Confidence]int) map[Confidence]int {
	target := make(map[Confidence]int, len(source))
	for k, v := range source {
		target[k] = v
	}
	return target
}
func cloneCaps(source map[string]int) map[string]int {
	target := make(map[string]int, len(source))
	for k, v := range source {
		target[k] = v
	}
	return target
}

func categoryCapsSorted(policy Policy) []string {
	keys := make([]string, 0, len(policy.CategoryContributionCaps))
	for key := range policy.CategoryContributionCaps {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
