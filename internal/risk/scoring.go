package risk

import (
	"fmt"
	"sort"
	"strings"
)

const scoringMethod = "Capped integer weighted sum: severity weight × confidence percent rounded half up; then per-finding, per-category, and overall caps. The score is a relative product indicator, not a probability."

// CalculateRisk scores normalized findings with a validated, explicit policy.
// Duplicate deduplication keys count once; unknown and excluded codes remain visible.
func CalculateRisk(findings []NormalizedFinding, policy Policy) (*RiskAssessment, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("calculate risk: invalid policy: %w", err)
	}
	policy = clonePolicy(policy)
	ordered := append([]NormalizedFinding(nil), findings...)
	for index := range ordered {
		if ordered[index].DeduplicationKey == "" {
			ordered[index].DeduplicationKey = identityKey(strings.ToLower(strings.TrimSpace(ordered[index].Code)), evidenceKey(ordered[index].Evidence))
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].DeduplicationKey != ordered[j].DeduplicationKey {
			return ordered[i].DeduplicationKey < ordered[j].DeduplicationKey
		}
		if ordered[i].Code != ordered[j].Code {
			return ordered[i].Code < ordered[j].Code
		}
		if ordered[i].Evidence != ordered[j].Evidence {
			return ordered[i].Evidence < ordered[j].Evidence
		}
		if ordered[i].Title != ordered[j].Title {
			return ordered[i].Title < ordered[j].Title
		}
		if ordered[i].Description != ordered[j].Description {
			return ordered[i].Description < ordered[j].Description
		}
		if ordered[i].Source != ordered[j].Source {
			return ordered[i].Source < ordered[j].Source
		}
		return strings.Join(ordered[i].Sources, "\x00") < strings.Join(ordered[j].Sources, "\x00")
	})
	unique := make([]NormalizedFinding, 0, len(ordered))
	seen := make(map[string]bool, len(ordered))
	for _, finding := range ordered {
		if finding.DeduplicationKey != "" && seen[finding.DeduplicationKey] {
			continue
		}
		if err := finding.Validate(); err != nil {
			return nil, fmt.Errorf("calculate risk: invalid finding %q: %w", finding.Code, err)
		}
		mapping, known := findingCatalog[finding.Code]
		if !known && finding.Classification != FindingUnclassified {
			return nil, fmt.Errorf("calculate risk: unknown finding code %q cannot be classified", finding.Code)
		}
		if known && (finding.Classification != FindingClassified || finding.Severity != mapping.Severity || finding.Confidence != mapping.Confidence || finding.ScoringCategory != mapping.Category || finding.ScoreEligible != mapping.ScoreEligible) {
			return nil, fmt.Errorf("calculate risk: finding %q does not match its catalog classification", finding.Code)
		}
		if finding.DeduplicationKey != "" {
			seen[finding.DeduplicationKey] = true
		}
		finding.ScoreImpact = 0
		unique = append(unique, finding)
	}

	counts := make(map[Severity]int)
	categoryScore := make(map[string]int)
	categoryCap := make(map[string]int)
	var total int
	var top []RiskFactor
	excluded := make([]NormalizedFinding, 0)
	unclassified := 0
	for index := range unique {
		finding := &unique[index]
		if finding.Classification == FindingUnclassified {
			unclassified++
		}
		if finding.Classification == FindingClassified {
			counts[finding.Severity]++
		}
		if finding.Classification != FindingClassified || !finding.ScoreEligible || finding.ScoringCategory == "" {
			excluded = append(excluded, *finding)
			continue
		}
		base := policy.SeverityWeights[finding.Severity]
		multiplier := policy.ConfidenceMultipliers[finding.Confidence]
		raw := (base*multiplier + 50) / 100
		if raw > policy.FindingContributionCap {
			raw = policy.FindingContributionCap
		}
		cap, ok := policy.CategoryContributionCaps[finding.ScoringCategory]
		if !ok {
			cap = policy.MaximumScore
		}
		if remaining := cap - categoryScore[finding.ScoringCategory]; raw > remaining {
			raw = remaining
		}
		if remaining := policy.MaximumScore - total; raw > remaining {
			raw = remaining
		}
		if raw < 0 {
			raw = 0
		}
		finding.ScoreImpact = raw
		categoryScore[finding.ScoringCategory] += raw
		categoryCap[finding.ScoringCategory] = cap
		total += raw
		if raw > 0 {
			top = append(top, RiskFactor{Finding: *finding, Contribution: raw})
		} else {
			excluded = append(excluded, *finding)
		}
	}

	severityCounts := make([]SeverityCount, 0, len(counts))
	for _, severity := range []Severity{SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if counts[severity] > 0 {
			severityCounts = append(severityCounts, SeverityCount{Severity: severity, Count: counts[severity]})
		}
	}
	categories := make([]CategoryContribution, 0, len(categoryScore))
	for category, score := range categoryScore {
		categories = append(categories, CategoryContribution{Category: category, Score: score, Cap: categoryCap[category]})
	}
	sort.Slice(categories, func(i, j int) bool { return categories[i].Category < categories[j].Category })
	sort.Slice(top, func(i, j int) bool {
		if top[i].Contribution != top[j].Contribution {
			return top[i].Contribution > top[j].Contribution
		}
		return top[i].Finding.DeduplicationKey < top[j].Finding.DeduplicationKey
	})
	if len(top) > 5 {
		top = top[:5]
	}
	sort.Slice(excluded, func(i, j int) bool { return excluded[i].DeduplicationKey < excluded[j].DeduplicationKey })
	return &RiskAssessment{
		SchemaVersion: "bouclier-risk/v1", OverallScore: total, Classification: classify(total), PolicyID: policy.ID, PolicyVersion: policy.Version,
		Findings: unique, SeverityCounts: severityCounts, CategoryContributions: categories, TopRiskFactors: top,
		ExcludedFindings: excluded, UnclassifiedCount: unclassified, AnalysisCoverage: []ComponentCoverage{}, Limitations: []string{}, ScoringMethod: scoringMethod,
	}, nil
}

func classify(score int) RiskClass {
	switch {
	case score < 20:
		return RiskLow
	case score < 40:
		return RiskGuarded
	case score < 60:
		return RiskElevated
	case score < 80:
		return RiskHigh
	default:
		return RiskCritical
	}
}
