package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"bouclier/internal/risk"
)

// RenderJSON returns a stable, sanitized JSON representation. It never
// recalculates or reclassifies the assessment.
func RenderJSON(assessment *risk.RiskAssessment) ([]byte, error) {
	if assessment == nil {
		return nil, fmt.Errorf("render JSON report: assessment is nil")
	}
	copy := sanitizeAssessment(assessment)
	return json.MarshalIndent(copy, "", "  ")
}

func sanitizeAssessment(source *risk.RiskAssessment) *risk.RiskAssessment {
	copy := *source
	copy.Target = redact(copy.Target)
	copy.PolicyID = redact(copy.PolicyID)
	copy.PolicyVersion = redact(copy.PolicyVersion)
	copy.SchemaVersion = redact(copy.SchemaVersion)
	copy.ScoringMethod = redact(copy.ScoringMethod)
	copy.Findings = cloneFindings(source.Findings)
	copy.ExcludedFindings = cloneFindings(source.ExcludedFindings)
	copy.SeverityCounts = append([]risk.SeverityCount(nil), source.SeverityCounts...)
	copy.CategoryContributions = append([]risk.CategoryContribution(nil), source.CategoryContributions...)
	copy.TopRiskFactors = append([]risk.RiskFactor(nil), source.TopRiskFactors...)
	copy.AnalysisCoverage = append([]risk.ComponentCoverage(nil), source.AnalysisCoverage...)
	copy.Limitations = append([]string(nil), source.Limitations...)
	for i := range copy.TopRiskFactors {
		copy.TopRiskFactors[i].Finding = sanitizeFinding(copy.TopRiskFactors[i].Finding)
	}
	for i := range copy.AnalysisCoverage {
		copy.AnalysisCoverage[i].Component = redact(copy.AnalysisCoverage[i].Component)
		copy.AnalysisCoverage[i].Detail = redact(copy.AnalysisCoverage[i].Detail)
	}
	for i := range copy.Limitations {
		copy.Limitations[i] = redact(copy.Limitations[i])
	}
	if source.RegistrationAge != nil {
		age := *source.RegistrationAge
		if source.RegistrationAge.Age != nil {
			duration := *source.RegistrationAge.Age
			age.Age = &duration
		}
		age.Explanation = redact(age.Explanation)
		copy.RegistrationAge = &age
	}
	sort.Slice(copy.Findings, func(i, j int) bool { return findingLess(copy.Findings[i], copy.Findings[j]) })
	sort.Slice(copy.ExcludedFindings, func(i, j int) bool { return findingLess(copy.ExcludedFindings[i], copy.ExcludedFindings[j]) })
	sort.Slice(copy.SeverityCounts, func(i, j int) bool {
		if copy.SeverityCounts[i].Severity != copy.SeverityCounts[j].Severity {
			return copy.SeverityCounts[i].Severity < copy.SeverityCounts[j].Severity
		}
		return copy.SeverityCounts[i].Count < copy.SeverityCounts[j].Count
	})
	sort.Slice(copy.CategoryContributions, func(i, j int) bool {
		if copy.CategoryContributions[i].Category != copy.CategoryContributions[j].Category {
			return copy.CategoryContributions[i].Category < copy.CategoryContributions[j].Category
		}
		if copy.CategoryContributions[i].Score != copy.CategoryContributions[j].Score {
			return copy.CategoryContributions[i].Score < copy.CategoryContributions[j].Score
		}
		return copy.CategoryContributions[i].Cap < copy.CategoryContributions[j].Cap
	})
	sort.Slice(copy.TopRiskFactors, func(i, j int) bool {
		if copy.TopRiskFactors[i].Contribution != copy.TopRiskFactors[j].Contribution {
			return copy.TopRiskFactors[i].Contribution > copy.TopRiskFactors[j].Contribution
		}
		if findingLess(copy.TopRiskFactors[i].Finding, copy.TopRiskFactors[j].Finding) {
			return true
		}
		if findingLess(copy.TopRiskFactors[j].Finding, copy.TopRiskFactors[i].Finding) {
			return false
		}
		return copy.TopRiskFactors[i].Contribution < copy.TopRiskFactors[j].Contribution
	})
	sort.Slice(copy.AnalysisCoverage, func(i, j int) bool {
		if copy.AnalysisCoverage[i].Component != copy.AnalysisCoverage[j].Component {
			return copy.AnalysisCoverage[i].Component < copy.AnalysisCoverage[j].Component
		}
		if copy.AnalysisCoverage[i].State != copy.AnalysisCoverage[j].State {
			return copy.AnalysisCoverage[i].State < copy.AnalysisCoverage[j].State
		}
		return copy.AnalysisCoverage[i].Detail < copy.AnalysisCoverage[j].Detail
	})
	sort.Strings(copy.Limitations)
	return &copy
}

func findingLess(a, b risk.NormalizedFinding) bool {
	if a.DeduplicationKey != b.DeduplicationKey {
		return a.DeduplicationKey < b.DeduplicationKey
	}
	if a.Code != b.Code {
		return a.Code < b.Code
	}
	if a.Evidence != b.Evidence {
		return a.Evidence < b.Evidence
	}
	if a.Title != b.Title {
		return a.Title < b.Title
	}
	if a.Description != b.Description {
		return a.Description < b.Description
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return strings.Join(a.Sources, "\x00") < strings.Join(b.Sources, "\x00")
}

func cloneFindings(source []risk.NormalizedFinding) []risk.NormalizedFinding {
	result := make([]risk.NormalizedFinding, len(source))
	copy(result, source)
	for i := range result {
		result[i] = sanitizeFinding(result[i])
	}
	return result
}

func sanitizeFinding(f risk.NormalizedFinding) risk.NormalizedFinding {
	f.Code = redact(f.Code)
	f.Title = redact(f.Title)
	f.Description = redact(f.Description)
	f.Category = redact(f.Category)
	f.ScoringCategory = redact(f.ScoringCategory)
	f.Evidence = redact(f.Evidence)
	f.Source = redact(f.Source)
	f.Remediation = redact(f.Remediation)
	f.DeduplicationKey = redact(f.DeduplicationKey)
	f.Sources = append([]string(nil), f.Sources...)
	for i := range f.Sources {
		f.Sources[i] = redact(f.Sources[i])
	}
	sort.Strings(f.Sources)
	return f
}
