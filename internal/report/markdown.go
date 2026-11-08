package report

import (
	"fmt"
	"strings"
	"time"

	"bouclier/internal/risk"
)

// RenderMarkdown renders the supplied assessment without recomputing its score.
func RenderMarkdown(assessment *risk.RiskAssessment) (string, error) {
	if assessment == nil {
		return "", fmt.Errorf("render Markdown report: assessment is nil")
	}
	a := sanitizeAssessment(assessment)
	var out strings.Builder
	out.WriteString("# Bouclier Website Risk Assessment\n\n")
	out.WriteString("## Assessment overview\n\n")
	target := a.Target
	if target == "" {
		target = "not recorded"
	}
	out.WriteString("- **Target:** " + markdownEscape(target) + "\n")
	out.WriteString("- **Analyzed at:** " + markdownEscape(formatTime(a.AnalyzedAt)) + "\n")
	out.WriteString(fmt.Sprintf("- **Risk score:** %d/100 — **%s**\n", a.OverallScore, markdownEscape(string(a.Classification))))
	out.WriteString("- **Scoring policy:** " + markdownEscape(a.PolicyID) + " v" + markdownEscape(a.PolicyVersion) + "\n\n")
	out.WriteString("This score summarizes observed indicators under the listed checks and policy. It is not a probability that the site is malicious and does not establish that a site is safe. A zero score means no scored indicators were observed in the analysis that ran.\n\n")
	out.WriteString("## Executive summary\n\n")
	if len(a.Findings) == 0 {
		out.WriteString("No findings were supplied to the scoring engine. Review analysis coverage below; missing or unavailable checks do not count as clean results.\n\n")
	} else {
		out.WriteString(fmt.Sprintf("The assessment contains %d normalized findings, of which %d are unclassified. The score is %d/100 (%s) under policy %s v%s. Findings are observations and may require owner review.\n\n", len(a.Findings), a.UnclassifiedCount, a.OverallScore, a.Classification, a.PolicyID, a.PolicyVersion))
	}
	out.WriteString("## Finding counts by severity\n\n")
	if len(a.SeverityCounts) == 0 {
		out.WriteString("No classified findings.\n\n")
	} else {
		for _, count := range a.SeverityCounts {
			out.WriteString(fmt.Sprintf("- **%s:** %d\n", markdownEscape(string(count.Severity)), count.Count))
		}
		out.WriteString("\n")
	}
	out.WriteString("## Highest-impact findings\n\n")
	if len(a.TopRiskFactors) == 0 {
		out.WriteString("No findings contributed to the score.\n\n")
	} else {
		for _, factor := range a.TopRiskFactors {
			out.WriteString(fmt.Sprintf("- **%s** (%s, confidence %s): +%d points. %s\n", markdownEscape(factor.Finding.Title), markdownEscape(string(factor.Finding.Severity)), markdownEscape(string(factor.Finding.Confidence)), factor.Contribution, markdownEscape(factor.Finding.Description)))
		}
		out.WriteString("\n")
	}
	out.WriteString("## Complete findings\n\n")
	if len(a.Findings) == 0 {
		out.WriteString("No findings. This is not a guarantee of security.\n\n")
	}
	for index, finding := range a.Findings {
		out.WriteString(fmt.Sprintf("### %d. %s\n\n", index+1, markdownEscape(finding.Title)))
		out.WriteString("- **Code:** `" + markdownEscape(finding.Code) + "`\n")
		if finding.Classification == risk.FindingUnclassified {
			out.WriteString("- **Classification:** unclassified; excluded from scoring\n")
		} else {
			out.WriteString("- **Severity / confidence:** " + markdownEscape(string(finding.Severity)) + " / " + markdownEscape(string(finding.Confidence)) + "\n")
		}
		if finding.Category != "" {
			out.WriteString("- **Category:** " + markdownEscape(finding.Category) + "\n")
		}
		if finding.Source != "" {
			out.WriteString("- **Source:** " + markdownEscape(strings.Join(finding.Sources, ", ")) + "\n")
		}
		out.WriteString("- **Score contribution:** " + fmt.Sprintf("%d", finding.ScoreImpact) + "\n")
		out.WriteString("\n" + markdownEscape(finding.Description) + "\n\n")
		if finding.Evidence != "" {
			out.WriteString("**Evidence:** " + markdownEscape(finding.Evidence) + "\n\n")
		}
		remediation := finding.Remediation
		if remediation == "" {
			remediation = "Review this unclassified observation manually; it has no catalog mapping or score weight."
		}
		out.WriteString("**Suggested action:** " + markdownEscape(remediation) + "\n\n")
	}
	out.WriteString("## Category contributions\n\n")
	if len(a.CategoryContributions) == 0 {
		out.WriteString("No category contributed points.\n\n")
	} else {
		for _, contribution := range a.CategoryContributions {
			out.WriteString(fmt.Sprintf("- **%s:** %d/%d points\n", markdownEscape(contribution.Category), contribution.Score, contribution.Cap))
		}
		out.WriteString("\n")
	}
	out.WriteString("## Excluded from scoring\n\n")
	if len(a.ExcludedFindings) == 0 {
		out.WriteString("No findings were excluded.\n\n")
	} else {
		for _, finding := range a.ExcludedFindings {
			reason := "not configured to affect the score"
			if finding.Classification == risk.FindingUnclassified {
				reason = "unknown code; unclassified findings receive no score weight"
			}
			out.WriteString(fmt.Sprintf("- **%s** (`%s`): %s. %s\n", markdownEscape(finding.Title), markdownEscape(finding.Code), reason, markdownEscape(finding.Evidence)))
		}
		out.WriteString("\n")
	}
	out.WriteString("## Analysis coverage\n\n")
	if len(a.AnalysisCoverage) == 0 {
		out.WriteString("No component coverage was supplied.\n\n")
	} else {
		for _, component := range a.AnalysisCoverage {
			detail := ""
			if component.Detail != "" {
				detail = " — " + markdownEscape(component.Detail)
			}
			out.WriteString("- **" + markdownEscape(component.Component) + ":** " + markdownEscape(string(component.State)) + detail + "\n")
		}
		out.WriteString("\n")
	}
	if a.Intelligence != nil {
		out.WriteString("## Threat intelligence\n\n")
		syncTime := "never"
		if a.Intelligence.LastSuccessfulSync != nil {
			syncTime = formatTime(*a.Intelligence.LastSuccessfulSync)
		}
		out.WriteString(fmt.Sprintf("- **Sources configured/enabled:** %d / %d\n", a.Intelligence.SourcesConfigured, a.Intelligence.SourcesEnabled))
		out.WriteString(fmt.Sprintf("- **Indicators evaluated:** %d\n", a.Intelligence.IndicatorsConsidered))
		out.WriteString(fmt.Sprintf("- **Matches identified:** %d\n", a.Intelligence.MatchesCount))
		out.WriteString(fmt.Sprintf("- **Last successful synchronization:** %s\n", syncTime))
		if a.Intelligence.DatabaseStale {
			out.WriteString("- **Database status:** Stale (feeds have not been updated recently)\n")
		} else if a.Intelligence.DatabaseUnavailable {
			out.WriteString("- **Database status:** Unavailable\n")
		} else {
			out.WriteString("- **Database status:** Active\n")
		}
		if a.Intelligence.Detail != "" {
			out.WriteString(fmt.Sprintf("- **Detail:** %s\n", markdownEscape(a.Intelligence.Detail)))
		}
		out.WriteString("\n")
	}
	out.WriteString("## Limitations and unavailable checks\n\n")
	if len(a.Limitations) == 0 {
		out.WriteString("No additional limitations were supplied. Skipped and unavailable components are shown in the coverage section.\n\n")
	} else {
		for _, limitation := range a.Limitations {
			out.WriteString("- " + markdownEscape(limitation) + "\n")
		}
		out.WriteString("\n")
	}
	out.WriteString("## Scoring methodology\n\n")
	out.WriteString(markdownEscape(a.ScoringMethod) + "\n\n")
	out.WriteString("Findings are deduplicated by normalized target, stable code, and normalized evidence. A code with materially different evidence remains separate. Contributions use the policy severity weight and confidence multiplier, rounded half up, then apply per-finding, category, and overall caps. The initial score bands are 0–19 Low, 20–39 Guarded, 40–59 Elevated, 60–79 High, and 80–100 Critical. These are product thresholds, not certified security grades.\n")
	return out.String(), nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "not recorded"
	}
	return value.UTC().Format(time.RFC3339)
}
