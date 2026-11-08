package report

import (
	"testing"
	"time"

	"bouclier/internal/risk"
)

func FuzzRenderReport(f *testing.F) {
	seeds := []string{
		"https://example.com/",
		"https://user:pass@evil.com/path?secret=123",
		"<script>alert(1)</script>",
		"| pipe | markdown | syntax |",
		"```markdown codeblock```",
		"normal finding title",
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
		"cookie: session=secret123456",
		"\x00\x01\x02\x03\r\n\t",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 2048 {
			t.Skip()
		}

		finding := risk.NormalizedFinding{
			Code:             "FUZZ_CODE",
			Title:            input,
			Description:      input,
			Category:         "fuzz-category",
			Evidence:         input,
			Severity:         risk.SeverityMedium,
			Confidence:       risk.ConfidenceHigh,
			ScoreImpact:      25,
			DeduplicationKey: "fuzz-key-" + input,
			Classification:   risk.FindingClassified,
			Remediation:      input,
			Sources:          []string{input},
		}

		assessment := &risk.RiskAssessment{
			SchemaVersion:  "bouclier-risk/v1",
			Target:         "https://example.com/?q=" + input,
			AnalyzedAt:     time.Now().UTC(),
			OverallScore:   25,
			Classification: risk.RiskGuarded,
			PolicyID:       "bouclier-default",
			PolicyVersion:  "1",
			Findings:       []risk.NormalizedFinding{finding},
			SeverityCounts: []risk.SeverityCount{
				{Severity: risk.SeverityMedium, Count: 1},
			},
			Limitations: []string{input},
			AnalysisCoverage: []risk.ComponentCoverage{
				{Component: input, State: risk.ComponentCompleted, Detail: input},
			},
		}

		// Neither JSON nor Markdown rendering must ever panic
		_, _ = RenderJSON(assessment)
		_, _ = RenderMarkdown(assessment)
	})
}
