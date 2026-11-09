package report

import (
	"testing"
	"time"

	"bouclier/internal/risk"
)

func TestCorrelateTracksFindingChangesChronologically(t *testing.T) {
	firstTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := func(score int, findings ...risk.NormalizedFinding) *risk.RiskAssessment {
		return &risk.RiskAssessment{
			OverallScore: score, Classification: risk.RiskGuarded, Findings: findings,
		}
	}
	common := risk.NormalizedFinding{
		Code: "WEB_CSP", Category: "headers", Title: "Weak CSP", Evidence: "unsafe-eval present",
	}
	added := risk.NormalizedFinding{
		Code: "TLS_WEAK", Category: "tls", Title: "Weak protocol", Evidence: "TLS 1.0 enabled",
	}
	resolved := risk.NormalizedFinding{
		Code: "COOKIE_SECURE", Category: "cookies", Title: "Secure flag missing", Evidence: "session cookie",
	}
	got, err := Correlate("example.com", []CorrelationEntry{
		{ID: "scan-3", StartedAt: firstTime.Add(2 * time.Hour), Assessment: base(15, common, added)},
		{ID: "scan-1", StartedAt: firstTime, Assessment: base(25, common, resolved)},
		{ID: "scan-2", StartedAt: firstTime.Add(time.Hour), Assessment: base(40, common, added, resolved)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scans) != 3 || got.Scans[0].ID != "scan-1" || got.Scans[2].ID != "scan-3" {
		t.Fatalf("scans not chronological: %+v", got.Scans)
	}
	if len(got.Scans[0].NewFindings) != 0 || len(got.Scans[0].ResolvedFindings) != 0 {
		t.Fatalf("baseline should not have a previous-report delta: %+v", got.Scans[0])
	}
	if len(got.Scans[1].NewFindings) != 1 || got.Scans[1].NewFindings[0].Code != "TLS_WEAK" ||
		len(got.Scans[1].ResolvedFindings) != 0 {
		t.Fatalf("incorrect second-scan diff: %+v", got.Scans[1])
	}
	if len(got.Scans[2].NewFindings) != 0 || len(got.Scans[2].ResolvedFindings) != 1 ||
		got.Scans[2].ResolvedFindings[0].Code != "COOKIE_SECURE" {
		t.Fatalf("incorrect final-scan diff: %+v", got.Scans[2])
	}
}

func TestCorrelateNormalizesFingerprintWhitespaceAndCase(t *testing.T) {
	first := risk.NormalizedFinding{Code: "WEB_CSP", Title: "CSP", Evidence: "unsafe-eval  present"}
	next := risk.NormalizedFinding{Code: "web_csp", Title: "csp", Evidence: "UNSAFE-EVAL present"}
	got, err := Correlate("example.com", []CorrelationEntry{
		{ID: "one", StartedAt: time.Unix(1, 0), Assessment: &risk.RiskAssessment{Findings: []risk.NormalizedFinding{first}}},
		{ID: "two", StartedAt: time.Unix(2, 0), Assessment: &risk.RiskAssessment{Findings: []risk.NormalizedFinding{next}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scans[1].NewFindings) != 0 || len(got.Scans[1].ResolvedFindings) != 0 {
		t.Fatalf("case/whitespace-only changes should match: %+v", got.Scans[1])
	}
}
