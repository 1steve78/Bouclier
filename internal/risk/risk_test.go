package risk

import (
	"reflect"
	"strings"
	"testing"
)

func TestCatalogIsStableAndUnknownCodesStayUnclassified(t *testing.T) {
	first, second := Catalog(), Catalog()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("catalog order is not deterministic")
	}
	if len(first) == 0 {
		t.Fatal("catalog is empty")
	}
	findings, err := NormalizeFindings([]Observation{{Code: "UNKNOWN_TEST_CODE", Title: "Future signal", Evidence: "evidence", Source: SourceWeb}}, "https://example.com/path?token=private")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Classification != FindingUnclassified || findings[0].ScoreEligible || findings[0].ScoreImpact != 0 {
		t.Fatalf("unknown mapping: %+v", findings)
	}
	if strings.Contains(findings[0].DeduplicationKey, "private") {
		t.Fatal("query secret entered deduplication key")
	}
}

func TestNormalizeDeduplicatesOnlySameCodeAndEvidence(t *testing.T) {
	observations := []Observation{
		{Code: "WEB_HSTS_MISSING", Title: "HSTS absent", Evidence: "Header absent", Source: SourceWeb},
		{Code: "WEB_HSTS_MISSING", Title: "same observation", Evidence: " header   ABSENT ", Source: SourceTLS},
		{Code: "WEB_HSTS_MISSING", Title: "different host", Evidence: "other header", Source: SourceWeb},
	}
	got, err := NormalizeFindings(observations, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d normalized findings, want 2", len(got))
	}
	merged := false
	for _, finding := range got {
		if len(finding.Sources) == 2 {
			merged = true
		}
	}
	if !merged {
		t.Fatalf("duplicate sources were not merged: %+v", got)
	}
}

func TestCalculateRiskBoundsAndClassifies(t *testing.T) {
	policy := DefaultPolicy()
	cases := []struct {
		name  string
		code  string
		want  int
		class RiskClass
	}{
		{"empty", "", 0, RiskLow},
		{"low", "WEB_HSTS_MISSING", 6, RiskLow},
		{"critical weight", "WEB_HTML_INSECURE_PASSWORD_FORM", 35, RiskGuarded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var findings []NormalizedFinding
			if tc.code != "" {
				var err error
				findings, err = NormalizeFindings([]Observation{{Code: tc.code, Title: tc.code, Evidence: "one"}}, "example.com")
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := CalculateRisk(findings, policy)
			if err != nil {
				t.Fatal(err)
			}
			if got.OverallScore != tc.want || got.Classification != tc.class {
				t.Fatalf("got score/class %d/%s, want %d/%s", got.OverallScore, got.Classification, tc.want, tc.class)
			}
		})
	}
}

func TestCalculateRiskDedupCapsAndDeterminism(t *testing.T) {
	findings, err := NormalizeFindings([]Observation{
		{Code: "BRAND_SIMILAR_DOMAIN", Title: "brand", Evidence: "same"},
		{Code: "BRAND_SIMILAR_DOMAIN", Title: "brand duplicate", Evidence: "same"},
		{Code: "BRAND_SIMILAR_DOMAIN", Title: "brand other", Evidence: "different"},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultPolicy()
	a, err := CalculateRisk(findings, policy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CalculateRisk(findings, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same inputs produced different assessments")
	}
	if len(a.Findings) != 2 {
		t.Fatalf("dedup retained %d findings", len(a.Findings))
	}
	if a.OverallScore > policy.CategoryContributionCaps["brand-impersonation"] {
		t.Fatalf("category cap exceeded: %d", a.OverallScore)
	}
	for i := 0; i < 20; i++ {
		findings = append(findings, findings...)
	}
	capped, err := CalculateRisk(findings, policy)
	if err != nil {
		t.Fatal(err)
	}
	if capped.OverallScore != a.OverallScore {
		t.Fatalf("duplicates inflated score from %d to %d", a.OverallScore, capped.OverallScore)
	}
}

func TestPolicyRejectsInvalidWeights(t *testing.T) {
	policy := DefaultPolicy()
	policy.ConfidenceMultipliers[ConfidenceHigh] = 101
	if err := policy.Validate(); err == nil {
		t.Fatal("expected invalid confidence multiplier error")
	}
	policy = DefaultPolicy()
	policy.SeverityWeights[SeverityCritical] = -1
	if err := policy.Validate(); err == nil {
		t.Fatal("expected invalid severity weight error")
	}
}

func TestClassificationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score int
		class RiskClass
	}{{19, RiskLow}, {20, RiskGuarded}, {39, RiskGuarded}, {40, RiskElevated}, {59, RiskElevated}, {60, RiskHigh}, {79, RiskHigh}, {80, RiskCritical}, {100, RiskCritical}} {
		if got := classify(tc.score); got != tc.class {
			t.Errorf("classify(%d)=%s, want %s", tc.score, got, tc.class)
		}
	}
}

func TestCalculateRiskUsesCatalogAndFallsBackForEmptyKeys(t *testing.T) {
	findings, err := NormalizeFindings([]Observation{{Code: "BRAND_SIMILAR_DOMAIN", Title: "similar", Evidence: "x"}}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	finding := findings[0]
	finding.DeduplicationKey = ""
	a, err := CalculateRisk([]NormalizedFinding{finding, finding}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Findings) != 1 {
		t.Fatalf("empty identity allowed duplicate scoring: %d", len(a.Findings))
	}
	finding.Code = "UNLISTED_CODE"
	if _, err := CalculateRisk([]NormalizedFinding{finding}, DefaultPolicy()); err == nil {
		t.Fatal("unknown classified code was allowed to score")
	}
}

func TestConfidenceMultiplierAndContributionCaps(t *testing.T) {
	findings, err := NormalizeFindings([]Observation{{Code: "BRAND_SIMILAR_DOMAIN", Evidence: "one"}}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	defaultScore, err := CalculateRisk(findings, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	adjustedPolicy := DefaultPolicy()
	adjustedPolicy.ConfidenceMultipliers[ConfidenceMedium] = 30
	adjustedScore, err := CalculateRisk(findings, adjustedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if defaultScore.OverallScore != 21 || adjustedScore.OverallScore != 11 {
		t.Fatalf("confidence multipliers not applied: default=%d adjusted=%d", defaultScore.OverallScore, adjustedScore.OverallScore)
	}
	forged := findings[0]
	forged.Confidence = ConfidenceLow
	if _, err := CalculateRisk([]NormalizedFinding{forged}, DefaultPolicy()); err == nil {
		t.Fatal("non-catalog confidence override was accepted")
	}
	findings, err = NormalizeFindings([]Observation{{Code: "BRAND_SIMILAR_DOMAIN", Evidence: "one"}, {Code: "BRAND_SIMILAR_DOMAIN", Evidence: "two"}, {Code: "BRAND_SIMILAR_DOMAIN", Evidence: "three"}}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	a, err := CalculateRisk(findings, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if a.OverallScore > DefaultPolicy().CategoryContributionCaps["brand-impersonation"] {
		t.Fatalf("category cap exceeded: %d", a.OverallScore)
	}
}
