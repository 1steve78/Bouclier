package risk

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/registration"
	"bouclier/internal/webintel"
)

var registrationAgeFixture = registration.AgeAnalysis{Status: registration.AgeStatusVeryNew, Explanation: "Recent registration is contextual only."}

func TestAggregateCombinesFindingsAndCoverage(t *testing.T) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	urlResult := &heuristics.AnalysisResult{Findings: []heuristics.Finding{{Code: "BRAND_SIMILAR_DOMAIN", Title: "Brand similarity", Description: "Similar label", Category: "brand", Evidence: "paypa1.example"}}}
	webResult := &webintel.AnalysisResult{RequestedURL: "https://paypa1.example/?token=secret", Findings: []heuristics.Finding{{Code: "BRAND_SIMILAR_DOMAIN", Title: "Brand similarity", Description: "Similar label", Category: "brand", Evidence: "paypa1.example"}}, AnalyzedAt: stamp}
	assessment, err := Aggregate(AggregationInput{Target: "https://user:password@paypa1.example/path?token=secret", AnalyzedAt: stamp, URL: urlResult, Web: webResult, Coverage: []ComponentCoverage{{Component: "custom", State: ComponentPartial}}}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Target != "paypa1.example" {
		t.Fatalf("unsafe target normalization: %q", assessment.Target)
	}
	if assessment.AnalyzedAt != stamp {
		t.Fatalf("timestamp %v", assessment.AnalyzedAt)
	}
	if len(assessment.Findings) != 1 || len(assessment.Findings[0].Sources) != 2 {
		t.Fatalf("cross-layer finding not merged: %+v", assessment.Findings)
	}
	if assessment.OverallScore == 0 {
		t.Fatal("known brand finding was not scored")
	}
	coverage := map[string]ComponentState{}
	for _, item := range assessment.AnalysisCoverage {
		coverage[item.Component] = item.State
	}
	if coverage["ct_lookup"] != ComponentSkipped || coverage["custom"] != ComponentPartial {
		t.Fatalf("coverage states missing: %+v", coverage)
	}
	if len(assessment.Limitations) == 0 {
		t.Fatal("missing component limitations were not exposed")
	}
	if strings.Contains(assessment.Target, "secret") {
		t.Fatal("target contains sensitive URL data")
	}
}

func TestAggregateKeepsRegistrationAgeContextOnly(t *testing.T) {
	got, err := Aggregate(AggregationInput{Target: "example.com", RegistrationAge: &registrationAgeFixture}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got.RegistrationAge == nil || got.RegistrationAge.Status != "very_new" {
		t.Fatalf("registration context missing: %+v", got.RegistrationAge)
	}
	if got.OverallScore != 0 || len(got.Findings) != 0 {
		t.Fatal("registration age alone affected score")
	}
}

func TestTargetQueryIsNotRetained(t *testing.T) {
	got, err := NormalizeFindings([]Observation{{Code: "UNKNOWN", Title: "unknown"}}, "https://example.com/?session=topsecret")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "topsecret") {
		t.Fatal("sensitive query value leaked")
	}
}
