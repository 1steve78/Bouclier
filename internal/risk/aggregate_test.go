package risk

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/heuristics"
	"bouclier/internal/registration"
	"bouclier/internal/tlsintel"
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

func TestAggregateWebEmbeddedTLS(t *testing.T) {
	tlsRes := &tlsintel.AnalysisResult{
		TargetHostname:    "example.com",
		Findings:          []certanalysis.Finding{{Code: "CERT_HOSTNAME_MISMATCH", Title: "Mismatch", Evidence: "san mismatch"}},
		TLSStatus:         tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
		CertificateStatus: tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
		CTStatus:          tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
	}
	webRes := &webintel.AnalysisResult{
		RequestedURL: "https://example.com/",
		TLS:          tlsRes,
		Findings:     []heuristics.Finding{{Code: "WEB_HSTS_MISSING", Title: "Missing HSTS", Evidence: "header missing"}},
	}
	got, err := AggregateDefault(AggregationInput{Web: webRes})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("expected 2 findings (1 from web, 1 from embedded TLS), got %d: %+v", len(got.Findings), got.Findings)
	}
	var hasTLS, hasWeb bool
	for _, f := range got.Findings {
		if f.Code == "CERT_HOSTNAME_MISMATCH" {
			hasTLS = true
		}
		if f.Code == "WEB_HSTS_MISSING" {
			hasWeb = true
		}
	}
	if !hasTLS || !hasWeb {
		t.Fatalf("expected both TLS and Web findings, got: %+v", got.Findings)
	}
}

func TestAggregateCTOutageDoesNotAddRisk(t *testing.T) {
	tlsRes := &tlsintel.AnalysisResult{
		TargetHostname:    "example.com",
		Findings:          []certanalysis.Finding{},
		TLSStatus:         tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
		CertificateStatus: tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
		CTStatus:          tlsintel.ComponentStatus{State: tlsintel.StateFailed, Error: "connection timeout to CT log"},
	}
	got, err := AggregateDefault(AggregationInput{Target: "example.com", TLS: tlsRes})
	if err != nil {
		t.Fatal(err)
	}
	if got.OverallScore != 0 {
		t.Fatalf("CT failure created artificial risk score: %d", got.OverallScore)
	}
	var ctCoverage *ComponentCoverage
	for i := range got.AnalysisCoverage {
		if got.AnalysisCoverage[i].Component == "ct_lookup" {
			ctCoverage = &got.AnalysisCoverage[i]
			break
		}
	}
	if ctCoverage == nil || ctCoverage.State != ComponentFailed {
		t.Fatalf("expected CT coverage to be failed, got: %+v", ctCoverage)
	}
	foundLimitation := false
	for _, lim := range got.Limitations {
		if strings.Contains(lim, "ct_lookup coverage is failed; absence of findings is not a clean result") {
			foundLimitation = true
			break
		}
	}
	if !foundLimitation {
		t.Fatalf("expected CT failure limitation, got: %+v", got.Limitations)
	}
}
