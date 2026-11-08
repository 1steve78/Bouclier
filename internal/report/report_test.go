package report

import (
	"encoding/json"
	"strings"
	"testing"

	"bouclier/internal/risk"
)

func sampleAssessment(t *testing.T) *risk.RiskAssessment {
	t.Helper()
	findings, err := risk.NormalizeFindings([]risk.Observation{{Code: "WEB_HSTS_MISSING", Title: "Missing HSTS | `policy`", Description: "Header is absent <script>", Evidence: "https://example.com/path?token=private", Source: risk.SourceWeb}}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := risk.CalculateRisk(findings, risk.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	assessment.Target = "example.com"
	assessment.AnalysisCoverage = []risk.ComponentCoverage{{Component: "web", State: risk.ComponentPartial, Detail: "Authorization: Bearer abc123; Set-Cookie: arbitrary=opaque-cookie"}}
	assessment.Limitations = []string{"Cookie: session=secret-value", "Set-Cookie: arbitrary=opaque-cookie", "relative/path?access_token=query-secret"}
	return assessment
}

func TestRenderJSONIsValidStableAndRedacted(t *testing.T) {
	a := sampleAssessment(t)
	first, err := RenderJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("JSON output is not deterministic")
	}
	var decoded map[string]any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema_version"] != "bouclier-risk/v1" {
		t.Fatalf("schema version missing: %v", decoded["schema_version"])
	}
	for _, secret := range []string{"private", "abc123", "opaque-cookie", "secret-value", "query-secret"} {
		if strings.Contains(string(first), secret) {
			t.Fatalf("secret %q leaked: %s", secret, first)
		}
	}
	if a.AnalysisCoverage[0].Detail != "Authorization: Bearer abc123; Set-Cookie: arbitrary=opaque-cookie" {
		t.Fatal("renderer mutated its input")
	}
}

func TestRenderMarkdownEscapesAndReportsLimits(t *testing.T) {
	a := sampleAssessment(t)
	text, err := RenderMarkdown(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"# Bouclier Website Risk Assessment", "Risk score:", "## Analysis coverage", "partial", "not a probability", "&lt;script&gt;", "\\|"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Markdown missing %q:\n%s", expected, text)
		}
	}
	for _, secret := range []string{"private", "abc123", "opaque-cookie", "secret-value", "query-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q leaked", secret)
		}
	}
}

func TestRenderEmptyAssessmentAndNil(t *testing.T) {
	assessment, err := risk.CalculateRisk(nil, risk.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	text, err := RenderMarkdown(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "not a guarantee of security") {
		t.Fatal("empty assessment implies safety")
	}
	if _, err := RenderJSON(nil); err == nil {
		t.Fatal("nil JSON assessment should fail")
	}
	if _, err := RenderMarkdown(nil); err == nil {
		t.Fatal("nil Markdown assessment should fail")
	}
}
