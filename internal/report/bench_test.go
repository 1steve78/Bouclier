package report

import (
	"testing"
	"time"

	"bouclier/internal/risk"
)

func createBenchmarkAssessment() *risk.RiskAssessment {
	findings, _ := risk.NormalizeFindings([]risk.Observation{
		{Code: "WEB_HSTS_MISSING", Title: "Missing HSTS", Description: "Header is absent", Evidence: "https://example.com/", Source: risk.SourceWeb},
		{Code: "WEB_CSP_MISSING", Title: "Missing CSP", Description: "CSP header absent", Evidence: "https://example.com/", Source: risk.SourceWeb},
		{Code: "URL_SUBDOMAIN_DEPTH_HIGH", Title: "High Subdomain Depth", Description: "Excessive labels", Evidence: "example.com", Source: risk.SourceURL},
		{Code: "INTEL_MALICIOUS_DOMAIN", Title: "Malicious Domain", Description: "Known phishing", Evidence: "example.com", Source: risk.SourceDomain},
	}, "https://example.com/")

	assessment, _ := risk.CalculateRisk(findings, risk.DefaultPolicy())
	assessment.Target = "https://example.com/"
	assessment.AnalyzedAt = time.Now().UTC()
	assessment.AnalysisCoverage = []risk.ComponentCoverage{
		{Component: "url", State: risk.ComponentCompleted},
		{Component: "web", State: risk.ComponentCompleted},
		{Component: "tls", State: risk.ComponentCompleted},
		{Component: "intel", State: risk.ComponentCompleted},
	}
	assessment.Limitations = []string{"Automated passive scan only"}
	return assessment
}

func BenchmarkRenderJSON(b *testing.B) {
	assessment := createBenchmarkAssessment()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := RenderJSON(assessment)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRenderMarkdown(b *testing.B) {
	assessment := createBenchmarkAssessment()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := RenderMarkdown(assessment)
		if err != nil {
			b.Fatal(err)
		}
	}
}
