package risk

import (
	"testing"
	"time"

	"bouclier/internal/heuristics"
)

func BenchmarkRiskAggregation(b *testing.B) {
	urlResult := &heuristics.AnalysisResult{
		Findings: []heuristics.Finding{
			{Code: "URL_SUBDOMAIN_DEPTH_HIGH", Title: "Deep subdomains", Category: "structure", Evidence: "sub.example.com"},
			{Code: "URL_BRAND_NAME_IN_SUBDOMAIN", Title: "Brand name in subdomain", Category: "brand", Evidence: "paypal"},
		},
	}

	intelObs := []Observation{
		{
			Code:        "INTEL_MALICIOUS_DOMAIN",
			Category:    "threat-intelligence",
			Title:       "Malicious Domain",
			Description: "Reported as phishing domain",
			Evidence:    "example.com",
			Source:      "threat-intelligence",
		},
	}

	coverage := &IntelligenceCoverage{
		Ran:                  true,
		SourcesConfigured:    2,
		SourcesEnabled:       2,
		IndicatorsConsidered: 1500,
		MatchesCount:         1,
	}

	input := AggregationInput{
		Target:            "https://sub.example.com/login",
		AnalyzedAt:        time.Now().UTC(),
		URL:               urlResult,
		IntelObservations: intelObs,
		IntelCoverage:     coverage,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := AggregateDefault(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
