package intel

import (
	"testing"

	"bouclier/internal/risk"
)

func TestMatchesToObservations(t *testing.T) {
	matches := []Match{
		{
			Indicator: Indicator{
				Type:       TypeURL,
				Value:      "https://phish.com/login",
				Category:   "credential-theft",
				Confidence: 95,
				Severity:   risk.SeverityCritical,
				SourceName: "PhishTank",
			},
			MatchType:   MatchExactURL,
			Freshness:   "fresh",
			Explanation: "Direct URL match",
		},
		{
			Indicator: Indicator{
				Type:       TypeDomain,
				Value:      "bad-domain.com",
				Category:   "malware",
				Confidence: 70,
				Severity:   risk.SeverityHigh,
				SourceName: "OpenIntel",
			},
			MatchType:   MatchRegistrableDomain,
			Freshness:   "stale",
			Explanation: "Historical domain match",
		},
	}

	obs := MatchesToObservations(matches)
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}

	if obs[0].Code != CodeIntelMaliciousURL {
		t.Errorf("expected %s, got %s", CodeIntelMaliciousURL, obs[0].Code)
	}
	if obs[0].Source != "threat-intelligence" {
		t.Errorf("expected source threat-intelligence, got %s", obs[0].Source)
	}

	if obs[1].Code != CodeIntelMatchStale {
		t.Errorf("expected %s for stale indicator, got %s", CodeIntelMatchStale, obs[1].Code)
	}
}

func TestMatchesDeduplicationAcrossMultipleFeeds(t *testing.T) {
	// Simulate 3 distinct threat feeds reporting the exact same malicious domain
	matches := []Match{
		{
			Indicator: Indicator{
				Type:       TypeDomain,
				Value:      "phish-site.com",
				Category:   "phishing",
				Confidence: 80,
				Severity:   risk.SeverityHigh,
				SourceName: "Feed-Alpha",
				SourceID:   "feed-a",
			},
			MatchType:   MatchExactDomain,
			Freshness:   "fresh",
			Explanation: "Domain match from Feed-Alpha",
		},
		{
			Indicator: Indicator{
				Type:       TypeDomain,
				Value:      "phish-site.com",
				Category:   "phishing",
				Confidence: 95, // Higher confidence
				Severity:   risk.SeverityHigh,
				SourceName: "Feed-Beta",
				SourceID:   "feed-b",
			},
			MatchType:   MatchExactDomain,
			Freshness:   "fresh",
			Explanation: "Domain match from Feed-Beta",
		},
		{
			Indicator: Indicator{
				Type:       TypeDomain,
				Value:      "phish-site.com",
				Category:   "phishing",
				Confidence: 75,
				Severity:   risk.SeverityHigh,
				SourceName: "Feed-Gamma",
				SourceID:   "feed-c",
			},
			MatchType:   MatchExactDomain,
			Freshness:   "fresh",
			Explanation: "Domain match from Feed-Gamma",
		},
	}

	observations := MatchesToObservations(matches)

	// Multi-feed matches on identical indicators must consolidate into 1 observation
	if len(observations) != 1 {
		t.Fatalf("expected exactly 1 consolidated observation across 3 feeds, got %d", len(observations))
	}

	obs := observations[0]
	if obs.Code != CodeIntelMaliciousDomain {
		t.Errorf("expected code %s, got %s", CodeIntelMaliciousDomain, obs.Code)
	}
	if obs.Evidence != `domain indicator "phish-site.com"` {
		t.Errorf("expected canonical evidence, got %s", obs.Evidence)
	}

	// Now normalize observations through the risk engine and verify deduplication
	target := "phish-site.com"
	normalized, err := risk.NormalizeFindings(observations, target)
	if err != nil {
		t.Fatalf("normalize findings: %v", err)
	}
	if len(normalized) != 1 {
		t.Fatalf("expected 1 normalized finding, got %d", len(normalized))
	}

	// Calculate risk score: single feed vs 3 feeds must produce identical score
	singleMatch := []Match{matches[1]}
	singleObs := MatchesToObservations(singleMatch)
	singleNormalized, err := risk.NormalizeFindings(singleObs, target)
	if err != nil {
		t.Fatalf("normalize single finding: %v", err)
	}

	policy := risk.DefaultPolicy()
	assessmentMulti, err := risk.CalculateRisk(normalized, policy)
	if err != nil {
		t.Fatalf("calculate risk multi: %v", err)
	}
	assessmentSingle, err := risk.CalculateRisk(singleNormalized, policy)
	if err != nil {
		t.Fatalf("calculate risk single: %v", err)
	}

	if assessmentMulti.OverallScore != assessmentSingle.OverallScore {
		t.Errorf("score inflation detected! multi-feed score=%d, single-feed score=%d",
			assessmentMulti.OverallScore, assessmentSingle.OverallScore)
	}
}
