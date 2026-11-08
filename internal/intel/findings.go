package intel

import (
	"fmt"
	"strings"

	"bouclier/internal/risk"
)

const (
	CodeIntelMaliciousURL                = "INTEL_MALICIOUS_URL"
	CodeIntelMaliciousDomain             = "INTEL_MALICIOUS_DOMAIN"
	CodeIntelMaliciousIP                 = "INTEL_MALICIOUS_IP"
	CodeIntelSuspiciousRegistrableDomain = "INTEL_SUSPICIOUS_REGISTRABLE_DOMAIN"
	CodeIntelMatchStale                  = "INTEL_MATCH_STALE"
)

// MatchesToObservations converts a slice of Match hits into risk.Observation objects
// suitable for the risk aggregation pipeline. It consolidates duplicate hits for the same
// underlying indicator across multiple feeds to prevent risk score inflation.
func MatchesToObservations(matches []Match) []risk.Observation {
	var observations []risk.Observation

	type groupKey struct {
		code      string
		indType   IndicatorType
		normValue string
	}

	groups := make(map[groupKey][]Match)
	var orderedKeys []groupKey

	for _, m := range matches {
		code := selectFindingCode(m)
		k := groupKey{
			code:      code,
			indType:   m.Indicator.Type,
			normValue: strings.ToLower(strings.TrimSpace(m.Indicator.Value)),
		}
		if _, exists := groups[k]; !exists {
			orderedKeys = append(orderedKeys, k)
		}
		groups[k] = append(groups[k], m)
	}

	for _, k := range orderedKeys {
		grouped := groups[k]
		// Choose the hit with highest confidence
		best := grouped[0]
		for _, g := range grouped[1:] {
			if g.Indicator.Confidence > best.Indicator.Confidence {
				best = g
			}
		}

		// Collect unique source names
		var sources []string
		for _, g := range grouped {
			sName := strings.TrimSpace(g.Indicator.SourceName)
			if sName == "" {
				sName = g.Indicator.SourceID
			}
			found := false
			for _, existing := range sources {
				if existing == sName {
					found = true
					break
				}
			}
			if !found {
				sources = append(sources, sName)
			}
		}

		title := selectFindingTitle(best)
		evidence := fmt.Sprintf("%s indicator %q", best.Indicator.Type, best.Indicator.Value)
		desc := best.Explanation
		if len(sources) > 1 {
			desc = fmt.Sprintf("%s (corroborated by %d feeds: %s)",
				best.Explanation, len(sources), strings.Join(sources, ", "))
		}

		observations = append(observations, risk.Observation{
			Code:        k.code,
			Title:       title,
			Description: desc,
			Category:    "threat-intelligence",
			Evidence:    evidence,
			Source:      "threat-intelligence",
		})
	}

	return observations
}

func selectFindingCode(m Match) string {
	if m.Freshness == "stale" {
		return CodeIntelMatchStale
	}

	switch m.MatchType {
	case MatchExactURL:
		return CodeIntelMaliciousURL
	case MatchExactDomain:
		return CodeIntelMaliciousDomain
	case MatchExactIP:
		return CodeIntelMaliciousIP
	case MatchRegistrableDomain:
		return CodeIntelSuspiciousRegistrableDomain
	default:
		return CodeIntelMaliciousDomain
	}
}

func selectFindingTitle(m Match) string {
	if m.Freshness == "stale" {
		return "Target matches historical threat intelligence indicator"
	}

	switch m.MatchType {
	case MatchExactURL:
		return fmt.Sprintf("Target URL identified in threat intelligence (%s)", strings.ToLower(m.Indicator.Category))
	case MatchExactDomain:
		return fmt.Sprintf("Target domain identified in threat intelligence (%s)", strings.ToLower(m.Indicator.Category))
	case MatchExactIP:
		return fmt.Sprintf("Target IP identified in threat intelligence (%s)", strings.ToLower(m.Indicator.Category))
	case MatchRegistrableDomain:
		return fmt.Sprintf("Parent domain identified in threat intelligence (%s)", strings.ToLower(m.Indicator.Category))
	default:
		return "Target identified in threat intelligence"
	}
}
