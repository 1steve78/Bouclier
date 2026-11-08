package heuristics

import (
	"fmt"
	"net/netip"
	"sort"
)

// AnalyzeDomainBrandRelationships compares a validated hostname structure
// with the existing brand registry. It is offline and does not assign a
// verdict. This independent API does not alter Phase 1 analysis results.
func AnalyzeDomainBrandRelationships(info *DomainInfo) ([]Finding, error) {
	if info == nil {
		return nil, fmt.Errorf("analyze domain brand relationships: domain info is nil")
	}
	if info.Hostname == "" {
		return nil, fmt.Errorf("analyze domain brand relationships: hostname is empty")
	}
	if address, err := netip.ParseAddr(info.Hostname); err == nil {
		if !info.IsIPAddress || address.String() != info.Hostname || info.RegistrableDomain != "" || info.PublicSuffix != "" {
			return nil, fmt.Errorf("analyze domain brand relationships: IP domain info is inconsistent")
		}
		return []Finding{}, nil
	}
	if info.IsIPAddress {
		return nil, fmt.Errorf("analyze domain brand relationships: IP flag does not match hostname")
	}

	derived, err := ExtractDomainInfo(&NormalizedURL{Hostname: info.Hostname, OriginalHostname: info.OriginalHostname})
	if err != nil {
		return nil, fmt.Errorf("analyze domain brand relationships: validate hostname: %w", err)
	}
	if !domainInfoMatches(info, derived) {
		return nil, fmt.Errorf("analyze domain brand relationships: domain fields are inconsistent with hostname")
	}
	if derived.RegistrableDomain == "" {
		return []Finding{}, nil
	}

	// Known registrable brand domains and aliases are legitimate relationship
	// matches. Their subdomains do not become impersonation signals merely for
	// containing brand or account-related labels.
	if isKnownBrandDomain(derived.RegistrableDomain) {
		return []Finding{}, nil
	}

	findings := make([]Finding, 0, 2)
	if brand := brandInSubdomain(derived.Hostname, derived.RegistrableDomain); brand != nil {
		findings = append(findings, *finding(
			"BRAND_MISLEADING_SUBDOMAIN",
			"Brand name in a misleading subdomain",
			"A known brand label appears before a registrable domain that is not listed for that brand. The registrable domain identifies a different domain relationship; the label alone does not establish intent.",
			"brand-impersonation",
			fmt.Sprintf("a subdomain label matches the %s brand", brand.Name),
		))
	}

	if brand := exactBrandLabel(derived.RegistrableDomain); brand != nil {
		findings = append(findings, *finding(
			"BRAND_IN_DOMAIN_LABEL",
			"Brand label combined with an unrelated domain",
			"A complete brand label appears as a hyphen-separated component of the registrable domain, which is not a listed brand domain or alias. This structural match is a review signal, not proof of impersonation.",
			"brand-impersonation",
			fmt.Sprintf("registrable domain contains a complete %s brand label", brand.Name),
		))
	} else if match := closestBrandMatch(derived.RegistrableDomain); match != nil {
		findings = append(findings, *domainBrandSimilarityFinding(*match))
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Code < findings[j].Code })
	return findings, nil
}

func domainBrandSimilarityFinding(match brandMatch) *Finding {
	switch match.matchType {
	case "idn":
		return finding(
			"BRAND_IDN_SIMILAR_DOMAIN",
			"Internationalized registrable label resembles a brand",
			"A Punycode registrable label resembles a known brand under the existing limited IDN comparison. This does not cover all Unicode confusables and is not proof of impersonation.",
			"brand-impersonation",
			fmt.Sprintf("Punycode registrable label resembles %s under limited IDN comparison", match.brand.Name),
		)
	case "substitution":
		return finding(
			"BRAND_SIMILAR_REGISTRABLE_DOMAIN",
			"Brand-like character substitution in registrable domain",
			"The registrable label resembles a known brand under the existing limited character substitution mapping. Similarity is a review signal, not proof of ownership or intent.",
			"brand-impersonation",
			fmt.Sprintf("registrable label uses a limited character substitution resembling %s", match.brand.Name),
		)
	default:
		return finding(
			"BRAND_SIMILAR_REGISTRABLE_DOMAIN",
			"Registrable domain resembles a known brand",
			"The registrable label is within the existing conservative edit-distance threshold for a known brand. Similarity alone does not establish impersonation.",
			"brand-impersonation",
			fmt.Sprintf("registrable label resembles %s (edit distance %d)", match.brand.Name, match.distance),
		)
	}
}
