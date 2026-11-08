package heuristics

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	// Three subdomain labels warrant review; five are a stronger nesting signal.
	minNoteworthySubdomainLabels = 3
	strongSubdomainLabels        = 5
	// 180 is well below the 253-byte DNS hostname limit but above routine hostnames.
	longStructuredHostnameLength = 180
	// DNS labels may be 63 bytes; lengths above 50 are unusual but valid.
	longStructuredLabelLength = 50
	// Four hyphens in one label or a run of three is unusual; a normal compound
	// label such as "my-company" is below this threshold.
	excessiveHyphensPerLabel = 4
	maxHyphenRun             = 2
	// Numeric-heavy labels need at least five characters and four digits, and
	// must be at least 70% numeric. Fully numeric infrastructure labels are ignored.
	minNumericHeavyLabelLength = 5
	minNumericHeavyDigits      = 4
	minNumericHeavyRatio       = 0.70
)

var accountSubdomainTerms = map[string]struct{}{
	"account": {}, "auth": {}, "banking": {}, "billing": {}, "confirm": {},
	"login": {}, "password": {}, "payment": {}, "recover": {}, "secure": {},
	"signin": {}, "verify": {}, "wallet": {},
}

// AnalyzeDomainStructure emits deterministic structural observations from a
// validated DomainInfo. It does not perform network access or assign a verdict.
// This API is intentionally independent of AnalyzeURL/AnalyzePatterns so its
// findings do not duplicate existing Phase 1 URL signals.
func AnalyzeDomainStructure(info *DomainInfo) ([]Finding, error) {
	if info == nil {
		return nil, fmt.Errorf("analyze domain structure: domain info is nil")
	}
	if info.Hostname == "" {
		return nil, fmt.Errorf("analyze domain structure: hostname is empty")
	}
	if address, err := netip.ParseAddr(info.Hostname); err == nil {
		if !info.IsIPAddress || address.String() != info.Hostname || info.RegistrableDomain != "" || info.PublicSuffix != "" {
			return nil, fmt.Errorf("analyze domain structure: IP domain info is inconsistent")
		}
		return []Finding{}, nil
	}
	if info.IsIPAddress {
		return nil, fmt.Errorf("analyze domain structure: IP flag does not match hostname")
	}

	derived, err := ExtractDomainInfo(&NormalizedURL{Hostname: info.Hostname, OriginalHostname: info.OriginalHostname})
	if err != nil {
		return nil, fmt.Errorf("analyze domain structure: validate hostname: %w", err)
	}
	if !domainInfoMatches(info, derived) {
		return nil, fmt.Errorf("analyze domain structure: domain fields are inconsistent with hostname")
	}

	findings := make([]Finding, 0, 6)
	if count := len(derived.SubdomainLabels); count >= minNoteworthySubdomainLabels {
		strength := "noteworthy"
		if count >= strongSubdomainLabels {
			strength = "stronger"
		}
		findings = append(findings, *finding(
			"EXCESSIVE_SUBDOMAIN_DEPTH",
			"Deep subdomain nesting",
			"Several labels before the registrable domain can make the destination harder to inspect. Nesting alone does not indicate maliciousness.",
			"domain-structure",
			fmt.Sprintf("%d subdomain labels (%s structural signal; noteworthy threshold: %d, stronger threshold: %d)", count, strength, minNoteworthySubdomainLabels, strongSubdomainLabels),
		))
	}

	if len(derived.Hostname) > longStructuredHostnameLength {
		findings = append(findings, *finding(
			"LONG_HOSTNAME",
			"Long hostname",
			"This valid hostname is long compared with routine domain names and may be harder to read. DNS permits hostnames up to 253 bytes; length alone is not evidence of abuse.",
			"domain-structure",
			fmt.Sprintf("canonical hostname is %d bytes (review threshold: %d; DNS limit: 253)", len(derived.Hostname), longStructuredHostnameLength),
		))
	}

	if length := longestLabelLength(derived.Hostname); length > longStructuredLabelLength {
		findings = append(findings, *finding(
			"LONG_DOMAIN_LABEL",
			"Long hostname label",
			"A hostname label is unusually long while remaining within DNS label limits. Label length alone does not indicate maliciousness.",
			"domain-structure",
			fmt.Sprintf("longest label is %d bytes (review threshold: %d; DNS limit: 63)", length, longStructuredLabelLength),
		))
	}

	if count, run := excessiveHyphenSignal(derived.Hostname); count > 0 || run > maxHyphenRun {
		evidence := fmt.Sprintf("one label contains %d hyphens", count)
		if run > maxHyphenRun {
			evidence = fmt.Sprintf("one label contains a consecutive hyphen run of %d", run)
		}
		findings = append(findings, *finding(
			"EXCESSIVE_HYPHENS",
			"Unusually hyphenated hostname label",
			"A hostname label has several hyphens or a repeated hyphen run. Ordinary compound labels are not flagged.",
			"domain-structure",
			evidence,
		))
	}

	if digits, length, found := numericHeavyLabel(derived.Hostname); found {
		findings = append(findings, *finding(
			"NUMERIC_HEAVY_LABEL",
			"Numeric-heavy hostname label",
			"A non-numeric hostname label contains a high proportion of digits. Numeric labels can be legitimate infrastructure names, so this is only a structural observation.",
			"domain-structure",
			fmt.Sprintf("a label contains %d digits in %d characters (review threshold: %.0f%%)", digits, length, minNumericHeavyRatio*100),
		))
	}

	if terms := subdomainAccountTerms(derived.SubdomainLabels); len(terms) >= 2 {
		findings = append(findings, *finding(
			"SUSPICIOUS_SUBDOMAIN_COMBINATION",
			"Multiple account-related subdomain labels",
			"Multiple security or account-related terms appear in subdomain labels before the registrable domain. These terms may also occur in legitimate services.",
			"domain-structure",
			fmt.Sprintf("%d distinct account-related terms across subdomain labels", len(terms)),
		))
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Code < findings[j].Code })
	return findings, nil
}

func domainInfoMatches(got, want *DomainInfo) bool {
	return got.Hostname == want.Hostname &&
		got.RegistrableDomain == want.RegistrableDomain &&
		got.PublicSuffix == want.PublicSuffix &&
		got.Subdomain == want.Subdomain &&
		got.DomainDepth == want.DomainDepth &&
		got.IsIPAddress == want.IsIPAddress &&
		strings.Join(got.SubdomainLabels, "\x00") == strings.Join(want.SubdomainLabels, "\x00") &&
		strings.Join(got.DomainLabels, "\x00") == strings.Join(want.DomainLabels, "\x00")
}

func longestLabelLength(hostname string) int {
	longest := 0
	for _, label := range strings.Split(hostname, ".") {
		if len(label) > longest {
			longest = len(label)
		}
	}
	return longest
}

func excessiveHyphenSignal(hostname string) (int, int) {
	for _, label := range strings.Split(hostname, ".") {
		// The two adjacent hyphens at positions 3-4 are required in Punycode.
		punycodePrefix := strings.HasPrefix(label, "xn--")
		measured := label
		if punycodePrefix {
			measured = label[4:]
		}
		count := strings.Count(measured, "-")
		run := longestHyphenRun(measured)
		if count >= excessiveHyphensPerLabel || run > maxHyphenRun {
			return count, run
		}
	}
	return 0, 0
}

func longestHyphenRun(label string) int {
	longest, current := 0, 0
	for _, r := range label {
		if r == '-' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	return longest
}

func numericHeavyLabel(hostname string) (int, int, bool) {
	for _, label := range strings.Split(hostname, ".") {
		digits := 0
		for _, r := range label {
			if r >= '0' && r <= '9' {
				digits++
			}
		}
		if len(label) >= minNumericHeavyLabelLength && digits >= minNumericHeavyDigits && digits < len(label) && float64(digits)/float64(len(label)) >= minNumericHeavyRatio {
			return digits, len(label), true
		}
	}
	return 0, 0, false
}

func subdomainAccountTerms(labels []string) map[string]struct{} {
	terms := make(map[string]struct{})
	for _, label := range labels {
		for _, token := range strings.Split(label, "-") {
			if _, found := accountSubdomainTerms[token]; found {
				terms[token] = struct{}{}
			}
		}
	}
	return terms
}
