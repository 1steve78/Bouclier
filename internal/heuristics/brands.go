package heuristics

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Brand describes a canonical organization domain and a small set of known
// aliases. Domains use normalized ASCII DNS form.
type Brand struct {
	Name     string
	Domain   string
	Aliases  []string
	Category string
}

var brandRegistry = []Brand{
	{Name: "Google", Domain: "google.com", Aliases: []string{"googlemail.com", "gmail.com"}, Category: "technology"},
	{Name: "Microsoft", Domain: "microsoft.com", Aliases: []string{"live.com", "outlook.com", "office.com"}, Category: "technology"},
	{Name: "Apple", Domain: "apple.com", Aliases: []string{"icloud.com"}, Category: "technology"},
	{Name: "Amazon", Domain: "amazon.com", Aliases: []string{"amazon.co.uk", "amazon.ca"}, Category: "e-commerce"},
	{Name: "PayPal", Domain: "paypal.com", Aliases: []string{"paypal.co.uk"}, Category: "payments"},
	{Name: "Netflix", Domain: "netflix.com", Category: "entertainment"},
	{Name: "Facebook", Domain: "facebook.com", Aliases: []string{"fb.com"}, Category: "social"},
	{Name: "Instagram", Domain: "instagram.com", Category: "social"},
	{Name: "WhatsApp", Domain: "whatsapp.com", Aliases: []string{"wa.me"}, Category: "messaging"},
	{Name: "GitHub", Domain: "github.com", Category: "technology"},
	{Name: "LinkedIn", Domain: "linkedin.com", Category: "social"},
	{Name: "Adobe", Domain: "adobe.com", Category: "technology"},
	{Name: "Dropbox", Domain: "dropbox.com", Category: "technology"},
	{Name: "Telegram", Domain: "telegram.org", Aliases: []string{"t.me"}, Category: "messaging"},
	{Name: "Steam", Domain: "steampowered.com", Aliases: []string{"steamcommunity.com"}, Category: "gaming"},
}

// KnownBrands returns a defensive copy of the built-in registry.
func KnownBrands() []Brand {
	brands := make([]Brand, len(brandRegistry))
	for i, brand := range brandRegistry {
		brands[i] = brand
		brands[i].Aliases = append([]string(nil), brand.Aliases...)
	}
	return brands
}

// RegistrableDomain returns the effective top-level domain plus one label,
// using the Public Suffix List snapshot bundled with x/net.
func RegistrableDomain(hostname string) (string, error) {
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" {
		return "", fmt.Errorf("registrable domain: hostname is empty")
	}
	if addr, err := netip.ParseAddr(hostname); err == nil && addr.IsValid() {
		return "", fmt.Errorf("registrable domain: IP addresses do not have a registrable domain")
	}
	asciiHostname, err := normalizeDNSHostname(hostname)
	if err != nil {
		return "", fmt.Errorf("registrable domain: invalid hostname: %w", err)
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(asciiHostname)
	if err != nil {
		return "", fmt.Errorf("registrable domain: %w", err)
	}
	return registrable, nil
}

// AnalyzeBrandImpersonation compares a normalized URL's registrable domain
// and subdomain labels with the built-in registry. It emits signals, not a
// verdict, and performs no DNS or network operations.
func AnalyzeBrandImpersonation(u *NormalizedURL) ([]Finding, error) {
	if u == nil {
		return nil, fmt.Errorf("analyze brand impersonation: URL is nil")
	}
	if u.Hostname == "" {
		return nil, fmt.Errorf("analyze brand impersonation: hostname is empty")
	}
	if u.IsIPAddress {
		return []Finding{}, nil
	}
	if addr, err := netip.ParseAddr(u.Hostname); err == nil && addr.IsValid() {
		return []Finding{}, nil
	}

	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname, "."))
	if !strings.Contains(hostname, ".") || isLocalHostname(hostname) {
		return []Finding{}, nil
	}
	registrable, err := RegistrableDomain(hostname)
	if err != nil {
		return nil, fmt.Errorf("analyze brand impersonation: %w", err)
	}

	var findings []Finding
	if !isKnownBrandDomain(registrable) {
		if exact := exactBrandLabel(registrable); exact != nil {
			findings = append(findings, *finding(
				"BRAND_EXACT_LABEL",
				"Exact brand label in registrable domain",
				"The registrable domain contains a complete brand label but is not a listed canonical brand domain or alias. This may be impersonation, though the label alone does not establish ownership or intent.",
				"brand-impersonation",
				fmt.Sprintf("registrable domain contains the exact %s label", exact.Name),
			))
		} else if match := closestBrandMatch(registrable); match != nil {
			findings = append(findings, brandMatchFinding(*match))
		}
	}

	if subdomainBrand := brandInSubdomain(hostname, registrable); subdomainBrand != nil {
		findings = append(findings, *finding(
			"BRAND_MISLEADING_SUBDOMAIN",
			"Brand name in a subdomain",
			"A brand label appears before the registrable domain. The registrable domain determines the site owner; a brand-looking subdomain can mislead readers about that destination.",
			"brand-impersonation",
			fmt.Sprintf("%s appears as a complete hostname label before the registrable domain", subdomainBrand.Name),
		))
	}
	return findings, nil
}

type brandMatch struct {
	brand     Brand
	candidate string
	distance  int
	matchType string
}

func closestBrandMatch(registrable string) *brandMatch {
	labels := strings.Split(registrable, ".")
	if len(labels) == 0 {
		return nil
	}
	candidate := labels[0]
	var best *brandMatch
	for _, brand := range brandRegistry {
		for _, token := range brandTokens(brand) {
			match := compareBrandLabel(candidate, token, brand)
			if match == nil {
				continue
			}
			if best == nil || match.distance < best.distance {
				best = match
			}
		}
	}
	return best
}

func compareBrandLabel(candidate, token string, brand Brand) *brandMatch {
	limit := allowedBrandDistance(len(token))
	if strings.HasPrefix(candidate, "xn--") {
		unicodeLabel, err := idna.Lookup.ToUnicode(candidate)
		if err != nil {
			return nil
		}
		distance, changed := unicodeBrandDistance(unicodeLabel, token)
		if !changed || distance > limit {
			return nil
		}
		return &brandMatch{brand: brand, candidate: candidate, distance: distance, matchType: "idn"}
	}

	distance, transformed := brandDistance(candidate, token)
	if distance > limit || distance == 0 && !transformed {
		return nil
	}
	matchType := "similarity"
	if transformed {
		matchType = "substitution"
	}
	return &brandMatch{brand: brand, candidate: candidate, distance: distance, matchType: matchType}
}

func allowedBrandDistance(length int) int {
	// One edit is tolerated for labels of at least five characters, and two for
	// labels of at least eight. Short brand aliases require an exact match.
	if length >= 8 {
		return 2
	}
	if length >= 5 {
		return 1
	}
	return 0
}

func brandTokens(brand Brand) []string {
	tokens := make([]string, 0, len(brand.Aliases)+1)
	for _, domain := range append([]string{brand.Domain}, brand.Aliases...) {
		labels := strings.Split(domain, ".")
		if len(labels) > 0 {
			tokens = append(tokens, labels[0])
		}
	}
	return tokens
}

func isKnownBrandDomain(registrable string) bool {
	for _, brand := range brandRegistry {
		for _, domain := range append([]string{brand.Domain}, brand.Aliases...) {
			known, err := RegistrableDomain(domain)
			if err == nil && registrable == known {
				return true
			}
		}
	}
	return false
}

func exactBrandLabel(registrable string) *Brand {
	labels := strings.Split(registrable, ".")
	for _, label := range strings.Split(labels[0], "-") {
		for _, brand := range brandRegistry {
			for _, token := range brandTokens(brand) {
				if label == token {
					copy := brand
					return &copy
				}
			}
		}
	}
	return nil
}

func brandInSubdomain(hostname, registrable string) *Brand {
	prefix := strings.TrimSuffix(hostname, "."+registrable)
	if prefix == hostname || prefix == "" {
		return nil
	}
	for _, label := range strings.Split(prefix, ".") {
		for _, brand := range brandRegistry {
			for _, token := range brandTokens(brand) {
				if label == token {
					copy := brand
					return &copy
				}
			}
		}
	}
	return nil
}

func brandMatchFinding(match brandMatch) Finding {
	switch match.matchType {
	case "idn":
		return *finding(
			"BRAND_IDN_SIMILAR_DOMAIN",
			"Internationalized label resembles a brand",
			"A Punycode hostname label decodes to text that resembles a brand under a limited common-character comparison. This is a signal for manual review, not proof of impersonation.",
			"brand-impersonation",
			fmt.Sprintf("Punycode registrable label resembles %s under limited IDN comparison", match.brand.Name),
		)
	case "substitution":
		return *finding(
			"BRAND_CHARACTER_SUBSTITUTION",
			"Brand-like character substitution",
			"The registrable label maps a limited ASCII character substitution to a known brand spelling. Character mapping is intentionally limited and does not cover every visual confusable.",
			"brand-impersonation",
			fmt.Sprintf("registrable label uses an ASCII substitution resembling %s", match.brand.Name),
		)
	default:
		return *finding(
			"BRAND_SIMILAR_DOMAIN",
			"Domain resembles a known brand",
			"The registrable label is within the configured edit-distance threshold of a brand domain. Similarity alone is not proof of impersonation.",
			"brand-impersonation",
			fmt.Sprintf("registrable label resembles %s (edit distance %d)", match.brand.Name, match.distance),
		)
	}
}
