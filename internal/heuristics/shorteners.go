package heuristics

import "fmt"

// shortenerDomains contains known domains that issue shortened URLs. Matching
// is performed on the PSL-derived registrable domain, never on substrings.
var shortenerDomains = map[string]struct{}{
	"bit.ly":      {},
	"tinyurl.com": {},
	"t.co":        {},
	"is.gd":       {},
	"buff.ly":     {},
	"rebrand.ly":  {},
	"shorturl.at": {},
}

func detectShortener(u *NormalizedURL, classification *Classification) (*Finding, error) {
	if u == nil {
		return nil, fmt.Errorf("detect URL shortener: URL is nil")
	}
	if classification == nil {
		return nil, fmt.Errorf("detect URL shortener: classification is nil")
	}
	if u.Hostname == "" {
		return nil, fmt.Errorf("detect URL shortener: hostname is empty")
	}
	if classification.IsIPAddress || classification.IsLiteralIP || classification.IsLocalDomain {
		return nil, nil
	}

	registrable, err := RegistrableDomain(u.Hostname)
	if err != nil {
		return nil, fmt.Errorf("detect URL shortener: %w", err)
	}
	if _, found := shortenerDomains[registrable]; !found {
		return nil, nil
	}
	return finding(
		"URL_SHORTENER",
		"Known URL shortener domain",
		"This known shortening domain can conceal the eventual destination. Inspect the link carefully; a shortener URL is not inherently malicious.",
		"url-shortener",
		"registrable domain: "+registrable,
	), nil
}
