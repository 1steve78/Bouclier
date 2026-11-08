package heuristics

import (
	"fmt"

	"golang.org/x/net/publicsuffix"
)

// suspiciousTLDs is a small review list, not a ranking or proof of abuse.
// Entries are Public Suffix List suffixes and should be updated deliberately.
var suspiciousTLDs = map[string]struct{}{
	"click":   {},
	"country": {},
	"mov":     {},
	"top":     {},
	"xyz":     {},
	"zip":     {},
}

func detectSuspiciousTLD(u *NormalizedURL, classification *Classification) (*Finding, error) {
	if u == nil {
		return nil, fmt.Errorf("detect suspicious TLD: URL is nil")
	}
	if classification == nil {
		return nil, fmt.Errorf("detect suspicious TLD: classification is nil")
	}
	if u.Hostname == "" {
		return nil, fmt.Errorf("detect suspicious TLD: hostname is empty")
	}
	if classification.IsIPAddress || classification.IsLiteralIP || classification.IsLocalDomain {
		return nil, nil
	}

	suffix, err := publicSuffixForHost(u.Hostname)
	if err != nil {
		return nil, fmt.Errorf("detect suspicious TLD: %w", err)
	}
	if _, found := suspiciousTLDs[suffix]; !found {
		return nil, nil
	}
	return finding(
		"SUSPICIOUS_TLD",
		"TLD selected for additional scrutiny",
		"This public suffix is on Bouclier's small review list and may deserve additional context. Its use does not establish that the website is malicious.",
		"domain-suffix",
		"public suffix: "+suffix,
	), nil
}

func publicSuffixForHost(hostname string) (string, error) {
	asciiHostname, err := normalizeDNSHostname(hostname)
	if err != nil {
		return "", fmt.Errorf("validate hostname: %w", err)
	}
	if _, err := RegistrableDomain(asciiHostname); err != nil {
		return "", err
	}
	suffix, _ := publicsuffix.PublicSuffix(asciiHostname)
	if suffix == "" {
		return "", fmt.Errorf("public suffix is empty")
	}
	return suffix, nil
}
