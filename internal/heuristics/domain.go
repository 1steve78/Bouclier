package heuristics

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DomainInfo describes the canonical hostname structure without performing
// DNS, HTTP, WHOIS, or other network lookups.
type DomainInfo struct {
	OriginalHostname  string
	Hostname          string
	RegistrableDomain string
	PublicSuffix      string
	Subdomain         string
	SubdomainLabels   []string
	DomainLabels      []string
	DomainDepth       int
	IsIPAddress       bool
}

// ExtractDomainInfo returns the structural DNS components of a normalized
// URL's hostname. IP literals have no registrable domain or public suffix.
// A hostname consisting only of a Public Suffix List suffix is represented
// with an empty RegistrableDomain instead of inferring an extra label.
func ExtractDomainInfo(u *NormalizedURL) (*DomainInfo, error) {
	if u == nil {
		return nil, fmt.Errorf("extract domain info: URL is nil")
	}
	if u.Hostname == "" {
		return nil, fmt.Errorf("extract domain info: hostname is empty")
	}

	originalHostname := u.OriginalHostname
	if originalHostname == "" {
		originalHostname = u.Hostname
	}

	if address, err := netip.ParseAddr(u.Hostname); err == nil {
		hostname := address.String()
		return &DomainInfo{
			OriginalHostname: originalHostname,
			Hostname:         hostname,
			IsIPAddress:      true,
		}, nil
	}
	if u.IsIPAddress || strings.Contains(u.Hostname, ":") || looksLikeInvalidIPv4(u.Hostname) {
		return nil, fmt.Errorf("extract domain info: hostname is not a valid IP literal or DNS name")
	}

	hostname, err := normalizeDNSHostname(u.Hostname)
	if err != nil {
		return nil, fmt.Errorf("extract domain info: invalid hostname: %w", err)
	}
	labels := strings.Split(hostname, ".")
	publicSuffixName, _ := publicsuffix.PublicSuffix(hostname)
	if publicSuffixName == "" {
		return nil, fmt.Errorf("extract domain info: public suffix is empty")
	}
	info := &DomainInfo{
		OriginalHostname: originalHostname,
		Hostname:         hostname,
		PublicSuffix:     publicSuffixName,
		DomainDepth:      len(labels),
	}

	registrable, err := RegistrableDomain(hostname)
	if err != nil {
		if hostname == publicSuffixName {
			return info, nil
		}
		return nil, fmt.Errorf("extract domain info: derive registrable domain: %w", err)
	}
	info.RegistrableDomain = registrable
	info.DomainLabels = strings.Split(registrable, ".")

	if hostname != registrable {
		subdomain := strings.TrimSuffix(hostname, "."+registrable)
		if subdomain == hostname {
			return nil, fmt.Errorf("extract domain info: registrable domain is not a hostname suffix")
		}
		info.Subdomain = subdomain
		info.SubdomainLabels = strings.Split(subdomain, ".")
	}
	return info, nil
}
