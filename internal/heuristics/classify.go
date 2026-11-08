package heuristics

import (
	"fmt"
	"net/netip"
	"strings"
)

// HostType describes the syntax and local-name status of a URL destination.
type HostType string

const (
	HostTypeDNS   HostType = "dns"
	HostTypeIPv4  HostType = "ipv4"
	HostTypeIPv6  HostType = "ipv6"
	HostTypeLocal HostType = "local"
)

// Classification describes destination characteristics, not its safety or
// threat status. No DNS or network lookups are performed.
type Classification struct {
	HostType      HostType
	IsIPAddress   bool
	IsPublicIP    bool
	IsPrivateIP   bool
	IsLoopback    bool
	IsLinkLocal   bool
	IsMulticast   bool
	IsUnspecified bool
	IsLocalDomain bool
	IsLiteralIP   bool
}

// specialUsePrefixes covers notable non-public IPv4 and IPv6 allocations,
// including documentation, benchmarking, shared, and reserved ranges. This
// intentionally small list supplements netip's address properties; it is not
// a complete routing or IANA registry database.
var specialUsePrefixes = mustParsePrefixes(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"64:ff9b::/96",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
)

func mustParsePrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic("invalid built-in IP prefix " + value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// ClassifyURL classifies the parsed destination in u without resolving it.
// IsPublicIP is a conservative address-property approximation, not proof that
// an address is globally routable or safe to contact.
func ClassifyURL(u *NormalizedURL) (*Classification, error) {
	if u == nil {
		return nil, fmt.Errorf("classify URL: input is nil")
	}
	hostname := u.Hostname
	if hostname == "" {
		return nil, fmt.Errorf("classify URL: hostname is empty")
	}

	addr, err := netip.ParseAddr(hostname)
	if err == nil {
		return classifyIP(addr), nil
	}
	if u.IsIPAddress || strings.Contains(hostname, ":") || looksLikeInvalidIPv4(hostname) {
		return nil, fmt.Errorf("classify URL: malformed IP address")
	}

	local := isLocalHostname(hostname)
	hostType := HostTypeDNS
	if local {
		hostType = HostTypeLocal
	}
	return &Classification{
		HostType:      hostType,
		IsLocalDomain: local,
	}, nil
}

func classifyIP(addr netip.Addr) *Classification {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	classification := &Classification{
		IsIPAddress:   true,
		IsPrivateIP:   addr.IsPrivate(),
		IsLoopback:    addr.IsLoopback(),
		IsLinkLocal:   addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast(),
		IsMulticast:   addr.IsMulticast(),
		IsUnspecified: addr.IsUnspecified(),
	}
	if addr.Is4() {
		classification.HostType = HostTypeIPv4
	} else {
		classification.HostType = HostTypeIPv6
	}
	classification.IsLiteralIP = true
	classification.IsPublicIP = addr.IsGlobalUnicast() && !classification.IsPrivateIP && !isSpecialUse(addr)
	return classification
}

func isSpecialUse(addr netip.Addr) bool {
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isLocalHostname(hostname string) bool {
	hostname = strings.ToLower(hostname)
	if hostname == "localhost" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal"} {
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}
	return false
}
