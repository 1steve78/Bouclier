package registration

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// RegistrationInfo contains only domain-level registration metadata. It has
// no fields for registrant names, email addresses, phone numbers, or addresses.
type RegistrationInfo struct {
	Domain      string
	Registrar   string
	CreatedAt   *time.Time
	UpdatedAt   *time.Time
	ExpiresAt   *time.Time
	Status      []string
	NameServers []string
	DataSource  string
	RetrievedAt time.Time
	IsRedacted  bool
}

// NormalizeDomain converts a DNS name to lowercase IDNA ASCII and returns its
// PSL-derived registrable domain. IP literals and public-suffix-only inputs
// are rejected because registration lookups are keyed by registrable domain.
func NormalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("%w: domain is empty", ErrInvalidDomain)
	}
	if address, err := netip.ParseAddr(domain); err == nil && address.IsValid() {
		return "", fmt.Errorf("%w: IP addresses are not domain names", ErrUnsupportedDomain)
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("%w: IDNA conversion failed", ErrInvalidDomain)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", fmt.Errorf("%w: hostname length is invalid", ErrInvalidDomain)
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: hostname label is invalid", ErrInvalidDomain)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return "", fmt.Errorf("%w: hostname label contains invalid characters", ErrInvalidDomain)
			}
		}
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return "", fmt.Errorf("%w: no registrable domain", ErrUnsupportedDomain)
	}
	return registrable, nil
}

// NormalizeAndValidate canonicalizes the domain, timestamps, status values,
// and nameservers in place. Optional registration dates may be absent; zero
// optional dates are represented as nil. RetrievedAt and DataSource are
// required provenance fields.
func (info *RegistrationInfo) NormalizeAndValidate() error {
	if info == nil {
		return fmt.Errorf("%w: registration info is nil", ErrInvalidProviderResponse)
	}
	domain, err := NormalizeDomain(info.Domain)
	if err != nil {
		return fmt.Errorf("validate registration domain: %w", err)
	}
	if info.RetrievedAt.IsZero() {
		return fmt.Errorf("%w: retrieval time is required", ErrInvalidProviderResponse)
	}
	if strings.TrimSpace(info.DataSource) == "" {
		return fmt.Errorf("%w: data source is required", ErrInvalidProviderResponse)
	}
	info.Domain = domain
	info.Registrar = strings.TrimSpace(info.Registrar)
	info.DataSource = strings.TrimSpace(info.DataSource)
	info.RetrievedAt = info.RetrievedAt.UTC()
	info.CreatedAt = normalizeOptionalTime(info.CreatedAt)
	info.UpdatedAt = normalizeOptionalTime(info.UpdatedAt)
	info.ExpiresAt = normalizeOptionalTime(info.ExpiresAt)
	info.Status = normalizeStrings(info.Status, true)
	info.NameServers, err = normalizeNameServers(info.NameServers)
	if err != nil {
		return err
	}
	return nil
}

func normalizeOptionalTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func normalizeStrings(values []string, lowercase bool) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lowercase {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil
	}
	return result
}

func normalizeNameServers(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if value == "" {
			continue
		}
		ascii, err := idna.Lookup.ToASCII(value)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid nameserver hostname", ErrInvalidProviderResponse)
		}
		ascii = strings.ToLower(ascii)
		if err := validateHostname(ascii); err != nil {
			return nil, fmt.Errorf("%w: invalid nameserver hostname", ErrInvalidProviderResponse)
		}
		result = append(result, ascii)
	}
	return normalizeStrings(result, true), nil
}

func validateHostname(hostname string) error {
	if hostname == "" || len(hostname) > 253 {
		return fmt.Errorf("invalid hostname length")
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid hostname label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return fmt.Errorf("invalid hostname character")
			}
		}
	}
	return nil
}
