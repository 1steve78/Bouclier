package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// IndicatorType classifies the kind of threat intelligence indicator.
type IndicatorType string

const (
	TypeDomain IndicatorType = "domain"
	TypeURL    IndicatorType = "url"
	TypeIPv4   IndicatorType = "ipv4"
	TypeIPv6   IndicatorType = "ipv6"

	// MaxIndicatorLength bounds indicator values to prevent memory and parsing abuse.
	MaxIndicatorLength = 8192
	// MaxDomainLength is the maximum allowed domain name length (RFC 1035).
	MaxDomainLength = 253
)

var (
	ErrInvalidIndicatorType  = errors.New("invalid indicator type")
	ErrInvalidIndicatorValue = errors.New("invalid indicator value")
	ErrMalformedIndicator    = errors.New("malformed indicator")
	ErrExpiredIndicator      = errors.New("indicator has expired")
)

// ValidIndicatorType checks if the given type is supported.
func ValidIndicatorType(t IndicatorType) bool {
	switch t {
	case TypeDomain, TypeURL, TypeIPv4, TypeIPv6:
		return true
	default:
		return false
	}
}

// Indicator represents a normalized threat intelligence record.
type Indicator struct {
	ID          string            `json:"id"`
	Type        IndicatorType     `json:"type"`
	Value       string            `json:"value"` // Canonical normalized value
	SourceID    string            `json:"source_id"`
	SourceName  string            `json:"source_name"`
	Category    string            `json:"category"`   // e.g. "phishing", "malware", "c2", "suspicious"
	Confidence  int               `json:"confidence"` // 0-100
	Severity    risk.Severity     `json:"severity"`   // informational, low, medium, high, critical
	FirstSeen   *time.Time        `json:"first_seen,omitempty"`
	LastSeen    *time.Time        `json:"last_seen,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	IngestedAt  time.Time         `json:"ingested_at"`
	SourceRef   string            `json:"source_ref,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// DeterministicID generates a reproducible ID for an indicator based on source, type, and normalized value.
func DeterministicID(sourceID string, indType IndicatorType, normalizedValue string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(sourceID)))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(string(indType))))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(normalizedValue)))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// NormalizeIndicator validates and normalizes an indicator value according to its type.
func NormalizeIndicator(indType IndicatorType, rawValue string) (string, error) {
	val := strings.TrimSpace(rawValue)
	if val == "" {
		return "", fmt.Errorf("%w: value is empty", ErrInvalidIndicatorValue)
	}
	if len(val) > MaxIndicatorLength {
		return "", fmt.Errorf("%w: value exceeds maximum length of %d bytes", ErrInvalidIndicatorValue, MaxIndicatorLength)
	}

	for _, r := range val {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: control characters are not permitted", ErrInvalidIndicatorValue)
		}
	}

	switch indType {
	case TypeDomain:
		return normalizeDomainIndicator(val)
	case TypeURL:
		return normalizeURLIndicator(val)
	case TypeIPv4:
		return normalizeIPv4Indicator(val)
	case TypeIPv6:
		return normalizeIPv6Indicator(val)
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidIndicatorType, indType)
	}
}

func normalizeDomainIndicator(val string) (string, error) {
	if len(val) > MaxDomainLength {
		return "", fmt.Errorf("%w: domain exceeds %d characters: %q", ErrInvalidIndicatorValue, MaxDomainLength, val)
	}
	// Reject URLs, schemes, ports, or paths in domain indicators
	if strings.Contains(val, "://") || strings.Contains(val, "/") || strings.Contains(val, "\\") {
		return "", fmt.Errorf("%w: domain cannot contain scheme, slashes, or path: %q", ErrInvalidIndicatorValue, val)
	}
	if strings.Contains(val, "@") {
		return "", fmt.Errorf("%w: domain cannot contain userinfo: %q", ErrInvalidIndicatorValue, val)
	}
	if strings.Contains(val, ":") {
		return "", fmt.Errorf("%w: domain cannot contain port: %q", ErrInvalidIndicatorValue, val)
	}
	if strings.Contains(val, " ") || strings.Contains(val, "\t") {
		return "", fmt.Errorf("%w: domain cannot contain whitespace: %q", ErrInvalidIndicatorValue, val)
	}

	val = strings.TrimSuffix(val, ".")
	val = strings.ToLower(val)

	// Check if it's an IP literal
	if _, err := netip.ParseAddr(val); err == nil {
		return "", fmt.Errorf("%w: IP literal %q must use ipv4/ipv6 indicator type, not domain", ErrInvalidIndicatorValue, val)
	}

	ascii, err := idna.Lookup.ToASCII(val)
	if err != nil {
		return "", fmt.Errorf("%w: invalid IDNA domain %q: %v", ErrInvalidIndicatorValue, val, err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))

	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: domain must have at least two labels: %q", ErrInvalidIndicatorValue, val)
	}
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("%w: empty label in domain %q", ErrInvalidIndicatorValue, val)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("%w: label exceeds 63 characters in domain %q", ErrInvalidIndicatorValue, val)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%w: label cannot start or end with hyphen in domain %q", ErrInvalidIndicatorValue, val)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return "", fmt.Errorf("%w: invalid character %q in domain label %q", ErrInvalidIndicatorValue, r, label)
			}
		}
	}

	// The root TLD (last label) must be a recognized ICANN TLD
	lastLabel := labels[len(labels)-1]
	if _, icann := publicsuffix.PublicSuffix(lastLabel); !icann {
		return "", fmt.Errorf("%w: unrecognized top-level domain %q in %q", ErrInvalidIndicatorValue, lastLabel, val)
	}

	// Validate public suffix and registrable domain
	if _, err := heuristics.RegistrableDomain(ascii); err != nil {
		return "", fmt.Errorf("%w: invalid domain or unrecognized public suffix %q: %v", ErrInvalidIndicatorValue, val, err)
	}

	return ascii, nil
}

func normalizeURLIndicator(val string) (string, error) {
	norm, err := heuristics.NormalizeURL(val)
	if err != nil {
		return "", fmt.Errorf("%w: invalid URL: %v", ErrInvalidIndicatorValue, err)
	}
	return norm.Normalized, nil
}

func normalizeIPv4Indicator(val string) (string, error) {
	addr, err := netip.ParseAddr(val)
	if err != nil {
		return "", fmt.Errorf("%w: invalid IPv4 address %q: %v", ErrInvalidIndicatorValue, val, err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("%w: expected IPv4, got %q", ErrInvalidIndicatorValue, val)
	}
	return addr.String(), nil
}

func normalizeIPv6Indicator(val string) (string, error) {
	val = strings.TrimPrefix(val, "[")
	val = strings.TrimSuffix(val, "]")
	addr, err := netip.ParseAddr(val)
	if err != nil {
		return "", fmt.Errorf("%w: invalid IPv6 address %q: %v", ErrInvalidIndicatorValue, val, err)
	}
	if !addr.Is6() {
		return "", fmt.Errorf("%w: expected IPv6, got %q", ErrInvalidIndicatorValue, val)
	}
	return addr.String(), nil
}

// Validate ensures the indicator fields meet all domain requirements.
func (ind *Indicator) Validate() error {
	if ind == nil {
		return fmt.Errorf("%w: nil indicator", ErrMalformedIndicator)
	}
	if !ValidIndicatorType(ind.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidIndicatorType, ind.Type)
	}
	if strings.TrimSpace(ind.Value) == "" {
		return fmt.Errorf("%w: empty value", ErrInvalidIndicatorValue)
	}
	if strings.TrimSpace(ind.SourceID) == "" {
		return fmt.Errorf("%w: empty source_id", ErrMalformedIndicator)
	}
	if strings.TrimSpace(ind.SourceName) == "" {
		return fmt.Errorf("%w: empty source_name", ErrMalformedIndicator)
	}
	if strings.TrimSpace(ind.Category) == "" {
		return fmt.Errorf("%w: empty category", ErrMalformedIndicator)
	}
	if ind.Confidence < 0 || ind.Confidence > 100 {
		return fmt.Errorf("%w: confidence must be between 0 and 100, got %d", ErrMalformedIndicator, ind.Confidence)
	}
	switch ind.Severity {
	case risk.SeverityInformational, risk.SeverityLow, risk.SeverityMedium, risk.SeverityHigh, risk.SeverityCritical:
	default:
		return fmt.Errorf("%w: invalid severity %q", ErrMalformedIndicator, ind.Severity)
	}

	normVal, err := NormalizeIndicator(ind.Type, ind.Value)
	if err != nil {
		return err
	}
	ind.Value = normVal

	if ind.ID == "" {
		ind.ID = DeterministicID(ind.SourceID, ind.Type, ind.Value)
	}

	if ind.IngestedAt.IsZero() {
		ind.IngestedAt = time.Now().UTC()
	}

	if ind.FirstSeen != nil && ind.LastSeen != nil && ind.LastSeen.Before(*ind.FirstSeen) {
		return fmt.Errorf("%w: last_seen is before first_seen", ErrMalformedIndicator)
	}
	if ind.FirstSeen != nil && ind.ExpiresAt != nil && ind.ExpiresAt.Before(*ind.FirstSeen) {
		return fmt.Errorf("%w: expires_at is before first_seen", ErrMalformedIndicator)
	}

	return nil
}

// IsExpired checks whether the indicator is expired at the given reference time.
// Policy:
// - Expired: expires_at <= reference_time (expired indicators never match)
// - Active:  expires_at > reference_time, or expires_at == nil (no expiration)
func (ind *Indicator) IsExpired(at time.Time) bool {
	if ind.ExpiresAt == nil {
		return false
	}
	return !ind.ExpiresAt.After(at)
}
