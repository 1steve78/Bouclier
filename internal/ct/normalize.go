package ct

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"bouclier/internal/heuristics"
	"golang.org/x/net/publicsuffix"
)

// NormalizeQuery canonicalizes the hostname and enforces the explicit query
// scope. Registrable-domain scope intentionally includes names only beneath
// that registrable domain; it does not perform substring matching.
func NormalizeQuery(query Query) (Query, error) {
	if query.Scope != ScopeExactHostname && query.Scope != ScopeRegistrableDomain {
		return Query{}, fmt.Errorf("normalize CT query: %w: unknown query scope", ErrUnsupportedQuery)
	}
	if query.Limit == 0 {
		query.Limit = DefaultLimit
	}
	if query.Limit < 1 || query.Limit > MaxLimit {
		return Query{}, fmt.Errorf("normalize CT query: %w: result limit must be between 1 and %d", ErrUnsupportedQuery, MaxLimit)
	}
	hostname, err := normalizeHostname(query.Domain)
	if err != nil {
		return Query{}, fmt.Errorf("normalize CT query domain: %w", err)
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return Query{}, fmt.Errorf("normalize CT query domain: %w: domain has no registrable domain", ErrUnsupportedQuery)
	}
	if query.Scope == ScopeRegistrableDomain {
		if hostname != registrable {
			return Query{}, fmt.Errorf("normalize CT query domain: %w: registrable-domain scope requires the registrable domain itself", ErrUnsupportedQuery)
		}
		hostname = registrable
	}
	query.Domain = hostname
	return query, nil
}

// NormalizeEntries validates and canonicalizes provider entries, retains only
// entries matching query scope, then deduplicates, sorts, and applies Limit.
func NormalizeEntries(entries []CTEntry, query Query) ([]CTEntry, error) {
	normalizedQuery, err := NormalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrNoResults
	}
	filtered := make([]CTEntry, 0, len(entries))
	for index, entry := range entries {
		entry, err = normalizeEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("normalize CT entry %d: %w", index+1, err)
		}
		if matchesQuery(entry.Certificate.DNSNames, normalizedQuery) {
			filtered = append(filtered, entry)
		}
	}
	if len(filtered) == 0 {
		return nil, ErrNoResults
	}
	sort.Slice(filtered, func(i, j int) bool {
		leftID, rightID := entryIdentity(filtered[i]), entryIdentity(filtered[j])
		if leftID != rightID {
			return leftID < rightID
		}
		return entryCanonical(filtered[i]) < entryCanonical(filtered[j])
	})
	unique := filtered[:0]
	lastID := ""
	lastCanonical := ""
	for _, entry := range filtered {
		identity := entryIdentity(entry)
		if len(unique) > 0 && identity == lastID {
			if entryCanonical(entry) != lastCanonical {
				return nil, fmt.Errorf("%w: conflicting duplicate log entry", ErrInvalidResponse)
			}
			continue
		}
		unique = append(unique, entry)
		lastID = identity
		lastCanonical = entryCanonical(entry)
	}
	sort.Slice(unique, func(i, j int) bool {
		if !unique[i].EntryTimestamp.Equal(unique[j].EntryTimestamp) {
			return unique[i].EntryTimestamp.Before(unique[j].EntryTimestamp)
		}
		if unique[i].LogID != unique[j].LogID {
			return unique[i].LogID < unique[j].LogID
		}
		return unique[i].LeafIndex < unique[j].LeafIndex
	})
	if len(unique) > normalizedQuery.Limit {
		unique = unique[:normalizedQuery.Limit]
	}
	return unique, nil
}

func normalizeHostname(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", fmt.Errorf("%w: hostname is empty", ErrUnsupportedQuery)
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.IsValid() {
		return "", fmt.Errorf("%w: IP addresses cannot be queried as domains", ErrUnsupportedQuery)
	}
	if strings.ContainsAny(value, "/\\:@?#[]") {
		return "", fmt.Errorf("%w: expected a hostname, not a URL or authority", ErrUnsupportedQuery)
	}
	parsed, err := heuristics.NormalizeURL("https://" + value)
	if err != nil || parsed.IsIPAddress {
		return "", fmt.Errorf("%w: malformed hostname", ErrUnsupportedQuery)
	}
	return parsed.Hostname, nil
}

func normalizeEntry(entry CTEntry) (CTEntry, error) {
	entry.LogID = strings.TrimSpace(entry.LogID)
	entry.LogURL = strings.TrimSpace(entry.LogURL)
	if entry.LogID == "" || entry.EntryTimestamp.IsZero() {
		return CTEntry{}, fmt.Errorf("%w: log ID and entry timestamp are required", ErrInvalidResponse)
	}
	logID, err := base64.StdEncoding.DecodeString(entry.LogID)
	if err != nil || len(logID) != 32 {
		return CTEntry{}, fmt.Errorf("%w: log ID must be a 32-byte SHA-256 value encoded with standard base64", ErrInvalidResponse)
	}
	entry.LogID = base64.StdEncoding.EncodeToString(logID)
	parsedURL, err := url.Parse(entry.LogURL)
	if err != nil || parsedURL.Hostname() == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || parsedURL.Opaque != "" || !strings.EqualFold(parsedURL.Scheme, "https") {
		return CTEntry{}, fmt.Errorf("%w: invalid log URL", ErrInvalidResponse)
	}
	logHost := parsedURL.Hostname()
	if _, ipErr := netip.ParseAddr(logHost); ipErr == nil {
		return CTEntry{}, fmt.Errorf("%w: CT log URL must use a DNS hostname", ErrInvalidResponse)
	}
	normalizedLogHost, hostErr := normalizeHostname(logHost)
	if hostErr != nil || !strings.Contains(normalizedLogHost, ".") || strings.HasSuffix(normalizedLogHost, ".local") || strings.HasSuffix(normalizedLogHost, ".internal") || strings.HasSuffix(normalizedLogHost, ".localhost") {
		return CTEntry{}, fmt.Errorf("%w: unsafe log URL hostname", ErrInvalidResponse)
	}
	entry.LogURL = parsedURL.String()
	entry.EntryTimestamp = entry.EntryTimestamp.UTC()
	cert := &entry.Certificate
	cert.Subject = strings.TrimSpace(cert.Subject)
	cert.Issuer = strings.TrimSpace(cert.Issuer)
	if cert.Subject == "" || cert.Issuer == "" || cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || !cert.NotAfter.After(cert.NotBefore) {
		return CTEntry{}, fmt.Errorf("%w: certificate subject, issuer, and valid date range are required", ErrInvalidResponse)
	}
	cert.NotBefore = cert.NotBefore.UTC()
	cert.NotAfter = cert.NotAfter.UTC()
	cert.SerialNumber, err = normalizeSerial(cert.SerialNumber)
	if err != nil {
		return CTEntry{}, fmt.Errorf("%w: invalid serial number", ErrInvalidResponse)
	}
	cert.FingerprintSHA256, err = normalizeFingerprint(cert.FingerprintSHA256)
	if err != nil {
		return CTEntry{}, fmt.Errorf("%w: invalid SHA-256 fingerprint", ErrInvalidResponse)
	}
	if len(cert.DNSNames) == 0 {
		return CTEntry{}, fmt.Errorf("%w: at least one DNS SAN is required", ErrInvalidResponse)
	}
	names := make([]string, 0, len(cert.DNSNames))
	seen := make(map[string]struct{}, len(cert.DNSNames))
	for _, name := range cert.DNSNames {
		name = strings.TrimSpace(name)
		wildcard := strings.HasPrefix(name, "*.")
		toNormalize := strings.TrimPrefix(name, "*.")
		if strings.Contains(toNormalize, "*") {
			return CTEntry{}, fmt.Errorf("%w: invalid DNS SAN", ErrInvalidResponse)
		}
		if strings.Contains(name, "*") && !wildcard {
			return CTEntry{}, fmt.Errorf("%w: invalid DNS SAN", ErrInvalidResponse)
		}
		normalized, normErr := normalizeHostname(toNormalize)
		if normErr != nil {
			return CTEntry{}, fmt.Errorf("%w: invalid DNS SAN", ErrInvalidResponse)
		}
		if wildcard {
			normalized = "*." + normalized
		}
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			names = append(names, normalized)
		}
	}
	sort.Strings(names)
	cert.DNSNames = names
	return entry, nil
}

func normalizeSerial(value string) (string, error) {
	value = strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(value))
	value = strings.TrimPrefix(strings.ToLower(value), "0x")
	if value == "" {
		return "", fmt.Errorf("empty serial")
	}
	serial, ok := new(big.Int).SetString(value, 16)
	if !ok || serial.Sign() < 0 {
		return "", fmt.Errorf("invalid serial")
	}
	return strings.ToUpper(serial.Text(16)), nil
}

func normalizeFingerprint(value string) (string, error) {
	value = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(value)))
	if len(value) != 64 {
		return "", fmt.Errorf("invalid fingerprint length")
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return "", fmt.Errorf("invalid fingerprint character")
		}
	}
	return value, nil
}

func matchesQuery(names []string, query Query) bool {
	for _, name := range names {
		if query.Scope == ScopeExactHostname && name == query.Domain {
			return true
		}
		if query.Scope == ScopeRegistrableDomain {
			host := strings.TrimPrefix(name, "*.")
			registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
			if err == nil && registrable == query.Domain {
				return true
			}
		}
	}
	return false
}

func entryIdentity(entry CTEntry) string {
	return entry.LogID + "\x00" + fmt.Sprint(entry.LeafIndex)
}

func entryCanonical(entry CTEntry) string {
	certificate := entry.Certificate
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		entry.LogURL, entry.EntryTimestamp.Format(time.RFC3339Nano), certificate.Subject,
		certificate.Issuer, strings.Join(certificate.DNSNames, ","), certificate.NotBefore.Format(time.RFC3339Nano),
		certificate.NotAfter.Format(time.RFC3339Nano), certificate.SerialNumber,
		certificate.FingerprintSHA256, entry.LogID)
}
