// Package ct defines normalized, provider-independent Certificate
// Transparency query and entry models. It performs no network requests.
package ct

import "time"

// QueryScope controls which DNS names are included in a query result.
type QueryScope string

const (
	ScopeExactHostname     QueryScope = "exact_hostname"
	ScopeRegistrableDomain QueryScope = "registrable_domain"
	DefaultLimit                      = 100
	MaxLimit                          = 1000
)

// Query identifies either one canonical hostname or a registrable domain.
// Domain is normalized to lowercase IDNA ASCII by NormalizeQuery.
type Query struct {
	Domain string
	Scope  QueryScope
	Limit  int
}

// CTEntry is a sanitized summary of one transparency log entry.
type CTEntry struct {
	// LogID is the RFC 6962 SHA-256 log identifier encoded with padded
	// standard base64.
	LogID          string
	LogURL         string
	EntryTimestamp time.Time
	LeafIndex      uint64
	Certificate    CertificateSummary
}

// CertificateSummary contains selected metadata only; raw certificate data
// and public keys are intentionally excluded.
type CertificateSummary struct {
	Subject           string
	Issuer            string
	DNSNames          []string
	NotBefore         time.Time
	NotAfter          time.Time
	SerialNumber      string
	FingerprintSHA256 string
}
