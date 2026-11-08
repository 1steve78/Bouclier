package ct

import (
	"errors"
	"testing"
	"time"
)

func TestNormalizeEntryIDNWildcardAndUTC(t *testing.T) {
	entry := testEntry("log-id", 5, "*.bücher.example", time.Date(2024, 1, 1, 3, 0, 0, 0, time.FixedZone("offset", 3*60*60)))
	entry.LogID = " " + entry.LogID + " "
	entry.Certificate.DNSNames = []string{"*.bücher.example", "xn--bcher-kva.example", "*.xn--bcher-kva.example"}
	normalized, err := normalizeEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.LogID != testLogID("log-id") || normalized.EntryTimestamp.Location() != time.UTC || normalized.Certificate.NotBefore.Location() != time.UTC {
		t.Fatalf("metadata not normalized: %+v", normalized)
	}
	if len(normalized.Certificate.DNSNames) != 2 || normalized.Certificate.DNSNames[0] != "*.xn--bcher-kva.example" || normalized.Certificate.DNSNames[1] != "xn--bcher-kva.example" {
		t.Fatalf("DNS SANs not canonical: %#v", normalized.Certificate.DNSNames)
	}
}

func TestNormalizeEntryRejectsMalformedMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CTEntry)
	}{
		{"missing log ID", func(e *CTEntry) { e.LogID = " " }},
		{"malformed log ID encoding", func(e *CTEntry) { e.LogID = "not-base64" }},
		{"wrong log ID length", func(e *CTEntry) { e.LogID = "AQ==" }},
		{"missing timestamp", func(e *CTEntry) { e.EntryTimestamp = time.Time{} }},
		{"invalid URL", func(e *CTEntry) { e.LogURL = "file:///tmp/log" }},
		{"HTTP URL", func(e *CTEntry) { e.LogURL = "http://ct.example/log" }},
		{"URL credentials", func(e *CTEntry) { e.LogURL = "https://user:pass@ct.example/log" }},
		{"URL fragment", func(e *CTEntry) { e.LogURL = "https://ct.example/log#token" }},
		{"URL query", func(e *CTEntry) { e.LogURL = "https://ct.example/log?token=x" }},
		{"IP URL host", func(e *CTEntry) { e.LogURL = "https://192.0.2.1/log" }},
		{"missing certificate subject", func(e *CTEntry) { e.Certificate.Subject = "" }},
		{"invalid certificate dates", func(e *CTEntry) { e.Certificate.NotAfter = e.Certificate.NotBefore }},
		{"invalid serial", func(e *CTEntry) { e.Certificate.SerialNumber = "xyz" }},
		{"invalid fingerprint", func(e *CTEntry) { e.Certificate.FingerprintSHA256 = "not-a-hash" }},
		{"invalid SAN", func(e *CTEntry) { e.Certificate.DNSNames = []string{"bad..example"} }},
		{"invalid wildcard", func(e *CTEntry) { e.Certificate.DNSNames = []string{"foo.*.example"} }},
		{"no DNS SAN", func(e *CTEntry) { e.Certificate.DNSNames = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := testEntry("log", 1, "example.com", time.Unix(1, 0))
			tt.mutate(&entry)
			if _, err := normalizeEntry(entry); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("normalizeEntry error=%v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestNormalizeEntriesRejectsConflictingDuplicateIdentity(t *testing.T) {
	first := testEntry("same-log", 7, "example.com", time.Unix(1, 0))
	conflict := first
	conflict.Certificate = first.Certificate
	conflict.Certificate.FingerprintSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := NormalizeEntries([]CTEntry{first, conflict}, Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("conflicting duplicate error=%v, want ErrInvalidResponse", err)
	}
}

func TestNormalizeEntriesRejectsOutOfScopeAndReturnsNoResults(t *testing.T) {
	entry := testEntry("log", 1, "notexample.com", time.Unix(1, 0))
	if _, err := NormalizeEntries([]CTEntry{entry}, Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, ErrNoResults) {
		t.Fatalf("out-of-scope result error=%v", err)
	}
	entry.Certificate.DNSNames = []string{"other.example.net"}
	if _, err := NormalizeEntries([]CTEntry{entry}, Query{Domain: "example.com", Scope: ScopeRegistrableDomain}); !errors.Is(err, ErrNoResults) {
		t.Fatalf("unrelated registrable domain error=%v", err)
	}
}
