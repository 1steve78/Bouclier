package ct

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

type fakeProvider struct {
	entries []CTEntry
	err     error
	query   Query
	called  bool
}

type waitingProvider struct{ started chan struct{} }

func (p waitingProvider) Search(ctx context.Context, _ Query) ([]CTEntry, error) {
	close(p.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *fakeProvider) Search(_ context.Context, query Query) ([]CTEntry, error) {
	p.called = true
	p.query = query
	return p.entries, p.err
}

func TestQueryEntriesExactAndRegistrableScopes(t *testing.T) {
	entries := []CTEntry{
		testEntry("l1", 1, "login.example.com", time.Unix(2, 0)),
		testEntry("l1", 2, "example.com.evil.org", time.Unix(1, 0)),
		testEntry("l1", 3, "www.example.com", time.Unix(3, 0)),
		testEntry("l1", 4, "notexample.com", time.Unix(4, 0)),
	}
	exact := &fakeProvider{entries: entries}
	got, err := QueryEntries(context.Background(), exact, Query{Domain: "LOGIN.EXAMPLE.COM.", Scope: ScopeExactHostname})
	if err != nil || len(got) != 1 || got[0].LeafIndex != 1 || exact.query.Domain != "login.example.com" || exact.query.Limit != DefaultLimit {
		t.Fatalf("exact query got=%+v query=%+v err=%v", got, exact.query, err)
	}
	registrable := &fakeProvider{entries: entries}
	got, err = QueryEntries(context.Background(), registrable, Query{Domain: "example.com", Scope: ScopeRegistrableDomain})
	if err != nil || len(got) != 2 || registrable.query.Domain != "example.com" {
		t.Fatalf("registrable query got=%+v query=%+v err=%v", got, registrable.query, err)
	}
}

func TestQueryEntriesIDNAAndPunycode(t *testing.T) {
	entry := testEntry("log", 1, "bücher.example", time.Unix(1, 0))
	provider := &fakeProvider{entries: []CTEntry{entry}}
	got, err := QueryEntries(context.Background(), provider, Query{Domain: "bücher.example", Scope: ScopeExactHostname})
	if err != nil || len(got) != 1 || got[0].Certificate.DNSNames[0] != "xn--bcher-kva.example" {
		t.Fatalf("unicode result=%+v err=%v", got, err)
	}
	provider = &fakeProvider{entries: []CTEntry{entry}}
	got, err = QueryEntries(context.Background(), provider, Query{Domain: "xn--bcher-kva.example", Scope: ScopeExactHostname})
	if err != nil || len(got) != 1 || got[0].Certificate.DNSNames[0] != "xn--bcher-kva.example" {
		t.Fatalf("punycode result=%+v err=%v", got, err)
	}
}

func TestNormalizeQueryRejectsInvalidAndIPDomains(t *testing.T) {
	for _, domain := range []string{"", "127.0.0.1", "::1", "example..com", "-bad.example", "example.com/path", "co.uk"} {
		if _, err := NormalizeQuery(Query{Domain: domain, Scope: ScopeExactHostname}); !errors.Is(err, ErrUnsupportedQuery) {
			t.Errorf("NormalizeQuery(%q) error=%v, want ErrUnsupportedQuery", domain, err)
		}
	}
	if _, err := NormalizeQuery(Query{Domain: "example.com", Scope: "substring"}); !errors.Is(err, ErrUnsupportedQuery) {
		t.Fatalf("unsupported scope error=%v", err)
	}
	if _, err := NormalizeQuery(Query{Domain: "example.com", Scope: ScopeExactHostname, Limit: MaxLimit + 1}); !errors.Is(err, ErrUnsupportedQuery) {
		t.Fatalf("oversized limit error=%v", err)
	}
	if _, err := NormalizeQuery(Query{Domain: "login.example.com", Scope: ScopeRegistrableDomain}); !errors.Is(err, ErrUnsupportedQuery) {
		t.Fatalf("registrable scope silently broadened subdomain: %v", err)
	}
}

func TestNormalizeEntriesMetadataDedupSortAndLimit(t *testing.T) {
	newer := testEntry("log-b", 2, "a.example.com", time.Date(2024, 2, 1, 1, 0, 0, 0, time.FixedZone("offset", 3600)))
	newer.Certificate.SerialNumber = "0x000A"
	newer.Certificate.FingerprintSHA256 = "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"
	older := testEntry("log-a", 1, "example.com", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	results, err := NormalizeEntries([]CTEntry{newer, older, newer}, Query{Domain: "example.com", Scope: ScopeRegistrableDomain, Limit: 1})
	if err != nil || len(results) != 1 || results[0].LogID != testLogID("log-a") {
		t.Fatalf("normalized result=%+v err=%v", results, err)
	}
	all, err := NormalizeEntries([]CTEntry{newer, older, newer}, Query{Domain: "example.com", Scope: ScopeRegistrableDomain})
	if err != nil || len(all) != 2 {
		t.Fatalf("deduplicated results=%+v err=%v", all, err)
	}
	if all[0].EntryTimestamp.Location() != time.UTC || all[1].Certificate.SerialNumber != "A" || all[1].Certificate.FingerprintSHA256 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("entry normalization failed: %+v", all)
	}
}

func TestQueryEntriesProviderErrorsNoResultsAndCancellation(t *testing.T) {
	provider := &fakeProvider{err: ErrRateLimited}
	if _, err := QueryEntries(context.Background(), provider, Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("provider error=%v", err)
	}
	provider = &fakeProvider{}
	if _, err := QueryEntries(context.Background(), provider, Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, ErrNoResults) {
		t.Fatalf("empty result error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	provider = &fakeProvider{entries: []CTEntry{testEntry("log", 1, "example.com", time.Now())}}
	cancel()
	if _, err := QueryEntries(ctx, provider, Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, context.Canceled) || provider.called {
		t.Fatalf("cancel error=%v provider called=%v", err, provider.called)
	}
	ctx, cancel = context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, queryErr := QueryEntries(ctx, waitingProvider{started: started}, Query{Domain: "example.com", Scope: ScopeExactHostname})
		done <- queryErr
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("in-progress provider cancellation error=%v", err)
	}
	for _, providerErr := range []error{ErrProviderUnavailable, context.DeadlineExceeded, ErrInvalidResponse} {
		provider = &fakeProvider{err: providerErr}
		if _, err := QueryEntries(context.Background(), provider, Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, providerErr) {
			t.Errorf("provider error %v not preserved: %v", providerErr, err)
		}
	}
}

func testEntry(log string, index uint64, san string, timestamp time.Time) CTEntry {
	return CTEntry{
		LogID: testLogID(log), LogURL: "https://ct.example/log", EntryTimestamp: timestamp, LeafIndex: index,
		Certificate: CertificateSummary{
			Subject: "CN=example", Issuer: "CN=test CA", DNSNames: []string{san},
			NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			SerialNumber: "01", FingerprintSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
}

func testLogID(value string) string {
	id := sha256.Sum256([]byte(value))
	return base64.StdEncoding.EncodeToString(id[:])
}
