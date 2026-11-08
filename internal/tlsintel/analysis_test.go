package tlsintel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/ct"
	"bouclier/internal/heuristics"
	"bouclier/internal/tlscheck"
)

type fakeCTProvider struct {
	entries []ct.CTEntry
	err     error
	query   ct.Query
	calls   int
}

func (p *fakeCTProvider) Search(_ context.Context, query ct.Query) ([]ct.CTEntry, error) {
	p.calls++
	p.query = query
	return p.entries, p.err
}

func testCertificate(t *testing.T, dnsName string, notBefore, notAfter time.Time) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsName},
		DNSNames: []string{dnsName}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return cert, roots
}

func testCTEntry(now time.Time) ct.CTEntry {
	return ct.CTEntry{
		LogID: base64.StdEncoding.EncodeToString(make([]byte, 32)), LogURL: "https://ct.example/log",
		EntryTimestamp: now, LeafIndex: 7,
		Certificate: ct.CertificateSummary{
			Subject: "CN=example.com", Issuer: "CN=Example CA", DNSNames: []string{"example.com"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), SerialNumber: "01",
			FingerprintSHA256: strings.Repeat("a", 64),
		},
	}
}

func testInput(t *testing.T, raw string) *heuristics.NormalizedURL {
	t.Helper()
	input, err := heuristics.NormalizeURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func fakeInspector(cert *x509.Certificate, handshakeOK bool, inspectErr error) inspectFunc {
	return func(_ context.Context, host string, cfg tlscheck.ConnectionConfig) (*tlscheck.TLSConnectionResult, error) {
		if host != "example.com" {
			return nil, errors.New("unexpected target hostname")
		}
		if cfg.Timeout <= 0 || cfg.HandshakeTimeout <= 0 {
			return nil, errors.New("timeouts were not configured")
		}
		serverName := cfg.ServerName
		if serverName == "" {
			serverName = host
		}
		result := &tlscheck.TLSConnectionResult{
			TargetHostname: host, ServerName: serverName, Address: "93.184.216.34:443",
			HandshakeSuccess: handshakeOK,
		}
		if cert != nil {
			result.PeerCertificates = []*x509.Certificate{cert}
		}
		return result, inspectErr
	}
}

func TestAnalyzeTLSSuccessfulPipelineAndExplicitScope(t *testing.T) {
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	cert, roots := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	provider := &fakeCTProvider{entries: []ct.CTEntry{testCTEntry(now)}}
	options := Options{Certificate: certanalysis.Config{Roots: roots}, CTProvider: provider, CurrentTime: now}
	result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com/path?token=secret"), options, fakeInspector(cert, true, nil), certanalysis.AnalyzeCertificates)
	if err != nil {
		t.Fatal(err)
	}
	if result.TLSStatus.State != StateCompleted || result.CertificateStatus.State != StateCompleted || result.CTStatus.State != StateCompleted {
		t.Fatalf("component states: TLS=%s cert=%s CT=%s", result.TLSStatus.State, result.CertificateStatus.State, result.CTStatus.State)
	}
	if result.Connection == nil || result.Certificate == nil || len(result.CertificateTransparency) != 1 {
		t.Fatalf("incomplete result: %+v", result)
	}
	if provider.query.Scope != ct.ScopeExactHostname || provider.query.Domain != "example.com" {
		t.Fatalf("default CT query = %+v", provider.query)
	}
	if strings.Contains(result.TargetHostname, "secret") || strings.Contains(result.CTStatus.Error, "secret") {
		t.Fatal("sensitive query value leaked into result")
	}
	if result.Certificate.PathTrusted != true || result.Certificate.ChainValidAtTime != true {
		t.Fatalf("certificate trust semantics changed: %+v", result.Certificate)
	}
}

func TestAnalyzeTLSOptionalCTStatuses(t *testing.T) {
	now := time.Now().UTC()
	cert, roots := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	for _, tc := range []struct {
		name     string
		provider *fakeCTProvider
		want     ComponentState
		wantErr  error
	}{
		{name: "provider missing", want: StateSkipped},
		{name: "no results", provider: &fakeCTProvider{err: ct.ErrNoResults}, want: StateNoResults, wantErr: ct.ErrNoResults},
		{name: "unavailable", provider: &fakeCTProvider{err: ct.ErrProviderUnavailable}, want: StateFailed, wantErr: ct.ErrProviderUnavailable},
		{name: "rate limited", provider: &fakeCTProvider{err: ct.ErrRateLimited}, want: StateFailed, wantErr: ct.ErrRateLimited},
		{name: "truncated", provider: &fakeCTProvider{entries: []ct.CTEntry{testCTEntry(now)}, err: ct.ErrResultsTruncated}, want: StatePartial, wantErr: ct.ErrResultsTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := Options{Certificate: certanalysis.Config{Roots: roots}, CTProvider: tc.provider, CurrentTime: now}
			result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com"), options, fakeInspector(cert, true, nil), certanalysis.AnalyzeCertificates)
			if err != nil {
				t.Fatal(err)
			}
			if result.TLSStatus.State != StateCompleted || result.CertificateStatus.State != StateCompleted || result.CTStatus.State != tc.want {
				t.Fatalf("statuses TLS=%s cert=%s CT=%s", result.TLSStatus.State, result.CertificateStatus.State, result.CTStatus.State)
			}
			if tc.wantErr != nil && !errors.Is(result.CTStatus.Err, tc.wantErr) {
				t.Fatalf("CT error %v does not wrap %v", result.CTStatus.Err, tc.wantErr)
			}
			if tc.want == StatePartial && len(result.CertificateTransparency) != 1 {
				t.Fatal("partial CT entries were discarded")
			}
		})
	}
}

func TestAnalyzeTLSFailurePreservesAvailableResults(t *testing.T) {
	now := time.Now().UTC()
	valid, roots := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	untrusted := errors.New("TLS handshake verification failed")
	result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com"), Options{Certificate: certanalysis.Config{Roots: roots}, CurrentTime: now}, fakeInspector(valid, false, untrusted), certanalysis.AnalyzeCertificates)
	if err != nil {
		t.Fatal(err)
	}
	if result.TLSStatus.State != StateFailed || result.Connection == nil || result.Connection.HandshakeSuccess {
		t.Fatalf("failed handshake result was not preserved: %+v", result)
	}
	if result.Certificate == nil || result.Certificate.TLSHandshakeSuccess {
		t.Fatalf("certificate metadata was not analyzed as untrusted: %+v", result.Certificate)
	}
	if result.Certificate.PathTrusted && result.Certificate.ChainTrusted == false {
		t.Fatal("compatibility trust alias changed unexpectedly")
	}

	noPeerErr := errors.New("connection failed")
	result, err = analyzeTLS(context.Background(), testInput(t, "https://example.com"), Options{}, fakeInspector(nil, false, noPeerErr), certanalysis.AnalyzeCertificates)
	if err != nil || result.TLSStatus.State != StateFailed || result.CertificateStatus.State != StateSkipped || result.Certificate != nil {
		t.Fatalf("no-peer partial result = result:%+v error:%v", result, err)
	}
}

func TestAnalyzeTLSCTDoesNotChangeCertificateTrustOrVerdict(t *testing.T) {
	now := time.Now().UTC()
	cert, _ := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	provider := &fakeCTProvider{entries: []ct.CTEntry{testCTEntry(now)}}
	result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com"), Options{CTProvider: provider, CurrentTime: now}, fakeInspector(cert, false, errors.New("untrusted handshake")), certanalysis.AnalyzeCertificates)
	if err != nil {
		t.Fatal(err)
	}
	if result.CTStatus.State != StateCompleted || result.Certificate.PathTrusted || result.Certificate.ChainTrusted {
		t.Fatalf("CT changed trust result: cert=%+v CT=%+v", result.Certificate, result.CTStatus)
	}
	for _, finding := range result.Findings {
		if strings.Contains(strings.ToLower(finding.Code), "ct") {
			t.Fatalf("CT observation became a finding: %+v", finding)
		}
	}
}

func TestAnalyzeTLSKeepsConnectionAndServerNameDistinct(t *testing.T) {
	now := time.Now().UTC()
	cert, roots := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	options := Options{Connection: tlscheck.ConnectionConfig{ServerName: "login.example.net"}, Certificate: certanalysis.Config{Roots: roots}}
	result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com"), options, fakeInspector(cert, true, nil), certanalysis.AnalyzeCertificates)
	if err != nil {
		t.Fatal(err)
	}
	if result.Connection.TargetHostname != "example.com" || result.Connection.ServerName != "login.example.net" || result.Certificate.ServerName != result.Connection.ServerName {
		t.Fatalf("target/TLS identity conflated: connection=%+v certificate=%+v", result.Connection, result.Certificate)
	}
}

func TestAnalyzeTLSReportsExpiredAndMismatchedPeerCertificates(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name        string
		certName    string
		notBefore   time.Time
		notAfter    time.Time
		wantFinding string
	}{
		{name: "expired", certName: "example.com", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour), wantFinding: "CERT_EXPIRED"},
		{name: "hostname mismatch", certName: "other.example", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), wantFinding: "CERT_HOSTNAME_MISMATCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, roots := testCertificate(t, tc.certName, tc.notBefore, tc.notAfter)
			result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com"), Options{
				Certificate: certanalysis.Config{Roots: roots}, CurrentTime: now,
			}, fakeInspector(cert, false, errors.New("verification failed")), certanalysis.AnalyzeCertificates)
			if err != nil {
				t.Fatal(err)
			}
			if result.Certificate == nil || result.Certificate.TLSHandshakeSuccess {
				t.Fatalf("failed-handshake certificate result missing: %+v", result.Certificate)
			}
			for _, finding := range result.Findings {
				if finding.Code == tc.wantFinding {
					return
				}
			}
			t.Fatalf("finding %q not present: %+v", tc.wantFinding, result.Findings)
		})
	}
}

func TestAnalyzeTLSRejectsInvalidInputsBeforeInspection(t *testing.T) {
	called := false
	inspect := func(context.Context, string, tlscheck.ConnectionConfig) (*tlscheck.TLSConnectionResult, error) {
		called = true
		return nil, nil
	}
	for _, tc := range []struct {
		name    string
		input   *heuristics.NormalizedURL
		options Options
	}{
		{name: "nil input"},
		{name: "invalid hostname", input: &heuristics.NormalizedURL{Normalized: "https://bad host", Hostname: "bad host"}},
		{name: "inconsistent hostname", input: testInput(t, "https://example.com"), options: Options{CTScope: ct.QueryScope("implicit_subdomain")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := analyzeTLS(context.Background(), tc.input, tc.options, inspect, certanalysis.AnalyzeCertificates)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if called {
		t.Fatal("TLS inspector called for invalid input")
	}
}

func TestAnalyzeTLSInvalidScopeAndCancellation(t *testing.T) {
	called := false
	inspect := func(context.Context, string, tlscheck.ConnectionConfig) (*tlscheck.TLSConnectionResult, error) {
		called = true
		return nil, nil
	}
	input := testInput(t, "https://example.com")
	if _, err := analyzeTLS(context.Background(), input, Options{CTScope: "invalid"}, inspect, certanalysis.AnalyzeCertificates); err == nil {
		t.Fatal("invalid CT scope accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzeTLS(ctx, input, Options{}, inspect, certanalysis.AnalyzeCertificates); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if called {
		t.Fatal("inspector called after pre-cancellation")
	}
}

func TestAnalyzeTLSCertificateFailureAndContextDuringCT(t *testing.T) {
	now := time.Now().UTC()
	cert, roots := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	provider := &fakeCTProvider{err: ct.ErrRateLimited}
	result, err := analyzeTLS(context.Background(), testInput(t, "https://example.com"), Options{Certificate: certanalysis.Config{Roots: roots}, CTProvider: provider}, fakeInspector(cert, true, nil), func(*tlscheck.TLSConnectionResult, certanalysis.Config) (*certanalysis.CertificateAnalysis, error) {
		return nil, errors.New("certificate analysis failed")
	})
	if err != nil || result.CertificateStatus.State != StateFailed || result.TLSStatus.State != StateCompleted || result.CTStatus.State != StateFailed {
		t.Fatalf("component failure handling: result=%+v err=%v", result, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancellingProvider := ctProviderFunc(func(ctx context.Context, _ ct.Query) ([]ct.CTEntry, error) {
		cancel()
		return nil, ctx.Err()
	})
	result, err = analyzeTLS(ctx, testInput(t, "https://example.com"), Options{Certificate: certanalysis.Config{Roots: roots}, CTProvider: cancellingProvider, CurrentTime: now}, fakeInspector(cert, true, nil), certanalysis.AnalyzeCertificates)
	if !errors.Is(err, context.Canceled) || result.Certificate == nil || result.TLSStatus.State != StateCompleted || result.CTStatus.State != StateFailed {
		t.Fatalf("context partial result=%+v err=%v", result, err)
	}
}

type ctProviderFunc func(context.Context, ct.Query) ([]ct.CTEntry, error)

func (f ctProviderFunc) Search(ctx context.Context, query ct.Query) ([]ct.CTEntry, error) {
	return f(ctx, query)
}

func TestAnalyzeTLSRegistrableScopeAndIPSkipsCT(t *testing.T) {
	now := time.Now().UTC()
	cert, roots := testCertificate(t, "example.com", now.Add(-time.Hour), now.Add(time.Hour))
	provider := &fakeCTProvider{err: ct.ErrNoResults}
	result, err := analyzeTLS(context.Background(), testInput(t, "https://login.example.co.uk"), Options{CTProvider: provider, CTScope: ct.ScopeRegistrableDomain, Certificate: certanalysis.Config{Roots: roots}}, func(_ context.Context, host string, _ tlscheck.ConnectionConfig) (*tlscheck.TLSConnectionResult, error) {
		return &tlscheck.TLSConnectionResult{TargetHostname: host, ServerName: host, PeerCertificates: []*x509.Certificate{cert}, HandshakeSuccess: true}, nil
	}, certanalysis.AnalyzeCertificates)
	if err != nil {
		t.Fatal(err)
	}
	if provider.query.Domain != "example.co.uk" || provider.query.Scope != ct.ScopeRegistrableDomain {
		t.Fatalf("registrable scope query = %+v", provider.query)
	}
	if !strings.HasPrefix(result.TargetHostname, "login.") {
		t.Fatalf("target hostname changed: %q", result.TargetHostname)
	}

	ipProvider := &fakeCTProvider{err: ct.ErrNoResults}
	ipURL := testInput(t, "https://8.8.8.8")
	ipResult, err := analyzeTLS(context.Background(), ipURL, Options{CTProvider: ipProvider}, func(_ context.Context, host string, _ tlscheck.ConnectionConfig) (*tlscheck.TLSConnectionResult, error) {
		return nil, errors.New("test stopped before dial")
	}, certanalysis.AnalyzeCertificates)
	if err != nil || ipResult.CTStatus.State != StateSkipped || ipProvider.calls != 0 {
		t.Fatalf("IP CT handling result=%+v calls=%d err=%v", ipResult, ipProvider.calls, err)
	}
}

func TestFindingsDeduplicateAndSortDeterministically(t *testing.T) {
	findings := []certanalysis.Finding{
		{Code: "B", Evidence: "two"}, {Code: "A", Evidence: "one"},
		{Code: "A", Evidence: "one"}, {Code: "A", Evidence: "other"},
	}
	got := deduplicateFindings(findings)
	if len(got) != 3 || got[0].Code != "A" || got[0].Evidence != "one" || got[1].Evidence != "other" || got[2].Code != "B" {
		t.Fatalf("deduped findings = %+v", got)
	}
}
