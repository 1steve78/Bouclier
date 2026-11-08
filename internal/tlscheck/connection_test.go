package tlscheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"bouclier/internal/config"
)

type stubResolver struct {
	addresses []netip.Addr
	err       error
	called    bool
	calls     int
}

func (r *stubResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.called = true
	r.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]netip.Addr(nil), r.addresses...), r.err
}

func TestConnectionConfigUsesApplicationTimeouts(t *testing.T) {
	defaults := DefaultConnectionConfig()
	if defaults.Timeout != 8*time.Second || defaults.HandshakeTimeout != 5*time.Second || defaults.Port != "443" {
		t.Fatalf("defaults = %+v", defaults)
	}
	scanner := config.ScannerConfig{HTTPTimeout: 3 * time.Second, TLSHandshakeTimeout: time.Second}
	got := ConnectionConfigFromScannerConfig(scanner)
	if got.Timeout != scanner.HTTPTimeout || got.HandshakeTimeout != scanner.TLSHandshakeTimeout {
		t.Fatalf("mapped config = %+v", got)
	}
}

func TestInspectConnectionRejectsInvalidInput(t *testing.T) {
	for _, tt := range []struct{ hostname, port string }{
		{"", "443"}, {"bad host.example", "443"}, {"host.example/path", "443"}, {"192.0.2.999", "443"}, {"host.example", "0"}, {"host.example", "65536"}, {"host.example", "https"},
	} {
		resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
		cfg := testConfig()
		cfg.Port = tt.port
		_, err := inspectConnection(context.Background(), tt.hostname, cfg, inspectDependencies{resolver: resolver, dial: unusedDial})
		if err == nil {
			t.Errorf("inspectConnection(%q, %q) succeeded; want error", tt.hostname, tt.port)
		}
		if resolver.called {
			t.Errorf("resolver called for invalid input %q", tt.hostname)
		}
	}
}

func TestInspectConnectionRejectsUnsafeIPAddresses(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.1", "169.254.1.1", "0.0.0.0",
		"169.254.169.254", "100.100.100.200", "224.0.0.1", "::1", "::8.8.8.8",
		"fc00::1", "fe80::1", "ff02::1", "::", "::ffff:127.0.0.1",
		"64:ff9b::808:808", "2001::1", "2001:db8::1", "2002:0808:0808::1",
	} {
		t.Run(raw, func(t *testing.T) {
			addr := netip.MustParseAddr(raw)
			if isAllowedAddress(addr) {
				t.Errorf("address %s was allowed", raw)
			}
			_, err := inspectConnection(context.Background(), raw, testConfig(), inspectDependencies{dial: unusedDial})
			if err == nil {
				t.Errorf("InspectConnection accepted prohibited IP %s", raw)
			}
		})
	}
}

func TestInspectConnectionValidIPSkipsDNSAndDialsLiteral(t *testing.T) {
	resolver := &stubResolver{}
	dialed := false
	_, err := inspectConnection(context.Background(), "8.8.8.8", testConfig(), inspectDependencies{
		resolver: resolver,
		dial: func(_ context.Context, network, address string) (net.Conn, error) {
			dialed = true
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Fatalf("dial target = %s %s", network, address)
			}
			return nil, errors.New("test dial stop")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "test dial stop") {
		t.Fatalf("error = %v, want test dial result", err)
	}
	if resolver.called || !dialed {
		t.Fatalf("resolver called=%v, dialed=%v", resolver.called, dialed)
	}
}

func TestInspectConnectionRejectsLocalHostnames(t *testing.T) {
	for _, hostname := range []string{"localhost", "service.localhost", "router.local", "db.internal", "printer.lan", "host.home.arpa", "host.test", "host.example", "service.onion", "printer", "intranet", "nas", "server"} {
		resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
		_, err := inspectConnection(context.Background(), hostname, testConfig(), inspectDependencies{resolver: resolver, dial: unusedDial})
		if err == nil {
			t.Errorf("local hostname %q was accepted", hostname)
		}
		if resolver.called {
			t.Errorf("resolver called for local hostname %q", hostname)
		}
	}
}

func TestInspectConnectionRejectsScopedResolverAddress(t *testing.T) {
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("2001:4860::8888%eth0")}}
	dialCalled := false
	_, err := inspectConnection(context.Background(), "target.com", testConfig(), inspectDependencies{
		resolver: resolver,
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialCalled = true
			return nil, errors.New("unexpected dial")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "prohibited address") || dialCalled {
		t.Fatalf("error=%v, dialCalled=%v; want scoped address rejection before dial", err, dialCalled)
	}
}

func TestInspectConnectionRejectsMixedSafeAndUnsafeDNSResults(t *testing.T) {
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}}
	dialCalled := false
	_, err := inspectConnection(context.Background(), "target.com", testConfig(), inspectDependencies{
		resolver: resolver,
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialCalled = true
			return nil, errors.New("unexpected dial")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "prohibited address") {
		t.Fatalf("error = %v, want unsafe DNS response rejection", err)
	}
	if dialCalled {
		t.Fatal("dial occurred before all DNS addresses were validated")
	}
}

func TestInspectConnectionDNSResolutionError(t *testing.T) {
	resolver := &stubResolver{err: errors.New("lookup failed")}
	_, err := inspectConnection(context.Background(), "target.com", testConfig(), inspectDependencies{resolver: resolver, dial: unusedDial})
	if err == nil || !strings.Contains(err.Error(), "resolve target") {
		t.Fatalf("error = %v, want contextual DNS error", err)
	}
}

func TestInspectConnectionContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	_, err := inspectConnection(ctx, "target.com", testConfig(), inspectDependencies{resolver: resolver, dial: unusedDial})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if resolver.called {
		t.Fatal("resolver called after context cancellation")
	}
}

func TestInspectConnectionTimeout(t *testing.T) {
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	cfg := testConfig()
	cfg.Timeout = 40 * time.Millisecond
	_, err := inspectConnection(context.Background(), "target.com", cfg, inspectDependencies{
		resolver: resolver,
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestInspectConnectionSuccessfulLocalTLS(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	localAddress := server.Listener.Addr().String()
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	result, err := inspectConnection(context.Background(), "target.com", testConfigWithServerName("example.com"), inspectDependencies{
		resolver: resolver,
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "8.8.8.8:443" {
				return nil, fmt.Errorf("dial address = %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, localAddress)
		},
		roots: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.HandshakeSuccess || result.TargetHostname != "target.com" || result.ServerName != "example.com" || result.NegotiatedTLS == "" || result.CipherSuite == 0 {
		t.Fatalf("incomplete TLS result: %+v", result)
	}
	if len(result.PeerCertificates) == 0 || len(result.VerifiedChains) == 0 {
		t.Fatalf("peer chain not captured: %+v", result)
	}
	if result.Address != "8.8.8.8:443" {
		t.Errorf("reported address = %q", result.Address)
	}
	if resolver.calls != 1 {
		t.Errorf("resolver calls = %d, want exactly one", resolver.calls)
	}
}

func TestInspectConnectionRejectsDNSRebindingBeforeProhibitedDial(t *testing.T) {
	answers := [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("169.254.169.254")},
	}
	lookups := 0
	resolver := resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if lookups >= len(answers) {
			return nil, errors.New("unexpected DNS lookup")
		}
		answer := answers[lookups]
		lookups++
		return append([]netip.Addr(nil), answer...), nil
	})
	var dialed []string
	deps := inspectDependencies{
		resolver: resolver,
		dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			if address != "8.8.8.8:443" {
				return nil, errors.New("attempted to dial an unvalidated destination")
			}
			return nil, errors.New("stopped after observing validated public destination")
		},
	}
	if _, err := inspectConnection(context.Background(), "target.com", testConfig(), deps); err == nil || !strings.Contains(err.Error(), "validated public destination") {
		t.Fatalf("initial public destination error=%v; want controlled dial stop", err)
	}
	result, err := inspectConnection(context.Background(), "target.com", testConfig(), deps)
	if err == nil || result != nil || !strings.Contains(err.Error(), "prohibited address") {
		t.Fatalf("rebinding result=%+v err=%v; want prohibited DNS answer rejection", result, err)
	}
	if lookups != 2 || len(dialed) != 1 || dialed[0] != "8.8.8.8:443" {
		t.Fatalf("lookups=%d dial destinations=%v; want two lookups and only the initial public dial", lookups, dialed)
	}
}

func TestInspectConnectionDefaultTLSNameIsTarget(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	result, err := inspectConnection(context.Background(), "example.com", testConfig(), localServerDependencies(server, resolver, roots))
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetHostname != "example.com" || result.ServerName != "example.com" || resolver.calls != 1 {
		t.Fatalf("target/server name/resolver = %q/%q/%d", result.TargetHostname, result.ServerName, resolver.calls)
	}
}

func TestInspectConnectionUntrustedCertificateReturnsPeerMetadata(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	result, err := inspectConnection(context.Background(), "target.com", testConfigWithServerName("example.com"), localServerDependencies(server, &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, nil))
	assertUntrustedPeerResult(t, result, err)
}

func TestInspectConnectionHostnameMismatchReturnsPeerMetadata(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	result, err := inspectConnection(context.Background(), "target.com", testConfigWithServerName("mismatch.invalid"), localServerDependencies(server, &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, roots))
	assertUntrustedPeerResult(t, result, err)
	if result.ServerName != "mismatch.invalid" || result.TargetHostname != "target.com" {
		t.Fatalf("target and TLS identity were conflated: %+v", result)
	}
}

func TestInspectConnectionExpiredCertificateReturnsPeerMetadata(t *testing.T) {
	server, roots := expiredTLSServer(t)
	defer server.Close()
	result, err := inspectConnection(context.Background(), "target.com", testConfig(), localServerDependencies(server, &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, roots))
	assertUntrustedPeerResult(t, result, err)
}

func TestInspectConnectionTLSHandshakeFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _ = conn.Write([]byte("not a TLS record"))
			_ = conn.Close()
		}
	}()
	result, err := inspectConnection(context.Background(), "target.com", testConfig(), inspectDependencies{
		resolver: &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	})
	if err == nil || !strings.Contains(err.Error(), "TLS handshake failed") {
		t.Fatalf("error = %v, want handshake error", err)
	}
	if result != nil {
		t.Fatalf("result = %+v; no peer certificate was received", result)
	}
}

func TestInspectConnectionHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			buffer := make([]byte, 1024)
			_, _ = conn.Read(buffer)
			<-time.After(200 * time.Millisecond)
		}
	}()
	cfg := testConfig()
	cfg.HandshakeTimeout = 40 * time.Millisecond
	_, err = inspectConnection(context.Background(), "target.com", cfg, inspectDependencies{
		resolver: &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want handshake deadline", err)
	}
}

func TestNormalizeTargetIDNAndPortValidation(t *testing.T) {
	got, isIP, err := normalizeTarget("bücher.example")
	if err != nil || isIP || got != "xn--bcher-kva.example" {
		t.Fatalf("normalizeTarget() = (%q, %v, %v)", got, isIP, err)
	}
	if err := validatePort("443"); err != nil {
		t.Fatal(err)
	}
}

func TestInspectConnectionRejectsInvalidServerNameBeforeResolution(t *testing.T) {
	resolver := &stubResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	cfg := testConfigWithServerName("bad server name")
	_, err := inspectConnection(context.Background(), "target.com", cfg, inspectDependencies{resolver: resolver, dial: unusedDial})
	if err == nil || resolver.called {
		t.Fatalf("error=%v resolverCalled=%v; want invalid override rejected before DNS", err, resolver.called)
	}
}

func TestInspectConnectionCancellationDuringResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	resolver := resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	finished := make(chan error, 1)
	go func() {
		_, err := inspectConnection(ctx, "target.com", testConfig(), inspectDependencies{resolver: resolver, dial: unusedDial})
		finished <- err
	}()
	<-started
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("inspection did not stop after cancellation")
	}
}

func testConfig() ConnectionConfig {
	return ConnectionConfig{Timeout: time.Second, HandshakeTimeout: time.Second, Port: "443"}
}

func testConfigWithServerName(serverName string) ConnectionConfig {
	cfg := testConfig()
	cfg.ServerName = serverName
	return cfg
}

func unusedDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected network dial")
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func localServerDependencies(server *httptest.Server, resolver resolver, roots *x509.CertPool) inspectDependencies {
	return inspectDependencies{
		resolver: resolver,
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		roots: roots,
	}
}

func assertUntrustedPeerResult(t *testing.T, result *TLSConnectionResult, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected TLS verification error")
	}
	if result == nil || result.HandshakeSuccess || len(result.PeerCertificates) == 0 {
		t.Fatalf("failed handshake did not preserve peer metadata: result=%+v err=%v", result, err)
	}
	if len(result.VerifiedChains) != 0 {
		t.Fatalf("failed handshake represented chains as verified: %+v", result.VerifiedChains)
	}
}

func expiredTLSServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bouclier test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "target.com"},
		DNSNames: []string{"target.com"}, NotBefore: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leafCert}
	server := httptest.NewUnstartedServer(nil)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return server, roots
}
