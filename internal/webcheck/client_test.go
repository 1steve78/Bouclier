package webcheck

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/heuristics"
)

type fixedResolver struct {
	addresses []netip.Addr
	calls     atomic.Int32
}

type sequenceResolver struct {
	answers [][]netip.Addr
	calls   atomic.Int32
}

func (r *sequenceResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	i := int(r.calls.Add(1)) - 1
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i >= len(r.answers) {
		return nil, errors.New("unexpected lookup")
	}
	return append([]netip.Addr(nil), r.answers[i]...), nil
}

func (r *fixedResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]netip.Addr(nil), r.addresses...), nil
}

func testWebClient(t *testing.T, handler http.Handler, options ClientOptions) (*Client, *httptest.Server, *fixedResolver) {
	t.Helper()
	server := httptest.NewServer(handler)
	resolver := &fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dialer := &net.Dialer{}
	client, err := newClient(options, resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:80" {
			return nil, errors.New("unexpected pinned destination")
		}
		return dialer.DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return client, server, resolver
}

func normalized(t *testing.T, raw string) *heuristics.NormalizedURL {
	t.Helper()
	u, err := heuristics.NormalizeURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func makeTLSPair(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair, cert
}

func TestClientPinsValidatedIPAndSanitizesResponse(t *testing.T) {
	client, _, resolver := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request: %s %#v", r.Method, r.Header)
		}
		if r.Host != "example.com" {
			t.Errorf("HTTP Host = %q, want original hostname", r.Host)
		}
		if r.Header.Get("User-Agent") != "test-agent" {
			t.Errorf("user-agent = %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Add("Set-Cookie", "sid=super-secret; Secure; HttpOnly; SameSite=Lax")
		w.Header().Set("Location", "https://example.com/?token=response-secret")
		w.Header().Set("X-Debug-Link", "https://example.com/path?token=header-secret")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}), ClientOptions{UserAgent: "test-agent"})
	result, err := client.Inspect(context.Background(), normalized(t, "http://user:password@example.com/path?token=request-secret#fragment"))
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("DNS lookups = %d", resolver.calls.Load())
	}
	if result.RequestedURL != "http://example.com/path" || result.FinalURL != "http://example.com/path" {
		t.Fatalf("URLs were not sanitized: %+v", result)
	}
	if result.BytesRead == 0 || !result.IsHTML || string(result.HTML) != "<html>ok</html>" {
		t.Fatalf("body metadata: %+v", result)
	}
	if result.Headers.Get("Set-Cookie") != "" || strings.Contains(strings.Join(result.Headers.Values("Location"), ""), "secret") {
		t.Fatal("sensitive response headers exposed")
	}
	if strings.Contains(result.Headers.Get("X-Debug-Link"), "header-secret") || !strings.Contains(result.Headers.Get("X-Debug-Link"), "example.com/path") {
		t.Fatalf("header URL was not safely redacted: %q", result.Headers.Get("X-Debug-Link"))
	}
	findings, err := AnalyzeCookies(result)
	if err != nil || len(findings) != 1 || findings[0].Code != "WEB_COOKIE_SESSION_OVER_HTTP" {
		t.Fatalf("secure cookie analysis: %v %v", findings, err)
	}
	if len(result.CookieAttributes) != 1 || result.CookieAttributes[0].Name != "sid" {
		t.Fatalf("cookie attributes = %+v", result.CookieAttributes)
	}
	for _, attribute := range result.CookieAttributes {
		if strings.Contains(attribute.Name, "super-secret") {
			t.Fatal("cookie value leaked")
		}
	}
}

func TestClientRedirectsAndEnforcesEachDestination(t *testing.T) {
	var targetCalls atomic.Int32
	client, _, resolver := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "http://other.com/end?token=hidden", http.StatusFound)
		case "/end":
			targetCalls.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("done"))
		default:
			http.NotFound(w, r)
		}
	}), ClientOptions{MaxRedirects: 2})
	result, err := client.Inspect(context.Background(), normalized(t, "http://example.com/start"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RedirectChain) != 1 || !result.CrossOriginRedirect || result.RedirectChain[0].Destination != "http://other.com/end" {
		t.Fatalf("redirect result = %+v", result)
	}
	if targetCalls.Load() != 1 || resolver.calls.Load() != 2 {
		t.Fatalf("requests=%d DNS lookups=%d", targetCalls.Load(), resolver.calls.Load())
	}

	unsafe, _, unsafeResolver := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "http://127.0.0.1/private", http.StatusFound)
			return
		}
		t.Error("unsafe redirect request was sent")
	}), ClientOptions{})
	partial, err := unsafe.Inspect(context.Background(), normalized(t, "http://example.com/"))
	if err == nil || partial == nil || unsafeResolver.calls.Load() != 1 {
		t.Fatalf("unsafe redirect result=%+v err=%v lookups=%d", partial, err, unsafeResolver.calls.Load())
	}
}

func TestClientRevalidatesRedirectDNSBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "http://redirect.example.net/private", http.StatusFound)
	}))
	defer server.Close()
	resolver := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("8.8.8.8")}, {netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("10.0.0.1")}}}
	dialer := &net.Dialer{}
	var dialed []string
	client, err := newClient(ClientOptions{}, resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if address != "8.8.8.8:80" {
			return nil, errors.New("unexpected destination")
		}
		return dialer.DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Inspect(context.Background(), normalized(t, "http://example.com"))
	if err == nil || result == nil || requests.Load() != 1 || resolver.calls.Load() != 2 {
		t.Fatalf("redirect was not rejected safely: result=%+v err=%v requests=%d lookups=%d", result, err, requests.Load(), resolver.calls.Load())
	}
	if len(dialed) != 1 || dialed[0] != "8.8.8.8:80" {
		t.Fatalf("redirect dial destinations = %v, want only the initial validated address", dialed)
	}
}

func TestClientRejectsDNSRebindingOnSubsequentInspection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	resolver := &sequenceResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	dialer := &net.Dialer{}
	var dialed []string
	client, err := newClient(ClientOptions{}, resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if address != "8.8.8.8:80" {
			return nil, errors.New("attempted to dial an unvalidated destination")
		}
		return dialer.DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Inspect(context.Background(), normalized(t, "http://target.com")); err != nil {
		t.Fatalf("initial public destination inspection failed: %v", err)
	}
	result, err := client.Inspect(context.Background(), normalized(t, "http://target.com"))
	if !errors.Is(err, ErrUnsafeTarget) || result == nil {
		t.Fatalf("rebinding inspection result=%+v err=%v; want prohibited DNS answer rejection", result, err)
	}
	if resolver.calls.Load() != 2 || len(dialed) != 1 || dialed[0] != "8.8.8.8:80" {
		t.Fatalf("lookups=%d dial destinations=%v; want two lookups and only the initial public dial", resolver.calls.Load(), dialed)
	}
}

func TestClientRejectsUnsupportedRedirectLimits(t *testing.T) {
	for _, redirects := range []int{0, config.MaxRedirectsLimit} {
		if _, err := newClient(ClientOptions{MaxRedirects: redirects}, &fixedResolver{}, unusedWebDial); err != nil {
			t.Errorf("newClient rejected max redirects %d: %v", redirects, err)
		}
	}
	for _, redirects := range []int{-1, config.MaxRedirectsLimit + 1} {
		if _, err := newClient(ClientOptions{MaxRedirects: redirects}, &fixedResolver{}, unusedWebDial); err == nil {
			t.Errorf("newClient accepted max redirects %d", redirects)
		}
	}
}

func unusedWebDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}

func TestClientRejectsLoopbackRedirectBeforeDial(t *testing.T) {
	var dials atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1/private", http.StatusFound)
	}))
	defer server.Close()
	resolver := &fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	dialer := &net.Dialer{}
	client, err := newClient(ClientOptions{}, resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != "8.8.8.8:80" {
			return nil, errors.New("attempted to dial an unvalidated destination")
		}
		return dialer.DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Inspect(context.Background(), normalized(t, "http://example.com"))
	if !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("loopback redirect error = %v, want ErrUnsafeTarget", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want only the initial validated destination", got)
	}
}

func TestClientRejectsUnsafeAddressesAndPorts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []netip.Addr
		raw       string
	}{
		{"loopback", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, "http://example.com"},
		{"mapped loopback", []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, "http://example.com"},
		{"mixed resolution", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.2")}, "http://example.com"},
		{"shared address space", []netip.Addr{netip.MustParseAddr("100.64.0.1")}, "http://example.com"},
		{"hex-like IPv4 hostname resolving to loopback", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, "http://0x7f.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fixedResolver{addresses: tc.addresses}
			dialCalled := false
			client, err := newClient(ClientOptions{}, resolver, func(context.Context, string, string) (net.Conn, error) {
				dialCalled = true
				return nil, errors.New("unexpected dial")
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Inspect(context.Background(), normalized(t, tc.raw))
			if !errors.Is(err, ErrUnsafeTarget) || dialCalled {
				t.Fatalf("unsafe destination accepted or dialed: %v", err)
			}
		})
	}
	resolver := &fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	client, err := newClient(ClientOptions{}, resolver, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected dial") })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Inspect(context.Background(), normalized(t, "http://example.com:8080")); err == nil {
		t.Fatal("nonstandard port accepted")
	}
	if _, err := client.Inspect(context.Background(), normalized(t, "http://printer")); err == nil {
		t.Fatal("single-label hostname accepted")
	}
}

func TestAllowedWebAddressRejectsSpecialUseRanges(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3", "10.0.0.1", "127.0.0.1", "169.254.1.1", "169.254.169.254",
		"172.16.0.1", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "100.64.0.1",
		"100.100.100.200", "::", "::1", "::8.8.8.8", "fc00::1", "fe80::1", "ff02::1",
		"::ffff:10.0.0.1", "64:ff9b::808:808", "100::1", "2001::1", "2001:db8::1",
		"2002:0808:0808::1", "3fff::1",
	} {
		t.Run(raw, func(t *testing.T) {
			addr := netip.MustParseAddr(raw)
			if allowedWebAddress(addr) {
				t.Errorf("unsafe address %s was allowed", addr)
			}
		})
	}
}

func TestClientBodyLimitCompressionAndNonHTML(t *testing.T) {
	client, _, _ := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/compressed" {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			z := gzip.NewWriter(w)
			_, _ = z.Write([]byte(strings.Repeat("x", 1000)))
			_ = z.Close()
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(strings.Repeat("a", 1000)))
	}), ClientOptions{MaxBodyBytes: 100})
	compressed, err := client.Inspect(context.Background(), normalized(t, "http://example.com/compressed"))
	if err != nil || !compressed.BodyTruncated || len(compressed.HTML) != 100 {
		t.Fatalf("compressed result=%+v err=%v", compressed, err)
	}
	nonHTML, err := client.Inspect(context.Background(), normalized(t, "http://example.com/data"))
	if err != nil || nonHTML.IsHTML || len(nonHTML.HTML) != 0 || !nonHTML.BodyTruncated || nonHTML.BytesRead != 101 {
		t.Fatalf("non-HTML result=%+v err=%v", nonHTML, err)
	}
}

func TestClientRedirectLimitAndLoop(t *testing.T) {
	client, _, _ := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loop" {
			http.Redirect(w, r, "/loop", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}), ClientOptions{MaxRedirects: 1})
	if _, err := client.Inspect(context.Background(), normalized(t, "http://example.com/loop")); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("loop error = %v", err)
	}
	result, err := client.Inspect(context.Background(), normalized(t, "http://example.com/start"))
	if err == nil || result == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("limit result=%+v err=%v", result, err)
	}
}

func TestClientCancellation(t *testing.T) {
	started := make(chan struct{})
	client, _, _ := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }), ClientOptions{Timeout: time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	input := normalized(t, "http://example.com")
	go func() { _, err := client.Inspect(ctx, input); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestClientTimeout(t *testing.T) {
	started := make(chan struct{})
	client, _, _ := testWebClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }), ClientOptions{Timeout: time.Second})
	done := make(chan struct {
		result *HTTPInspectionResult
		err    error
	}, 1)
	input := normalized(t, "http://example.com")
	go func() {
		result, err := client.Inspect(context.Background(), input)
		done <- struct {
			result *HTTPInspectionResult
			err    error
		}{result, err}
	}()
	<-started
	out := <-done
	if !errors.Is(out.err, context.DeadlineExceeded) || out.result == nil {
		t.Fatalf("timeout result=%+v err=%v", out.result, out.err)
	}
}

func TestClientHTTPSPreservesHostIdentity(t *testing.T) {
	pair, cert := makeTLSPair(t)
	sni := make(chan string, 1)
	host := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host <- r.Host
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()
	resolver := &fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	localDialer := &net.Dialer{}
	dialed := make(chan string, 1)
	client, err := newClient(ClientOptions{}, resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed <- address
		return localDialer.DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	})
	if err != nil {
		t.Fatal(err)
	}
	client.roots = x509.NewCertPool()
	client.roots.AddCert(cert)
	result, err := client.Inspect(context.Background(), normalized(t, "https://example.com"))
	if err != nil || !result.FinalHTTPS {
		t.Fatalf("HTTPS inspection result=%+v err=%v", result, err)
	}
	if got := <-dialed; got != "8.8.8.8:443" {
		t.Fatalf("HTTPS dial destination = %q, want validated IP and port", got)
	}
	if got := <-sni; got != "example.com" {
		t.Fatalf("TLS SNI = %q, want original hostname", got)
	}
	if got := <-host; got != "example.com" {
		t.Fatalf("HTTP Host = %q, want original hostname", got)
	}
}

func TestClientRecordsHTTPSDowngrade(t *testing.T) {
	pair, cert := makeTLSPair(t)
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/final", http.StatusFound)
	}))
	tlsServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	tlsServer.StartTLS()
	defer tlsServer.Close()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpServer.Close()
	resolver := &fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	tlsAddress := strings.TrimPrefix(tlsServer.URL, "https://")
	httpAddress := strings.TrimPrefix(httpServer.URL, "http://")
	dialer := &net.Dialer{}
	client, err := newClient(ClientOptions{}, resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		if port == "443" {
			return dialer.DialContext(ctx, network, tlsAddress)
		}
		if port == "80" {
			return dialer.DialContext(ctx, network, httpAddress)
		}
		return nil, errors.New("unexpected port")
	})
	if err != nil {
		t.Fatal(err)
	}
	client.roots = x509.NewCertPool()
	client.roots.AddCert(cert)
	result, err := client.Inspect(context.Background(), normalized(t, "https://example.com/start"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.HTTPSDowngrade || result.FinalHTTPS || len(result.RedirectChain) != 1 || !result.RedirectChain[0].Downgrade {
		t.Fatalf("downgrade not recorded: %+v", result)
	}
}
