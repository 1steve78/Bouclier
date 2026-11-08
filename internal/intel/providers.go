package intel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// LocalFileProvider loads threat intelligence from a local JSON or CSV file.
type LocalFileProvider struct{}

// NewLocalFileProvider creates a new local file provider.
func NewLocalFileProvider() *LocalFileProvider {
	return &LocalFileProvider{}
}

// FetchIndicators reads and parses indicators from a local file path.
func (p *LocalFileProvider) FetchIndicators(ctx context.Context, cfg SourceConfig) (*IngestionResult, error) {
	started := time.Now().UTC()
	if !cfg.Enabled {
		return nil, fmt.Errorf("%w: %s", ErrSourceDisabled, cfg.ID)
	}

	file, err := os.Open(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("open local intel file %q: %w", cfg.Endpoint, err)
	}
	defer file.Close()

	indicators, recordErrors, err := ParseIndicators(file, cfg.Format, cfg)
	if err != nil {
		return nil, fmt.Errorf("parse intel file: %w", err)
	}

	finished := time.Now().UTC()
	return &IngestionResult{
		SourceID:   cfg.ID,
		StartedAt:  started,
		FinishedAt: finished,
		Duration:   finished.Sub(started),
		TotalRead:  len(indicators) + len(recordErrors),
		ValidCount: len(indicators),
		Errors:     recordErrors,
		Indicators: indicators,
	}, nil
}

// HTTPSFeedProvider fetches threat intelligence feeds over HTTPS with strict SSRF protection.
type HTTPSFeedProvider struct {
	Resolver               Resolver
	Dialer                 Dialer
	AllowPrivateForTesting bool
}

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// NewHTTPSFeedProvider creates a secure HTTPS feed provider.
func NewHTTPSFeedProvider() *HTTPSFeedProvider {
	return &HTTPSFeedProvider{
		Resolver: net.DefaultResolver,
		Dialer:   (&net.Dialer{}).DialContext,
	}
}

// FetchIndicators fetches and parses a remote threat intelligence feed over HTTPS.
func (p *HTTPSFeedProvider) FetchIndicators(ctx context.Context, cfg SourceConfig) (*IngestionResult, error) {
	started := time.Now().UTC()
	if !cfg.Enabled {
		return nil, fmt.Errorf("%w: %s", ErrSourceDisabled, cfg.ID)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	parsedURL, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid feed endpoint: %w", err)
	}
	if !strings.EqualFold(parsedURL.Scheme, "https") {
		return nil, fmt.Errorf("remote feed endpoint must use https: %q", cfg.Endpoint)
	}

	client, err := p.buildSecureClient(parsedURL)
	if err != nil {
		return nil, fmt.Errorf("build secure http client: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Bouclier-ThreatIntel/1.0")
	req.Header.Set("Accept", "application/json, text/csv, text/plain")

	// Resolve authorization header from environment variable when requested
	var authHeader string
	if envVar := strings.TrimSpace(cfg.AuthHeaderEnv); envVar != "" {
		val, exists := os.LookupEnv(envVar)
		if !exists || strings.TrimSpace(val) == "" {
			return nil, fmt.Errorf("authentication environment variable %q is not set or empty", envVar)
		}
		authHeader = strings.TrimSpace(val)
	} else if strings.TrimSpace(cfg.AuthHeader) != "" {
		authHeader = strings.TrimSpace(cfg.AuthHeader)
	}

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute feed request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("feed server returned HTTP status %d (%s)", resp.StatusCode, resp.Status)
	}

	indicators, recordErrors, err := ParseIndicators(resp.Body, cfg.Format, cfg)
	if err != nil {
		return nil, fmt.Errorf("parse remote feed: %w", err)
	}

	finished := time.Now().UTC()
	return &IngestionResult{
		SourceID:   cfg.ID,
		StartedAt:  started,
		FinishedAt: finished,
		Duration:   finished.Sub(started),
		TotalRead:  len(indicators) + len(recordErrors),
		ValidCount: len(indicators),
		Errors:     recordErrors,
		Indicators: indicators,
	}, nil
}

// buildSecureClient constructs an http.Client that prevents SSRF, enforces HTTPS, and handles redirects safely.
func (p *HTTPSFeedProvider) buildSecureClient(initialURL *url.URL) (*http.Client, error) {
	transport := &http.Transport{
		Proxy:               nil, // Prevent inheriting environment proxy bypasses
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: p.AllowPrivateForTesting,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			if !p.AllowPrivateForTesting {
				portNum, portErr := strconv.Atoi(port)
				if portErr != nil || portNum < 1 || portNum > 65535 {
					return nil, fmt.Errorf("%w: invalid port %q", ErrSSRFBlocked, port)
				}
				// Prohibit dangerous non-web ports
				if portNum <= 1024 && portNum != 443 {
					return nil, fmt.Errorf("%w: prohibited feed port %d", ErrSSRFBlocked, portNum)
				}
			}

			// Resolve host to IP addresses and ensure none are private/loopback/restricted
			addrs, err := p.resolveAndCheckIPs(ctx, host)
			if err != nil {
				return nil, err
			}

			// Try connecting to the first allowed IP
			var lastErr error
			for _, ip := range addrs {
				target := net.JoinHostPort(ip.String(), port)
				conn, dialErr := p.Dialer(ctx, network, target)
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}

	redirectCount := 0
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectCount++
			if redirectCount > 3 {
				return errors.New("stopped after 3 redirects")
			}
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("redirect to non-https URL is rejected: %s", req.URL.String())
			}
			// SSRF check on redirect destination
			if _, err := p.resolveAndCheckIPs(req.Context(), req.URL.Hostname()); err != nil {
				return fmt.Errorf("redirect destination blocked: %w", err)
			}
			return nil
		},
	}

	return client, nil
}

func (p *HTTPSFeedProvider) resolveAndCheckIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrSSRFBlocked)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !p.AllowPrivateForTesting && isDisallowedAddress(addr) {
			return nil, fmt.Errorf("%w: address %s is private or restricted", ErrSSRFBlocked, addr)
		}
		return []netip.Addr{addr}, nil
	}

	// Hostname resolution
	addrs, err := p.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("dns resolution failed for %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns resolution returned no addresses for %q", host)
	}

	var allowed []netip.Addr
	for _, a := range addrs {
		addr := a.Unmap()
		if !p.AllowPrivateForTesting && isDisallowedAddress(addr) {
			return nil, fmt.Errorf("%w: dns resolved private/restricted address %s for %q", ErrSSRFBlocked, addr, host)
		}
		allowed = append(allowed, addr)
	}
	return allowed, nil
}

var prohibitedIntelPrefixes = mustParseIntelPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
	"2001:db8::/32", "2002::/16", "3fff::/20",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

func mustParseIntelPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic("invalid built-in prohibited prefix: " + value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func isDisallowedAddress(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range prohibitedIntelPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
