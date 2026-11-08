package webcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/heuristics"
)

const (
	defaultBodyLimit = 2 << 20
	defaultRedirects = 5
)

var (
	ErrUnsafeTarget     = errors.New("destination is not permitted")
	headerURLPattern    = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	headerSecretPattern = regexp.MustCompile(`(?i)\b(password|token|secret|api[_-]?key|access[_-]?key)=([^&;\s,]+)`)
)

// ClientOptions bounds the request and response. Zero values select safe defaults.
type ClientOptions struct {
	Timeout          time.Duration
	MaxRedirects     int
	DisableRedirects bool
	UserAgent        string
	MaxBodyBytes     int64
}

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type tcpDialer func(context.Context, string, string) (net.Conn, error)

// Client performs GET-only passive HTTP inspection. It never inherits proxy
// settings from the process environment.
type Client struct {
	options  ClientOptions
	resolver ipResolver
	dial     tcpDialer
	roots    *x509.CertPool
}

// NewClient validates options and creates a safe inspection client.
func NewClient(options ClientOptions) (*Client, error) {
	defaults := config.Default().Scanner
	if options.Timeout == 0 {
		options.Timeout = defaults.HTTPTimeout
	}
	if options.UserAgent == "" {
		options.UserAgent = defaults.UserAgent
	}
	return newClient(options, net.DefaultResolver, (&net.Dialer{}).DialContext)
}

func newClient(options ClientOptions, resolver ipResolver, dial tcpDialer) (*Client, error) {
	if options.Timeout == 0 {
		options.Timeout = 8 * time.Second
	}
	if options.Timeout < 0 {
		return nil, fmt.Errorf("create web client: timeout must be positive")
	}
	if options.DisableRedirects {
		options.MaxRedirects = 0
	} else if options.MaxRedirects == 0 {
		options.MaxRedirects = defaultRedirects
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > config.MaxRedirectsLimit {
		return nil, fmt.Errorf("create web client: maximum redirects must be between 0 and %d", config.MaxRedirectsLimit)
	}
	if options.UserAgent == "" {
		options.UserAgent = "Bouclier/0.1.0-dev"
	}
	if strings.TrimSpace(options.UserAgent) == "" || strings.ContainsAny(options.UserAgent, "\r\n") {
		return nil, fmt.Errorf("create web client: user-agent is invalid")
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = defaultBodyLimit
	}
	if options.MaxBodyBytes < 1 || options.MaxBodyBytes > 32<<20 {
		return nil, fmt.Errorf("create web client: response body limit must be between 1 byte and 32 MiB")
	}
	if resolver == nil || dial == nil {
		return nil, fmt.Errorf("create web client: resolver and dialer are required")
	}
	return &Client{options: options, resolver: resolver, dial: dial}, nil
}

// Inspect fetches a bounded response without sending cookies or credentials.
func (c *Client) Inspect(ctx context.Context, input *heuristics.NormalizedURL) (*HTTPInspectionResult, error) {
	if c == nil || ctx == nil {
		return nil, fmt.Errorf("inspect website: client and context are required")
	}
	if err := ValidateTarget(input); err != nil {
		return nil, fmt.Errorf("inspect website: %w", err)
	}
	parsed, _ := url.Parse(input.Normalized)
	if parsed.User != nil {
		// Never attach userinfo to a request, including a caller-constructed value.
		parsed.User = nil
	}
	if parsed.Fragment != "" {
		parsed.Fragment = ""
		parsed.RawFragment = ""
	}
	ctx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	started := time.Now()
	requestedSafe := sanitizedURL(parsed)
	result := &HTTPInspectionResult{
		RequestedURL:  requestedSafe,
		RedirectChain: make([]Redirect, 0),
		UsedHTTPS:     parsed.Scheme == "https",
	}
	defer func() { result.Duration = time.Since(started) }()
	seen := make(map[string]struct{})
	current := parsed
	for redirects := 0; ; redirects++ {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("inspect website: %w", err)
		}
		loopKey := current.String()
		if _, exists := seen[loopKey]; exists {
			return result, fmt.Errorf("inspect website: redirect loop detected")
		}
		seen[loopKey] = struct{}{}
		addresses, host, port, err := c.resolveAndValidate(ctx, current)
		if err != nil {
			return result, fmt.Errorf("inspect website: validate destination: %w", err)
		}
		requestURL := *current
		requestURL.User = nil
		requestURL.Fragment = ""
		requestURL.RawFragment = ""
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return result, fmt.Errorf("inspect website: create request: invalid request URL")
		}
		request.Header.Set("User-Agent", c.options.UserAgent)
		transport := c.transport(host, port, addresses)
		httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, requestErr := httpClient.Do(request)
		transport.CloseIdleConnections()
		if requestErr != nil {
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			return result, fmt.Errorf("inspect website: HTTP request failed: %w", unwrapURLError(requestErr))
		}
		if isRedirect(response.StatusCode) {
			location, locationErr := response.Location()
			response.Body.Close()
			if locationErr != nil {
				return result, fmt.Errorf("inspect website: malformed redirect location")
			}
			destination := current.ResolveReference(location)
			if destination.User != nil {
				return result, fmt.Errorf("inspect website: redirect containing credentials is rejected")
			}
			destination.Fragment = ""
			destination.RawFragment = ""
			if destination.Scheme != "http" && destination.Scheme != "https" {
				return result, fmt.Errorf("inspect website: redirect uses unsupported scheme: %w", ErrUnsafeTarget)
			}
			normalizedDestination, normalizeErr := heuristics.NormalizeURL(destination.String())
			if normalizeErr != nil {
				return result, fmt.Errorf("inspect website: malformed redirect destination")
			}
			destination, _ = url.Parse(normalizedDestination.Normalized)
			if err := validateWebPort(destination); err != nil {
				return result, fmt.Errorf("inspect website: unsafe redirect destination: %w", err)
			}
			cross := origin(current) != origin(destination)
			downgrade := current.Scheme == "https" && destination.Scheme == "http"
			result.RedirectChain = append(result.RedirectChain, Redirect{Source: sanitizedURL(current), Destination: sanitizedURL(destination), StatusCode: response.StatusCode, CrossOrigin: cross, Downgrade: downgrade})
			result.CrossOriginRedirect = result.CrossOriginRedirect || cross
			result.HTTPSDowngrade = result.HTTPSDowngrade || downgrade
			if redirects >= c.options.MaxRedirects {
				return result, fmt.Errorf("inspect website: redirect limit exceeded")
			}
			current = destination
			continue
		}
		defer response.Body.Close()
		result.FinalURL = sanitizedURL(current)
		result.StatusCode = response.StatusCode
		result.Protocol = response.Proto
		result.Headers = response.Header.Clone()
		result.cookies = response.Cookies()
		result.Headers.Del("Set-Cookie")
		result.Headers.Del("Location")
		result.Headers.Del("Link")
		result.Headers.Del("Content-Location")
		result.Headers.Del("Refresh")
		for name, headerValues := range result.Headers {
			for index, value := range headerValues {
				headerValues[index] = sanitizeHeaderValue(value)
			}
			result.Headers[name] = headerValues
		}
		result.ContentType = response.Header.Get("Content-Type")
		result.ContentLength = response.ContentLength
		result.RedirectCount = len(result.RedirectChain)
		result.FinalHTTPS = current.Scheme == "https"
		mediaType, _, mediaErr := mime.ParseMediaType(result.ContentType)
		result.IsHTML = mediaErr == nil && (strings.EqualFold(mediaType, "text/html") || strings.EqualFold(mediaType, "application/xhtml+xml"))
		body, readErr := readBounded(response.Body, c.options.MaxBodyBytes)
		if readErr != nil {
			return result, fmt.Errorf("inspect website: read response body: %w", readErr)
		}
		result.BytesRead = int64(len(body))
		result.BodyTruncated = int64(len(body)) > c.options.MaxBodyBytes
		if result.BodyTruncated {
			body = body[:c.options.MaxBodyBytes]
		}
		if result.IsHTML {
			result.HTML = body
		}
		return result, nil
	}
}

// ValidateTarget performs static target checks without DNS resolution or network
// access. The destination is still resolved, validated, and pinned at dial time.
func ValidateTarget(input *heuristics.NormalizedURL) error {
	if input == nil {
		return fmt.Errorf("normalized URL is nil")
	}
	parsed, err := url.Parse(input.Normalized)
	if err != nil || parsed == nil || parsed.Hostname() == "" {
		return fmt.Errorf("normalized URL is invalid")
	}
	validated, err := heuristics.NormalizeURL(input.Normalized)
	if err != nil || validated.Hostname != input.Hostname || validated.Scheme != input.Scheme || validated.Port != input.Port {
		return fmt.Errorf("normalized URL is inconsistent or invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme")
	}
	if err := validateWebPort(parsed); err != nil {
		return err
	}
	host := strings.TrimSuffix(parsed.Hostname(), ".")
	if host == "" || strings.Contains(host, "%") {
		return fmt.Errorf("hostname is invalid or contains a zone identifier")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !allowedWebAddress(address.Unmap()) {
			return fmt.Errorf("%w: destination address is not public", ErrUnsafeTarget)
		}
		return nil
	}
	if strings.Contains(host, ":") || !strings.Contains(host, ".") {
		return fmt.Errorf("IP literal or single-label hostname is invalid")
	}
	if isLocalWebHostname(strings.ToLower(host)) {
		return fmt.Errorf("%w: local or internal hostname is not permitted", ErrUnsafeTarget)
	}
	return nil
}

func (c *Client) transport(host, port string, addresses []netip.Addr) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 1 << 20,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots},
		ResponseHeaderTimeout:  c.options.Timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			requestedHost, requestedPort, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(strings.TrimSuffix(requestedHost, "."), strings.TrimSuffix(host, ".")) || requestedPort != port {
				return nil, fmt.Errorf("request destination changed after validation")
			}
			var last error
			for _, ip := range addresses {
				conn, dialErr := c.dial(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				last = dialErr
			}
			if last == nil {
				last = errors.New("validated destination has no addresses")
			}
			return nil, last
		},
	}
}

func (c *Client) resolveAndValidate(ctx context.Context, target *url.URL) ([]netip.Addr, string, string, error) {
	host := strings.TrimSuffix(target.Hostname(), ".")
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if err := validateWebPort(target); err != nil {
		return nil, "", "", err
	}
	if host == "" || strings.Contains(host, "%") {
		return nil, "", "", fmt.Errorf("hostname is invalid or contains a zone identifier")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !allowedWebAddress(addr) {
			return nil, "", "", fmt.Errorf("%w: destination address is not public", ErrUnsafeTarget)
		}
		return []netip.Addr{addr}, host, port, nil
	}
	if strings.Contains(host, ":") || !strings.Contains(host, ".") {
		return nil, "", "", fmt.Errorf("IP literal or single-label hostname is invalid")
	}
	if isLocalWebHostname(strings.ToLower(host)) {
		return nil, "", "", fmt.Errorf("%w: local or internal hostname is not permitted", ErrUnsafeTarget)
	}
	addresses, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, "", "", fmt.Errorf("DNS resolution failed: %w", err)
	}
	if len(addresses) == 0 {
		return nil, "", "", fmt.Errorf("DNS returned no addresses")
	}
	unique := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		if !addr.IsValid() || addr.Zone() != "" {
			return nil, "", "", fmt.Errorf("%w: DNS returned an invalid or scoped address", ErrUnsafeTarget)
		}
		addr = addr.Unmap()
		if !allowedWebAddress(addr) {
			return nil, "", "", fmt.Errorf("%w: DNS returned a prohibited address", ErrUnsafeTarget)
		}
		duplicate := false
		for _, existing := range unique {
			if existing == addr {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, addr)
		}
	}
	return unique, host, port, nil
}

func isLocalWebHostname(host string) bool {
	for _, suffix := range []string{"localhost", "local", "internal", "lan", "home", "home.arpa", "test", "invalid", "example", "onion", "corp", "intranet", "private", "localdomain"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func allowedWebAddress(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func validateWebPort(target *url.URL) error {
	port := target.Port()
	if port == "" {
		return nil
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 || value != 80 && value != 443 {
		return fmt.Errorf("%w: destination port must be 80 or 443", ErrUnsafeTarget)
	}
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	return io.ReadAll(limited)
}

func sanitizedURL(value *url.URL) string {
	copy := *value
	copy.User = nil
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	copy.RawFragment = ""
	return copy.String()
}

func sanitizeHeaderValue(value string) string {
	value = headerURLPattern.ReplaceAllStringFunc(value, func(raw string) string {
		trimmed := strings.TrimRight(raw, ".,);]")
		suffix := raw[len(trimmed):]
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return "[redacted-url]" + suffix
		}
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		parsed.RawFragment = ""
		return parsed.String() + suffix
	})
	return headerSecretPattern.ReplaceAllString(value, "$1=[redacted]")
}

func origin(value *url.URL) string {
	port := value.Port()
	if port == "" {
		if value.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Hostname()) + ":" + port
}

func isRedirect(status int) bool { return status >= 300 && status <= 399 }

func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}
