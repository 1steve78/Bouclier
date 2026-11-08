package heuristics

import (
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeURLValid(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		normalized       string
		scheme           string
		host             string
		hostname         string
		originalHostname string
		port             string
		path             string
		query            string
		fragment         string
		https            bool
		userinfo         bool
		ipAddress        bool
	}{
		{name: "HTTPS hostname", input: "https://example.com", normalized: "https://example.com/", scheme: "https", host: "example.com", hostname: "example.com", path: "/", https: true},
		{name: "HTTP hostname", input: "http://example.com", normalized: "http://example.com/", scheme: "http", host: "example.com", hostname: "example.com", path: "/"},
		{name: "uppercase scheme and hostname", input: "HTTPS://EXAMPLE.COM/login", normalized: "https://example.com/login", scheme: "https", host: "example.com", hostname: "example.com", path: "/login", https: true},
		{name: "non-default port", input: "https://example.com:8443/login", normalized: "https://example.com:8443/login", scheme: "https", host: "example.com:8443", hostname: "example.com", port: "8443", path: "/login", https: true},
		{name: "query", input: "https://example.com/search?q=test", normalized: "https://example.com/search?q=test", scheme: "https", host: "example.com", hostname: "example.com", path: "/search", query: "q=test", https: true},
		{name: "fragment", input: "https://example.com/path#section", normalized: "https://example.com/path#section", scheme: "https", host: "example.com", hostname: "example.com", path: "/path", fragment: "section", https: true},
		{name: "query order and escaping", input: "https://example.com/a%2Fb?z=2&a=%2F#part%2Ftwo", normalized: "https://example.com/a%2Fb?z=2&a=%2F#part%2Ftwo", scheme: "https", host: "example.com", hostname: "example.com", path: "/a%2Fb", query: "z=2&a=%2F", fragment: "part%2Ftwo", https: true},
		{name: "HTTPS default port", input: "https://example.com:443/login", normalized: "https://example.com/login", scheme: "https", host: "example.com", hostname: "example.com", port: "443", path: "/login", https: true},
		{name: "HTTP default port", input: "http://example.com:80/login", normalized: "http://example.com/login", scheme: "http", host: "example.com", hostname: "example.com", port: "80", path: "/login"},
		{name: "leading zero default port", input: "https://example.com:00443/", normalized: "https://example.com/", scheme: "https", host: "example.com", hostname: "example.com", port: "443", path: "/", https: true},
		{name: "DNS root dot", input: "https://example.com./login", normalized: "https://example.com/login", scheme: "https", host: "example.com", hostname: "example.com", path: "/login", https: true},
		{name: "IPv4", input: "http://192.168.1.1", normalized: "http://192.168.1.1/", scheme: "http", host: "192.168.1.1", hostname: "192.168.1.1", path: "/", ipAddress: true},
		{name: "IPv4 with port", input: "https://127.0.0.1:8443", normalized: "https://127.0.0.1:8443/", scheme: "https", host: "127.0.0.1:8443", hostname: "127.0.0.1", port: "8443", path: "/", https: true, ipAddress: true},
		{name: "IPv6", input: "http://[::1]/", normalized: "http://[::1]/", scheme: "http", host: "[::1]", hostname: "::1", path: "/", ipAddress: true},
		{name: "IPv6 with port", input: "https://[2001:db8::1]:8443/path", normalized: "https://[2001:db8::1]:8443/path", scheme: "https", host: "[2001:db8::1]:8443", hostname: "2001:db8::1", port: "8443", path: "/path", https: true, ipAddress: true},
		{name: "IPv6 canonical form", input: "https://[2001:0DB8:0:0::1]/", normalized: "https://[2001:db8::1]/", scheme: "https", host: "[2001:db8::1]", hostname: "2001:db8::1", path: "/", https: true, ipAddress: true},
		{name: "userinfo with password", input: "https://user:password@example.com/login", normalized: "https://user:password@example.com/login", scheme: "https", host: "example.com", hostname: "example.com", path: "/login", https: true, userinfo: true},
		{name: "userinfo destination is final host", input: "https://google.com@evil.example/login", normalized: "https://google.com@evil.example/login", scheme: "https", host: "evil.example", hostname: "evil.example", path: "/login", https: true, userinfo: true},
		{name: "single-label DNS name", input: "http://localhost/health", normalized: "http://localhost/health", scheme: "http", host: "localhost", hostname: "localhost", path: "/health"},
		{name: "Unicode IDN hostname", input: "https://bücher.example/", normalized: "https://xn--bcher-kva.example/", scheme: "https", host: "xn--bcher-kva.example", hostname: "xn--bcher-kva.example", originalHostname: "bücher.example", path: "/", https: true},
		{name: "Punycode IDN hostname", input: "https://xn--bcher-kva.example/", normalized: "https://xn--bcher-kva.example/", scheme: "https", host: "xn--bcher-kva.example", hostname: "xn--bcher-kva.example", originalHostname: "xn--bcher-kva.example", path: "/", https: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeURL(tt.input)
			if err != nil {
				t.Fatalf("NormalizeURL() error = %v", err)
			}
			if got.Original != tt.input || got.Normalized != tt.normalized || got.Scheme != tt.scheme ||
				got.Host != tt.host || got.Hostname != tt.hostname || got.Port != tt.port ||
				got.Path != tt.path || got.Query != tt.query || got.Fragment != tt.fragment ||
				got.IsHTTPS != tt.https || got.HasUserInfo != tt.userinfo || got.IsIPAddress != tt.ipAddress {
				t.Fatalf("NormalizeURL() = %+v", got)
			}
			if tt.originalHostname != "" && got.OriginalHostname != tt.originalHostname {
				t.Errorf("OriginalHostname = %q, want %q", got.OriginalHostname, tt.originalHostname)
			}
		})
	}
}

func TestNormalizeURLInvalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "empty", input: "", wantErr: "empty"},
		{name: "whitespace only", input: "   ", wantErr: "empty"},
		{name: "surrounding whitespace", input: " https://example.com", wantErr: "whitespace"},
		{name: "embedded whitespace", input: "https://example.com/a b", wantErr: "whitespace"},
		{name: "control character", input: "https://example.com/\npath", wantErr: "control characters"},
		{name: "missing scheme", input: "example.com", wantErr: "absolute URL"},
		{name: "scheme-relative URL", input: "//example.com/path", wantErr: "absolute URL"},
		{name: "unsupported FTP", input: "ftp://example.com", wantErr: "unsupported scheme"},
		{name: "file URL", input: "file:///etc/passwd", wantErr: "unsupported scheme"},
		{name: "javascript URL", input: "javascript:alert(1)", wantErr: "unsupported scheme"},
		{name: "empty authority", input: "https://", wantErr: "hostname"},
		{name: "missing hostname", input: "https:///path", wantErr: "hostname"},
		{name: "port too high", input: "https://example.com:99999", wantErr: "between 1 and 65535"},
		{name: "port zero", input: "https://example.com:0", wantErr: "between 1 and 65535"},
		{name: "nonnumeric port", input: "https://example.com:abc", wantErr: "decimal digits"},
		{name: "empty port", input: "https://example.com:", wantErr: "port cannot be empty"},
		{name: "malformed IPv6 bracket", input: "https://[invalid-ipv6", wantErr: "malformed URL"},
		{name: "unbracketed IPv6", input: "https://2001:db8::1/", wantErr: "IPv6 addresses must be bracketed"},
		{name: "invalid IPv6 literal", input: "https://[not-ipv6]/", wantErr: "malformed URL"},
		{name: "IPv6 zone identifier", input: "http://[fe80::1%25eth0]/", wantErr: "zone identifiers"},
		{name: "invalid hostname label", input: "https://-example.com/", wantErr: "invalid IDNA hostname"},
		{name: "invalid IPv4", input: "http://192.168.1.999/", wantErr: "invalid IPv4"},
		{name: "invalid IDNA hostname", input: "https://xn--.example/", wantErr: "invalid IDNA hostname"},
		{name: "invalid joiner", input: "https://a\u200db.example/", wantErr: "invalid IDNA hostname"},
		{name: "invalid UTF-8 hostname", input: "http://0.\xad/", wantErr: "invalid IDNA hostname"},
		{name: "bad percent escape", input: "https://example.com/%zz", wantErr: "malformed URL"},
		{name: "backslash", input: "https://example.com\\path", wantErr: "backslashes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeURL(tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NormalizeURL() error = %v, want text %q", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeURLErrorsDoNotExposeCredentialsOrQuery(t *testing.T) {
	input := "https://user:super-secret@example.com:bad/path?token=private"
	_, err := NormalizeURL(input)
	if err == nil {
		t.Fatal("NormalizeURL() succeeded for invalid port")
	}
	for _, sensitive := range []string{"super-secret", "private"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error exposed sensitive input %q: %v", sensitive, err)
		}
	}
}

func FuzzNormalizeURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com",
		"HTTPS://EXAMPLE.COM/login",
		"https://user:password@example.com/path?q=secret",
		"http://[::1]/",
		"https://example.com:99999",
		"not a URL",
		"https://bücher.example/",
		"https://[invalid-ipv6",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := NormalizeURL(input)
		if err != nil {
			return
		}
		if got == nil {
			t.Fatal("NormalizeURL() returned a nil URL without an error")
		}
		parsed, err := url.Parse(got.Normalized)
		if err != nil {
			t.Fatalf("normalized URL cannot be parsed: %v", err)
		}
		if parsed.Scheme != got.Scheme || parsed.Host != got.Host || got.Original != input {
			t.Fatalf("inconsistent normalized result: %+v", got)
		}
	})
}
