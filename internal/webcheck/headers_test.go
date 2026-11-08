package webcheck

import (
	"net/http"
	"testing"
)

func TestAnalyzeSecurityHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secure  bool
		headers http.Header
		want    []string
		absent  []string
	}{
		{name: "missing", secure: true, headers: http.Header{}, want: []string{"WEB_HSTS_MISSING", "WEB_CSP_MISSING", "WEB_CLICKJACKING_PROTECTION_MISSING", "WEB_NOSNIFF_MISSING", "WEB_REFERRER_POLICY_MISSING"}},
		{name: "strong protections", secure: true, headers: http.Header{"Strict-Transport-Security": {"max-age=31536000; includeSubDomains; preload"}, "Content-Security-Policy": {"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"}, "X-Frame-Options": {"DENY"}, "X-Content-Type-Options": {"nosniff"}, "Referrer-Policy": {"strict-origin-when-cross-origin"}}, absent: []string{"WEB_HSTS_MISSING", "WEB_HSTS_WEAK", "WEB_CLICKJACKING_PROTECTION_MISSING", "WEB_NOSNIFF_MISSING"}},
		{name: "weak and report-only", secure: true, headers: http.Header{"Strict-Transport-Security": {"max-age=20"}, "Content-Security-Policy-Report-Only": {"default-src *"}, "Referrer-Policy": {"unsafe-url"}}, want: []string{"WEB_HSTS_WEAK", "WEB_HSTS_NO_SUBDOMAINS", "WEB_CSP_REPORT_ONLY", "WEB_CLICKJACKING_PROTECTION_MISSING", "WEB_REFERRER_POLICY_WEAK"}},
		{name: "HTTP ignores HSTS", secure: false, headers: http.Header{"Strict-Transport-Security": {"max-age=0"}}, absent: []string{"WEB_HSTS_MISSING", "WEB_HSTS_WEAK"}},
		{name: "CSP weak directives", secure: true, headers: http.Header{"Content-Security-Policy": {"default-src *; script-src 'unsafe-inline' 'unsafe-eval'; frame-ancestors *"}}, want: []string{"WEB_CSP_WILDCARD_SOURCE", "WEB_CSP_UNSAFE_INLINE", "WEB_CSP_UNSAFE_EVAL", "WEB_CLICKJACKING_PROTECTION_MISSING"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := AnalyzeSecurityHeaders(&HTTPInspectionResult{FinalHTTPS: tc.secure, Headers: tc.headers})
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, f := range findings {
				seen[f.Code] = true
			}
			for _, code := range tc.want {
				if !seen[code] {
					t.Errorf("missing finding %s; got %v", code, findings)
				}
			}
			for _, code := range tc.absent {
				if seen[code] {
					t.Errorf("unexpected finding %s", code)
				}
			}
		})
	}
}
