package webcheck

import (
	"strings"
	"testing"
)

func TestAnalyzeHTMLPassiveSignals(t *testing.T) {
	result := &HTTPInspectionResult{
		FinalURL: "https://example.com/login", FinalHTTPS: true, IsHTML: true,
		HTML: []byte(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"><meta name="referrer" content="no-referrer"></head><body><script src="http://cdn.example.net/a.js"></script><link rel="stylesheet" href="http://assets.example.net/a.css"><iframe src="http://frame.example.org"></iframe><form action="http://submit.example.net/auth"><input type="password"></form><img src="https://images.example.org/a.png"></body></html>`),
	}
	findings, err := AnalyzeHTML(result)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.Code] = true
	}
	for _, code := range []string{"WEB_HTML_META_CSP_PRESENT", "WEB_HTML_META_REFERRER_POLICY", "WEB_HTML_MIXED_CONTENT_SCRIPT", "WEB_HTML_MIXED_CONTENT_STYLESHEET", "WEB_HTML_MIXED_CONTENT_IFRAME", "WEB_HTML_INSECURE_PASSWORD_FORM"} {
		if !seen[code] {
			t.Errorf("missing %s: %+v", code, findings)
		}
	}
	if len(result.ExternalResourceOrigins) != 4 {
		t.Fatalf("external origins = %v", result.ExternalResourceOrigins)
	}
}

func TestAnalyzeHTMLTruncatedMalformedAndNonHTML(t *testing.T) {
	truncated := &HTTPInspectionResult{FinalURL: "https://example.com", FinalHTTPS: true, IsHTML: true, BodyTruncated: true, HTML: []byte("<html><script src='http://x.example.org/a.js'>")}
	findings, err := AnalyzeHTML(truncated)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 || findings[0].Code != "WEB_HTML_INCOMPLETE" {
		t.Fatalf("truncated findings = %+v", findings)
	}
	if got, err := AnalyzeHTML(&HTTPInspectionResult{IsHTML: false, HTML: []byte("<form><input type=password></form>")}); err != nil || len(got) != 0 {
		t.Fatalf("non-HTML findings=%v err=%v", got, err)
	}
	malformed := &HTTPInspectionResult{FinalURL: "https://example.com", FinalHTTPS: true, IsHTML: true, HTML: []byte(strings.Repeat("<div>", 100) + "unfinished")}
	if _, err := AnalyzeHTML(malformed); err != nil {
		t.Fatalf("tolerant HTML parser returned error: %v", err)
	}
}
