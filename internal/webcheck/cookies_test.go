package webcheck

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeCookiesAttributesAndRedaction(t *testing.T) {
	result := &HTTPInspectionResult{FinalHTTPS: true, Headers: make(http.Header)}
	result.Headers.Add("Set-Cookie", "sessionid=TOP-SECRET; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=60")
	result.Headers.Add("Set-Cookie", "theme=dark; Path=/; SameSite=None")
	findings, err := AnalyzeCookies(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CookieAttributes) != 2 {
		t.Fatalf("cookie metadata = %+v", result.CookieAttributes)
	}
	if result.CookieAttributes[0].Name != "sessionid" || !result.CookieAttributes[0].HTTPOnly || !result.CookieAttributes[0].Secure || result.CookieAttributes[0].MaxAge != 60 || result.CookieAttributes[0].Path != "/" {
		t.Fatalf("session cookie metadata = %+v", result.CookieAttributes[0])
	}
	joined := ""
	for _, finding := range findings {
		joined += finding.Code + " " + finding.Evidence + " "
	}
	if strings.Contains(joined, "TOP-SECRET") {
		t.Fatal("cookie value leaked in evidence")
	}
	if !strings.Contains(joined, "WEB_COOKIE_SAMESITE_NONE_WITHOUT_SECURE") {
		t.Fatalf("SameSite=None weakness absent: %s", joined)
	}
	if strings.Contains(joined, "WEB_COOKIE_SESSION_MISSING") {
		t.Fatalf("secure session cookie incorrectly flagged: %s", joined)
	}
}

func TestAnalyzeCookiesConservativeSessionAndHTTP(t *testing.T) {
	result := &HTTPInspectionResult{FinalHTTPS: false, Headers: http.Header{"Set-Cookie": {"sid=secret; Domain=example.com; Expires=" + time.Now().UTC().Format(http.TimeFormat)}}}
	findings, err := AnalyzeCookies(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Code != "WEB_COOKIE_SESSION_OVER_HTTP" {
		t.Fatalf("findings = %+v", findings)
	}
	if strings.Contains(findings[0].Evidence, "secret") {
		t.Fatal("cookie value leaked")
	}
}
