package webcheck

import (
	"fmt"
	"net/http"
	"strings"

	"bouclier/internal/heuristics"
)

// AnalyzeCookies inspects response cookie attributes without exposing values.
func AnalyzeCookies(result *HTTPInspectionResult) ([]heuristics.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze cookies: result is nil")
	}
	cookies := result.cookies
	if len(cookies) == 0 {
		cookies = (&http.Response{Header: result.Headers}).Cookies()
	}
	var findings []heuristics.Finding
	result.CookieAttributes = make([]CookieInfo, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		result.CookieAttributes = append(result.CookieAttributes, CookieInfo{
			Name: safeCookieName(cookie.Name), Domain: cookie.Domain, Path: safeCookiePath(cookie.Path),
			Secure: cookie.Secure, HTTPOnly: cookie.HttpOnly, SameSite: sameSiteName(cookie.SameSite),
			Expires: cookie.Expires, MaxAge: cookie.MaxAge,
		})
		name := strings.ToLower(cookie.Name)
		sessionLike := sessionCookieName(name)
		if result.FinalHTTPS && sessionLike {
			if !cookie.Secure {
				findings = append(findings, finding("WEB_COOKIE_SESSION_MISSING_SECURE", "Session-like cookie lacks Secure", "A session-like cookie returned over HTTPS is not restricted to secure transport.", "web-cookie", "cookie name="+safeCookieName(cookie.Name)+"; Secure is absent"))
			}
			if !cookie.HttpOnly {
				findings = append(findings, finding("WEB_COOKIE_SESSION_MISSING_HTTPONLY", "Session-like cookie lacks HttpOnly", "HttpOnly limits direct access to a cookie through browser scripts.", "web-cookie", "cookie name="+safeCookieName(cookie.Name)+"; HttpOnly is absent"))
			}
		}
		if !result.FinalHTTPS && sessionLike {
			findings = append(findings, finding("WEB_COOKIE_SESSION_OVER_HTTP", "Session-like cookie was returned over HTTP", "The response used an unencrypted transport; cookie attributes do not make HTTP confidential.", "web-cookie", "session-like cookie name="+safeCookieName(cookie.Name)+"; response transport is HTTP"))
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			findings = append(findings, finding("WEB_COOKIE_SAMESITE_NONE_WITHOUT_SECURE", "SameSite=None cookie lacks Secure", "Browsers require Secure for cross-site cookies in modern cookie handling.", "web-cookie", "cookie name="+safeCookieName(cookie.Name)+"; SameSite=None without Secure"))
		}
		if sessionLike && cookie.SameSite == http.SameSiteDefaultMode {
			findings = append(findings, finding("WEB_COOKIE_SESSION_SAMESITE_UNSPECIFIED", "Session-like cookie has no explicit SameSite policy", "An explicit SameSite policy makes cross-site cookie behavior clearer.", "web-cookie", "cookie name="+safeCookieName(cookie.Name)+"; SameSite is unspecified"))
		}
	}
	return sortedFindings(findings), nil
}

func sameSiteName(mode http.SameSite) string {
	switch mode {
	case http.SameSiteDefaultMode:
		return "unspecified"
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return "unknown"
	}
}

func sessionCookieName(name string) bool {
	for _, marker := range []string{"session", "sessid", "auth", "token", "sid", "jwt"} {
		if name == marker || strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func safeCookieName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		return name[:64]
	}
	return name
}

func safeCookiePath(path string) string {
	if query := strings.IndexByte(path, '?'); query >= 0 {
		path = path[:query]
	}
	if fragment := strings.IndexByte(path, '#'); fragment >= 0 {
		path = path[:fragment]
	}
	if len(path) > 256 {
		path = path[:256]
	}
	return path
}
