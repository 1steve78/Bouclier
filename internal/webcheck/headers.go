package webcheck

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"bouclier/internal/heuristics"
)

// AnalyzeSecurityHeaders evaluates common response protections as contextual
// observations. It does not emulate browser policy processing.
func AnalyzeSecurityHeaders(result *HTTPInspectionResult) ([]heuristics.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze security headers: result is nil")
	}
	var findings []heuristics.Finding
	h := result.Headers

	if result.FinalHTTPS {
		values := values(h, "Strict-Transport-Security")
		if len(values) == 0 {
			findings = append(findings, finding("WEB_HSTS_MISSING", "Strict-Transport-Security is absent", "HTTPS responses benefit from a browser-enforced HTTPS policy.", "web-transport", "strict-transport-security header is absent"))
		} else {
			maxAge, includeSubdomains, preload, ok := parseHSTS(values)
			if !ok || maxAge <= 0 || maxAge < 15552000 {
				findings = append(findings, finding("WEB_HSTS_WEAK", "Strict-Transport-Security policy is weak or malformed", "The configured HSTS max-age is missing, invalid, or shorter than six months.", "web-transport", "strict-transport-security max-age is weak or invalid"))
			}
			if !includeSubdomains {
				findings = append(findings, finding("WEB_HSTS_NO_SUBDOMAINS", "HSTS does not cover subdomains", "The policy does not include the includeSubDomains directive.", "web-transport", "includeSubDomains directive is absent"))
			}
			if preload {
				findings = append(findings, finding("WEB_HSTS_PRELOAD_DIRECTIVE", "HSTS preload directive is present", "The directive alone does not establish preload eligibility or inclusion in a browser preload list.", "web-transport", "preload directive is present"))
			}
		}
	}

	enforced := parseCSP(values(h, "Content-Security-Policy"))
	reportOnly := parseCSP(values(h, "Content-Security-Policy-Report-Only"))
	if len(enforced) == 0 && len(reportOnly) > 0 {
		findings = append(findings, finding("WEB_CSP_REPORT_ONLY", "CSP is report-only", "A report-only policy reports violations but does not enforce restrictions.", "web-content-policy", "only Content-Security-Policy-Report-Only is configured"))
	} else if len(enforced) == 0 {
		findings = append(findings, finding("WEB_CSP_MISSING", "Content-Security-Policy is absent", "An enforced CSP can limit script and resource behavior in browsers.", "web-content-policy", "enforced content-security-policy header is absent"))
	} else {
		for _, policy := range enforced {
			for _, directive := range []string{"default-src", "script-src", "object-src", "base-uri"} {
				if _, ok := policy[directive]; !ok {
					findings = append(findings, finding("WEB_CSP_DIRECTIVE_MISSING_"+strings.ToUpper(strings.ReplaceAll(directive, "-", "_")), "CSP directive is absent", "The enforced policy does not set this commonly useful directive.", "web-content-policy", "missing directive: "+directive))
				}
			}
			for _, directive := range []string{"default-src", "script-src", "object-src", "base-uri", "frame-ancestors"} {
				for _, source := range policy[directive] {
					lower := strings.ToLower(source)
					if lower == "*" {
						findings = append(findings, finding("WEB_CSP_WILDCARD_SOURCE", "CSP contains a wildcard source", "A wildcard source permits resources from any origin for the directive.", "web-content-policy", "wildcard source in "+directive))
					}
					if (directive == "script-src" || directive == "default-src") && lower == "'unsafe-inline'" {
						findings = append(findings, finding("WEB_CSP_UNSAFE_INLINE", "CSP permits inline script or style", "unsafe-inline weakens restrictions for the configured directive.", "web-content-policy", "unsafe-inline in "+directive))
					}
					if (directive == "script-src" || directive == "default-src") && lower == "'unsafe-eval'" {
						findings = append(findings, finding("WEB_CSP_UNSAFE_EVAL", "CSP permits eval-like execution", "unsafe-eval weakens restrictions for the configured directive.", "web-content-policy", "unsafe-eval in "+directive))
					}
				}
			}
		}
	}
	frameProtected := hasFrameProtection(values(h, "X-Frame-Options"), enforced)
	if !frameProtected {
		findings = append(findings, finding("WEB_CLICKJACKING_PROTECTION_MISSING", "Frame embedding protection is absent", "Neither a recognized X-Frame-Options value nor an enforced frame-ancestors directive was found.", "web-content-policy", "frame protection is not configured"))
	}
	if !hasToken(values(h, "X-Content-Type-Options"), "nosniff") {
		findings = append(findings, finding("WEB_NOSNIFF_MISSING", "X-Content-Type-Options nosniff is absent", "nosniff helps prevent browsers from interpreting content as a different MIME type.", "web-content-policy", "x-content-type-options nosniff is absent"))
	}
	referrer := strings.ToLower(strings.TrimSpace(strings.Join(values(h, "Referrer-Policy"), ",")))
	validReferrer := map[string]bool{"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true, "origin-when-cross-origin": true, "same-origin": true, "strict-origin": true, "strict-origin-when-cross-origin": true, "unsafe-url": true}
	if referrer == "" {
		findings = append(findings, finding("WEB_REFERRER_POLICY_MISSING", "Referrer-Policy is absent", "A referrer policy can limit URL information shared with other origins.", "web-privacy", "referrer-policy header is absent"))
	} else if !validReferrer[referrer] {
		findings = append(findings, finding("WEB_REFERRER_POLICY_INVALID", "Referrer-Policy value is unrecognized", "The supplied policy value is not a recognized standard policy.", "web-privacy", "referrer-policy value is unrecognized"))
	} else if referrer == "unsafe-url" || referrer == "no-referrer-when-downgrade" {
		findings = append(findings, finding("WEB_REFERRER_POLICY_WEAK", "Referrer-Policy may expose full referrer URLs", "This policy can send full referrer URLs to other origins.", "web-privacy", "referrer-policy is permissive"))
	}
	for _, value := range values(h, "Permissions-Policy") {
		for _, directive := range strings.Split(value, ";") {
			parts := strings.SplitN(directive, "=", 2)
			if len(parts) == 2 && strings.Contains(strings.TrimSpace(parts[1]), "*") {
				findings = append(findings, finding("WEB_PERMISSIONS_POLICY_UNRESTRICTED", "Permissions-Policy allows all origins for a feature", "A feature directive contains a wildcard allowlist.", "web-privacy", "wildcard allowlist for "+strings.ToLower(strings.TrimSpace(parts[0]))))
			}
		}
	}
	return sortedFindings(findings), nil
}

func parseHSTS(values []string) (int64, bool, bool, bool) {
	var age int64
	ageSet, include, preload := false, false, false
	for _, value := range values {
		for _, part := range strings.Split(value, ";") {
			key, val, hasValue := strings.Cut(strings.TrimSpace(part), "=")
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "max-age":
				parsed, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
				if !hasValue || err != nil || parsed < 0 {
					return 0, include, preload, false
				}
				age, ageSet = parsed, true
			case "includesubdomains":
				include = true
			case "preload":
				preload = true
			}
		}
	}
	return age, include, preload, ageSet
}

func parseCSP(values []string) []map[string][]string {
	policies := make([]map[string][]string, 0, len(values))
	for _, value := range values {
		policy := make(map[string][]string)
		for _, directive := range splitCSP(value) {
			fields := strings.Fields(directive)
			if len(fields) == 0 {
				continue
			}
			name := strings.ToLower(fields[0])
			if _, duplicate := policy[name]; !duplicate {
				policy[name] = fields[1:]
			}
		}
		policies = append(policies, policy)
	}
	return policies
}

func splitCSP(value string) []string {
	var parts []string
	start := 0
	var quote rune
	for i, r := range value {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ';' {
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	return append(parts, value[start:])
}

func hasFrameProtection(xfo []string, policies []map[string][]string) bool {
	for _, value := range xfo {
		token := strings.ToLower(strings.TrimSpace(value))
		if token == "deny" || token == "sameorigin" {
			return true
		}
	}
	for _, policy := range policies {
		if values, ok := policy["frame-ancestors"]; ok && len(values) > 0 {
			restricted, hasSource := true, false
			for _, value := range values {
				lower := strings.ToLower(value)
				if lower == "*" || strings.HasPrefix(lower, "'") && lower != "'self'" && lower != "'none'" {
					restricted = false
				} else {
					hasSource = true
				}
			}
			if restricted && hasSource {
				return true
			}
		}
	}
	return false
}

func values(header http.Header, name string) []string {
	var result []string
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entries := header[key]
		if strings.EqualFold(key, name) {
			result = append(result, entries...)
		}
	}
	return result
}
func hasToken(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}
func finding(code, title, description, category, evidence string) heuristics.Finding {
	return heuristics.Finding{Code: code, Title: title, Description: description, Category: category, Evidence: evidence}
}
func sortedFindings(in []heuristics.Finding) []heuristics.Finding {
	seen := make(map[string]bool)
	out := make([]heuristics.Finding, 0, len(in))
	for _, item := range in {
		key := item.Code + "\x00" + item.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code == out[j].Code {
			return out[i].Evidence < out[j].Evidence
		}
		return out[i].Code < out[j].Code
	})
	return out
}
