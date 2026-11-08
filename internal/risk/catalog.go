package risk

import "sort"

// CatalogEntry gives a stable finding code a conservative meaning and action.
type CatalogEntry struct {
	Code          string
	Severity      Severity
	Confidence    Confidence
	Category      string
	Remediation   string
	ScoreEligible bool
}

var findingCatalog = buildCatalog()

func buildCatalog() map[string]CatalogEntry {
	entries := []CatalogEntry{
		entry("URL_MANY_SUBDOMAINS", SeverityLow, ConfidenceHigh, "url-structure", "Review the full hostname and confirm the registrable domain is the intended destination.", true),
		entry("URL_USERINFO", SeverityMedium, ConfidenceHigh, "url-structure", "Remove misleading userinfo and verify the destination hostname before opening the URL.", true),
		entry("URL_LONG_HOSTNAME", SeverityLow, ConfidenceHigh, "url-structure", "Review the hostname labels and confirm they belong to the expected service.", true),
		entry("URL_MANY_HOSTNAME_HYPHENS", SeverityLow, ConfidenceHigh, "url-structure", "Verify the domain owner and avoid relying on brand-like text in hostname labels.", true),
		entry("URL_HOSTNAME_DIGIT_RUN", SeverityLow, ConfidenceHigh, "url-structure", "Verify the hostname through a trusted source before using it.", true),
		entry("URL_LONG_PATH", SeverityInformational, ConfidenceHigh, "url-structure", "Check that the long path is expected; path length alone is not a security defect.", false),
		entry("URL_DEEP_PATH", SeverityLow, ConfidenceHigh, "url-structure", "Review the complete path and confirm the link destination with its owner.", true),
		entry("URL_REPEATED_PATH_SEPARATORS", SeverityLow, ConfidenceHigh, "url-structure", "Review the unusual path formatting before following the link.", true),
		entry("URL_LONG_ENCODED_PATH", SeverityLow, ConfidenceHigh, "url-structure", "Decode and review the path using a trusted tool before opening it.", true),
		entry("URL_REPEATED_PATH_CHARACTERS", SeverityLow, ConfidenceHigh, "url-structure", "Review the path for visual obfuscation; repeated characters are not proof of abuse.", true),
		entry("URL_IP_LITERAL", SeverityLow, ConfidenceHigh, "url-structure", "Verify that the IP address is an expected service destination.", true),
		entry("URL_SCHEME_LIKE_PATH", SeverityLow, ConfidenceHigh, "url-structure", "Check the actual hostname separately from URL-like text in its path.", true),
		entry("BRAND_EXACT_LABEL", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Verify the registrable domain against the brand's official site or trusted documentation.", true),
		entry("BRAND_CHARACTER_SUBSTITUTION", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Check each hostname character and use the brand's independently verified domain.", true),
		entry("BRAND_SIMILAR_DOMAIN", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Confirm ownership through a trusted brand channel; visual similarity is not proof of intent.", true),
		entry("BRAND_IDN_SIMILAR_DOMAIN", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Inspect the ASCII/Punycode hostname and verify the destination with the brand.", true),
		entry("BRAND_MISLEADING_SUBDOMAIN", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Read the hostname from right to left and verify the registrable domain, not the subdomain label.", true),
		entry("BRAND_IN_DOMAIN_LABEL", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Confirm the registrable domain independently; a brand label embedded in it does not establish ownership.", true),
		entry("BRAND_SIMILAR_REGISTRABLE_DOMAIN", SeverityHigh, ConfidenceMedium, "brand-impersonation", "Verify the complete registrable domain through an official brand channel.", true),
		entry("SUSPICIOUS_TLD", SeverityLow, ConfidenceMedium, "domain-suffix", "Use domain ownership and context to assess the site; a suffix alone is not malicious evidence.", true),
		entry("URL_SHORTENER", SeverityLow, ConfidenceHigh, "url-shortener", "Expand or verify the destination through a trusted mechanism before following the shortened link.", true),
		entry("PHISHING_KEYWORD", SeverityLow, ConfidenceMedium, "phishing-language", "Review the complete destination; account-related wording also appears in legitimate URLs.", true),
		entry("EXCESSIVE_SUBDOMAIN_DEPTH", SeverityLow, ConfidenceHigh, "domain-structure", "Confirm that every subdomain label is expected and belongs to the registrable domain owner.", true),
		entry("LONG_HOSTNAME", SeverityLow, ConfidenceHigh, "domain-structure", "Verify the long hostname and its registrable domain through a trusted source.", true),
		entry("LONG_DOMAIN_LABEL", SeverityLow, ConfidenceHigh, "domain-structure", "Review the unusually long label; length alone does not indicate abuse.", true),
		entry("EXCESSIVE_HYPHENS", SeverityLow, ConfidenceHigh, "domain-structure", "Verify the hostname owner and inspect labels for confusing separators.", true),
		entry("NUMERIC_HEAVY_LABEL", SeverityLow, ConfidenceMedium, "domain-structure", "Confirm that the numeric-heavy hostname label is expected for the service.", true),
		entry("SUSPICIOUS_SUBDOMAIN_COMBINATION", SeverityMedium, ConfidenceMedium, "domain-structure", "Verify the full hostname and registrable domain before entering account information.", true),
		entry("CERT_HOSTNAME_MISMATCH", SeverityHigh, ConfidenceHigh, "certificate-identity", "Configure the service with a certificate whose SAN matches the intended TLS server name.", true),
		entry("CERT_EXPIRED", SeverityHigh, ConfidenceHigh, "certificate-validity", "Renew and deploy a currently valid leaf certificate.", true),
		entry("CERT_NOT_YET_VALID", SeverityHigh, ConfidenceHigh, "certificate-validity", "Check certificate issuance and server clock, then deploy a certificate valid at the current time.", true),
		entry("CERT_INTERMEDIATE_EXPIRED", SeverityHigh, ConfidenceHigh, "certificate-validity", "Replace the expired intermediate chain and serve the correct current intermediates.", true),
		entry("CERT_INTERMEDIATE_NOT_YET_VALID", SeverityHigh, ConfidenceHigh, "certificate-validity", "Check the intermediate chain and system time, then deploy a valid chain.", true),
		entry("CERT_SELF_SIGNED", SeverityMedium, ConfidenceHigh, "certificate-trust", "Use a certificate chaining to the intended public or managed trust anchor where public trust is required.", true),
		entry("CERT_ROOTS_UNAVAILABLE", SeverityInformational, ConfidenceHigh, "certificate-trust", "Repeat analysis in an environment with an available trust store; this is missing analysis evidence.", false),
		entry("CERT_CHAIN_INVALID", SeverityHigh, ConfidenceHigh, "certificate-trust", "Correct the certificate chain, constraints, or server-auth usage so standard verification succeeds.", true),
		entry("CERT_UNTRUSTED", SeverityHigh, ConfidenceHigh, "certificate-trust", "Deploy a chain that terminates at a trust anchor accepted by intended clients.", true),
		entry("WEB_HTTPS_DOWNGRADE", SeverityHigh, ConfidenceHigh, "web-transport", "Keep the redirect chain on HTTPS and send HTTP requests to HTTPS destinations.", true),
		entry("WEB_CROSS_ORIGIN_REDIRECT", SeverityLow, ConfidenceHigh, "web-navigation", "Verify that the cross-origin destination is expected; this observation does not establish maliciousness.", true),
		entry("WEB_HSTS_MISSING", SeverityLow, ConfidenceHigh, "web-transport", "Consider enabling HSTS after confirming HTTPS works across the intended hostnames.", true),
		entry("WEB_HSTS_WEAK", SeverityLow, ConfidenceHigh, "web-transport", "Use an appropriate HSTS max-age and validate the policy before broad deployment.", true),
		entry("WEB_HSTS_NO_SUBDOMAINS", SeverityInformational, ConfidenceHigh, "web-transport", "Consider includeSubDomains only after confirming every covered subdomain supports HTTPS.", false),
		entry("WEB_HSTS_PRELOAD_DIRECTIVE", SeverityInformational, ConfidenceHigh, "web-transport", "Check all preload requirements independently; the directive does not mean the site is on a browser preload list.", false),
		entry("WEB_CSP_MISSING", SeverityLow, ConfidenceHigh, "web-content-policy", "Deploy an enforced CSP suited to the site's resources and test it before enforcement.", true),
		entry("WEB_CSP_REPORT_ONLY", SeverityInformational, ConfidenceHigh, "web-content-policy", "If enforcement is intended, review reports and deploy a separate enforced CSP.", false),
		entry("WEB_CSP_DIRECTIVE_MISSING_DEFAULT_SRC", SeverityLow, ConfidenceHigh, "web-content-policy", "Consider a restrictive default-src directive that fits the application.", true),
		entry("WEB_CSP_DIRECTIVE_MISSING_SCRIPT_SRC", SeverityLow, ConfidenceHigh, "web-content-policy", "Consider explicitly limiting script sources in the enforced policy.", true),
		entry("WEB_CSP_DIRECTIVE_MISSING_OBJECT_SRC", SeverityLow, ConfidenceHigh, "web-content-policy", "Consider object-src 'none' unless the site requires embedded objects.", true),
		entry("WEB_CSP_DIRECTIVE_MISSING_BASE_URI", SeverityLow, ConfidenceHigh, "web-content-policy", "Consider restricting base-uri to prevent unexpected base URL changes.", true),
		entry("WEB_CSP_WILDCARD_SOURCE", SeverityMedium, ConfidenceHigh, "web-content-policy", "Replace wildcard resource sources with the specific origins the application needs.", true),
		entry("WEB_CSP_UNSAFE_INLINE", SeverityMedium, ConfidenceHigh, "web-content-policy", "Avoid unsafe-inline where practical; consider nonces or hashes for required inline code.", true),
		entry("WEB_CSP_UNSAFE_EVAL", SeverityMedium, ConfidenceHigh, "web-content-policy", "Remove unsafe-eval and avoid dynamic evaluation of script strings where practical.", true),
		entry("WEB_CLICKJACKING_PROTECTION_MISSING", SeverityLow, ConfidenceHigh, "web-content-policy", "Set an appropriate enforced frame-ancestors policy or X-Frame-Options header.", true),
		entry("WEB_NOSNIFF_MISSING", SeverityLow, ConfidenceHigh, "web-content-policy", "Set X-Content-Type-Options: nosniff and serve accurate content types.", true),
		entry("WEB_REFERRER_POLICY_MISSING", SeverityInformational, ConfidenceHigh, "web-privacy", "Choose a Referrer-Policy appropriate for the site's privacy requirements.", false),
		entry("WEB_REFERRER_POLICY_INVALID", SeverityLow, ConfidenceHigh, "web-privacy", "Use a recognized Referrer-Policy value.", true),
		entry("WEB_REFERRER_POLICY_WEAK", SeverityLow, ConfidenceHigh, "web-privacy", "Prefer a policy that avoids sharing full paths and query strings with other origins.", true),
		entry("WEB_PERMISSIONS_POLICY_UNRESTRICTED", SeverityLow, ConfidenceMedium, "web-privacy", "Restrict the feature allowlist to the origins that actually need access.", true),
		entry("WEB_COOKIE_SESSION_MISSING_SECURE", SeverityMedium, ConfidenceHigh, "web-cookie", "Mark session-like cookies Secure so browsers send them only over HTTPS.", true),
		entry("WEB_COOKIE_SESSION_MISSING_HTTPONLY", SeverityMedium, ConfidenceHigh, "web-cookie", "Mark session cookies HttpOnly when script access is not required.", true),
		entry("WEB_COOKIE_SESSION_OVER_HTTP", SeverityHigh, ConfidenceHigh, "web-cookie", "Serve the response and session cookie only through HTTPS.", true),
		entry("WEB_COOKIE_SAMESITE_NONE_WITHOUT_SECURE", SeverityMedium, ConfidenceHigh, "web-cookie", "Add Secure to SameSite=None cookies and confirm cross-site behavior is required.", true),
		entry("WEB_COOKIE_SESSION_SAMESITE_UNSPECIFIED", SeverityLow, ConfidenceMedium, "web-cookie", "Set an explicit SameSite policy appropriate for the session flow.", true),
		entry("WEB_CORS_NULL_ORIGIN", SeverityMedium, ConfidenceMedium, "web-cors", "Review whether opaque/null origins need access and avoid granting sensitive data to them.", true),
		entry("WEB_CORS_WILDCARD_WITH_CREDENTIALS", SeverityMedium, ConfidenceHigh, "web-cors", "Review CORS origin and credential policy; browsers reject the literal wildcard with credentials.", true),
		entry("WEB_CORS_BROAD_ALLOWLIST", SeverityLow, ConfidenceMedium, "web-cors", "Limit allowed methods and headers to those required by the application.", true),
		entry("WEB_HTML_INCOMPLETE", SeverityInformational, ConfidenceHigh, "web-html", "Repeat with an adequately bounded response to assess the rest of the document; no risk is inferred from truncation.", false),
		entry("WEB_HTML_META_CSP_PRESENT", SeverityInformational, ConfidenceHigh, "web-html", "Use and assess an HTTP CSP header for a policy with broader browser support and clearer enforcement.", false),
		entry("WEB_HTML_META_REFERRER_POLICY", SeverityInformational, ConfidenceHigh, "web-html", "Review the response Referrer-Policy header separately from the document meta element.", false),
		entry("WEB_HTML_MIXED_CONTENT_SCRIPT", SeverityHigh, ConfidenceHigh, "web-html-mixed-content", "Serve script resources over HTTPS and update the page reference.", true),
		entry("WEB_HTML_MIXED_CONTENT_IFRAME", SeverityMedium, ConfidenceHigh, "web-html-mixed-content", "Serve framed content over HTTPS and review the embedded origin.", true),
		entry("WEB_HTML_MIXED_CONTENT_STYLESHEET", SeverityMedium, ConfidenceHigh, "web-html-mixed-content", "Serve stylesheets over HTTPS and update the page reference.", true),
		entry("WEB_HTML_MIXED_CONTENT_OBJECT", SeverityMedium, ConfidenceHigh, "web-html-mixed-content", "Remove or serve embedded objects over HTTPS.", true),
		entry("WEB_HTML_MIXED_CONTENT_EMBED", SeverityMedium, ConfidenceHigh, "web-html-mixed-content", "Remove or serve embedded resources over HTTPS.", true),
		entry("WEB_HTML_HTTP_LINK", SeverityInformational, ConfidenceHigh, "web-html-link", "Use HTTPS links where the destination supports it; this link was observed, not fetched.", false),
		entry("WEB_HTML_INSECURE_FORM", SeverityMedium, ConfidenceHigh, "web-html-form", "Change the form action to HTTPS and verify the destination before sending data.", true),
		entry("WEB_HTML_INSECURE_PASSWORD_FORM", SeverityHigh, ConfidenceHigh, "web-html-form", "Submit password forms only to an HTTPS endpoint and confirm the endpoint is trusted.", true),
		entry("WEB_TECHNOLOGY_DISCLOSURE_SERVER", SeverityInformational, ConfidenceHigh, "web-information-disclosure", "Consider minimizing unnecessary server banner details; disclosure alone does not establish vulnerability.", false),
		entry("WEB_TECHNOLOGY_DISCLOSURE_X_POWERED_BY", SeverityInformational, ConfidenceHigh, "web-information-disclosure", "Consider removing unnecessary framework identification headers.", false),
		entry("WEB_TECHNOLOGY_DISCLOSURE_X_ASPNET_VERSION", SeverityInformational, ConfidenceHigh, "web-information-disclosure", "Consider removing unnecessary platform version headers.", false),
		entry("WEB_TECHNOLOGY_DISCLOSURE_X_GENERATOR", SeverityInformational, ConfidenceHigh, "web-information-disclosure", "Consider removing unnecessary generator metadata headers.", false),
		entry("INTEL_MALICIOUS_URL", SeverityCritical, ConfidenceHigh, "threat-intelligence", "Avoid accessing this destination; the URL is flagged as malicious in threat intelligence feeds.", true),
		entry("INTEL_MALICIOUS_DOMAIN", SeverityHigh, ConfidenceHigh, "threat-intelligence", "Avoid interacting with this domain; the hostname matches a confirmed malicious indicator.", true),
		entry("INTEL_MALICIOUS_IP", SeverityHigh, ConfidenceHigh, "threat-intelligence", "Inspect traffic to this destination; the resolved server IP is flagged in threat intelligence.", true),
		entry("INTEL_SUSPICIOUS_REGISTRABLE_DOMAIN", SeverityMedium, ConfidenceMedium, "threat-intelligence", "Exercise caution; the parent registrable domain is flagged in threat intelligence feeds.", true),
		entry("INTEL_MATCH_STALE", SeverityLow, ConfidenceLow, "threat-intelligence", "Verify current domain reputation; the destination matches a historical/stale threat indicator.", true),
	}
	result := make(map[string]CatalogEntry, len(entries))
	for _, item := range entries {
		result[item.Code] = item
	}
	return result
}

func entry(code string, severity Severity, confidence Confidence, category, remediation string, scored bool) CatalogEntry {
	return CatalogEntry{Code: code, Severity: severity, Confidence: confidence, Category: category, Remediation: remediation, ScoreEligible: scored}
}

// Catalog returns the supported code mappings in stable order.
func Catalog() []CatalogEntry {
	result := make([]CatalogEntry, 0, len(findingCatalog))
	for _, item := range findingCatalog {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Code < result[j].Code })
	return result
}

// LookupCatalog returns a copy of the mapping for code.
func LookupCatalog(code string) (CatalogEntry, bool) {
	item, ok := findingCatalog[code]
	return item, ok
}
