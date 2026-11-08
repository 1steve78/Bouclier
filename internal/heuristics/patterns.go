package heuristics

import (
	"fmt"
	"strings"
)

const (
	maxHostnameLength   = 100
	maxSubdomainLabels  = 2
	maxHostnameHyphens  = 3
	maxHostnameDigitRun = 7
	maxPathLength       = 200
	maxPathSegments     = 8
	maxEncodedPathRun   = 60
	maxRepeatedPathRun  = 32
)

// Finding is an explainable URL pattern signal. Evidence must not contain
// credentials or raw query values.
type Finding struct {
	Code        string
	Title       string
	Description string
	Category    string
	Evidence    string
}

// AnalyzePatterns runs independent, deterministic URL structure checks. It
// does not assign a verdict or score and does not access the network.
func AnalyzePatterns(u *NormalizedURL, classification *Classification) ([]Finding, error) {
	if u == nil {
		return nil, fmt.Errorf("analyze URL patterns: URL is nil")
	}
	if classification == nil {
		return nil, fmt.Errorf("analyze URL patterns: classification is nil")
	}
	if u.Hostname == "" {
		return nil, fmt.Errorf("analyze URL patterns: hostname is empty")
	}

	detectors := []func(*NormalizedURL, *Classification) *Finding{
		detectExcessiveSubdomains,
		detectUserInfo,
		detectLongHostname,
		detectHostnameHyphens,
		detectHostnameDigitRun,
		detectLongPath,
		detectDeepPath,
		detectRepeatedPathSeparators,
		detectEncodedPathRun,
		detectRepeatedPathCharacters,
		detectIPLiteral,
		detectURLLikePath,
	}

	findings := make([]Finding, 0)
	seen := make(map[string]struct{}, len(detectors))
	for _, detect := range detectors {
		finding := detect(u, classification)
		if finding == nil {
			continue
		}
		if _, duplicate := seen[finding.Code]; duplicate {
			continue
		}
		seen[finding.Code] = struct{}{}
		findings = append(findings, *finding)
	}
	brandFindings, err := AnalyzeBrandImpersonation(u)
	if err != nil {
		return nil, fmt.Errorf("analyze brand patterns: %w", err)
	}
	for _, brandFinding := range brandFindings {
		if _, duplicate := seen[brandFinding.Code]; duplicate {
			continue
		}
		seen[brandFinding.Code] = struct{}{}
		findings = append(findings, brandFinding)
	}
	additionalDetectors := []struct {
		name   string
		detect func(*NormalizedURL, *Classification) (*Finding, error)
	}{
		{name: "suspicious TLD", detect: detectSuspiciousTLD},
		{name: "URL shortener", detect: detectShortener},
		{name: "phishing keywords", detect: func(u *NormalizedURL, _ *Classification) (*Finding, error) {
			return detectPhishingKeywords(u)
		}},
	}
	for _, detector := range additionalDetectors {
		newFinding, err := detector.detect(u, classification)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", detector.name, err)
		}
		if newFinding == nil {
			continue
		}
		if _, duplicate := seen[newFinding.Code]; duplicate {
			continue
		}
		seen[newFinding.Code] = struct{}{}
		findings = append(findings, *newFinding)
	}
	return findings, nil
}

func detectExcessiveSubdomains(u *NormalizedURL, _ *Classification) *Finding {
	registrable, err := RegistrableDomain(u.Hostname)
	if err != nil {
		return nil
	}
	hostLabels := strings.Split(strings.TrimSuffix(u.Hostname, "."), ".")
	domainLabels := strings.Split(registrable, ".")
	subdomainLabels := len(hostLabels) - len(domainLabels)
	if subdomainLabels <= maxSubdomainLabels {
		return nil
	}
	return finding("URL_MANY_SUBDOMAINS", "Many hostname labels", "Several labels before the registrable domain can obscure the destination structure.", "hostname-structure", fmt.Sprintf("hostname has %d subdomain labels before its registrable domain (threshold: %d)", subdomainLabels, maxSubdomainLabels))
}

func detectUserInfo(u *NormalizedURL, _ *Classification) *Finding {
	if !u.HasUserInfo {
		return nil
	}
	return finding("URL_USERINFO", "URL contains userinfo", "Text before the @ sign is URL userinfo, not the destination host; it can make a URL appear to point somewhere else. Credentials are intentionally omitted from evidence.", "url-structure", "userinfo is present before the destination host")
}

func detectLongHostname(u *NormalizedURL, _ *Classification) *Finding {
	if len(u.Hostname) <= maxHostnameLength {
		return nil
	}
	return finding("URL_LONG_HOSTNAME", "Long hostname", "A very long hostname can be difficult to inspect and may hide confusing label structure. Length alone does not indicate maliciousness.", "hostname-structure", fmt.Sprintf("hostname is %d characters (threshold: %d)", len(u.Hostname), maxHostnameLength))
}

func detectHostnameHyphens(u *NormalizedURL, _ *Classification) *Finding {
	count := strings.Count(u.Hostname, "-")
	if count <= maxHostnameHyphens {
		return nil
	}
	return finding("URL_MANY_HOSTNAME_HYPHENS", "Many hyphens in hostname", "A hostname with numerous hyphens can be harder to read. Hyphens are valid in DNS names and this signal is not a verdict.", "hostname-structure", fmt.Sprintf("hostname contains %d hyphens (threshold: %d)", count, maxHostnameHyphens))
}

func detectHostnameDigitRun(u *NormalizedURL, _ *Classification) *Finding {
	run := longestDigitRun(u.Hostname)
	if run <= maxHostnameDigitRun {
		return nil
	}
	return finding("URL_HOSTNAME_DIGIT_RUN", "Long digit sequence in hostname", "A long numeric run in a hostname can be difficult to distinguish from an identifier or address-like value.", "hostname-structure", fmt.Sprintf("hostname has a consecutive digit run of %d characters (threshold: %d)", run, maxHostnameDigitRun))
}

func detectLongPath(u *NormalizedURL, _ *Classification) *Finding {
	if len(u.Path) <= maxPathLength {
		return nil
	}
	return finding("URL_LONG_PATH", "Long URL path", "A long path can make the destination harder to inspect. Query strings are excluded from this check.", "path-structure", fmt.Sprintf("path is %d escaped characters (threshold: %d)", len(u.Path), maxPathLength))
}

func detectDeepPath(u *NormalizedURL, _ *Classification) *Finding {
	segments := pathSegmentCount(u.Path)
	if segments <= maxPathSegments {
		return nil
	}
	return finding("URL_DEEP_PATH", "Deeply nested URL path", "Many nested path segments can make the meaningful destination context harder to see.", "path-structure", fmt.Sprintf("path has %d non-empty segments (threshold: %d)", segments, maxPathSegments))
}

func detectRepeatedPathSeparators(u *NormalizedURL, _ *Classification) *Finding {
	if !strings.Contains(u.Path, "//") {
		return nil
	}
	return finding("URL_REPEATED_PATH_SEPARATORS", "Repeated path separators", "Repeated slashes inside the path can create visually confusing URL structure.", "path-structure", "path contains consecutive slash separators")
}

func detectEncodedPathRun(u *NormalizedURL, _ *Classification) *Finding {
	run := longestPercentEscapeRun(u.Path)
	if run < maxEncodedPathRun {
		return nil
	}
	return finding("URL_LONG_ENCODED_PATH", "Long encoded path section", "A long consecutive run of percent-encoded bytes can obscure the readable path content.", "path-structure", fmt.Sprintf("path contains a %d-character consecutive percent-escape run (threshold: %d)", run, maxEncodedPathRun))
}

func detectRepeatedPathCharacters(u *NormalizedURL, _ *Classification) *Finding {
	run := longestRepeatedPathCharacterRun(u.Path)
	if run < maxRepeatedPathRun {
		return nil
	}
	return finding("URL_REPEATED_PATH_CHARACTERS", "Repeated characters in path", "A long run of the same character can act as visual filler and make the rest of a path less noticeable.", "path-structure", fmt.Sprintf("path contains a repeated-character run of %d characters (threshold: %d)", run, maxRepeatedPathRun))
}

func detectIPLiteral(_ *NormalizedURL, classification *Classification) *Finding {
	if !classification.IsIPAddress && !classification.IsLiteralIP {
		return nil
	}
	return finding("URL_IP_LITERAL", "IP address used as destination", "This URL names an IP literal instead of a DNS hostname. That can be legitimate, but it may be less familiar to users.", "destination", "destination is an IP literal")
}

func detectURLLikePath(u *NormalizedURL, _ *Classification) *Finding {
	path := strings.ToLower(u.Path)
	if !strings.HasPrefix(path, "/http://") && !strings.HasPrefix(path, "/https://") {
		return nil
	}
	return finding("URL_SCHEME_LIKE_PATH", "URL-like text in path", "The path begins with text formatted like a complete URL, which may distract from the actual hostname shown by the browser.", "url-structure", "path begins with an http or https URL-like prefix")
}

func finding(code, title, description, category, evidence string) *Finding {
	return &Finding{Code: code, Title: title, Description: description, Category: category, Evidence: evidence}
}

func longestDigitRun(value string) int {
	longest, current := 0, 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			current++
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	return longest
}

func pathSegmentCount(path string) int {
	count := 0
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if segment != "" {
			count++
		}
	}
	return count
}

func longestPercentEscapeRun(path string) int {
	longest, current := 0, 0
	for i := 0; i+2 < len(path); {
		if path[i] == '%' && isHex(path[i+1]) && isHex(path[i+2]) {
			current += 3
			i += 3
			if current > longest {
				longest = current
			}
			continue
		}
		current = 0
		i++
	}
	return longest
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func longestRepeatedPathCharacterRun(path string) int {
	longest, current := 0, 0
	var previous byte
	for i := 0; i < len(path); i++ {
		if path[i] == previous {
			current++
		} else {
			previous = path[i]
			current = 1
		}
		if current > longest {
			longest = current
		}
	}
	return longest
}
