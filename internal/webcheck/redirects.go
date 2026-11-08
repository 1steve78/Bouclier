package webcheck

import (
	"fmt"

	"bouclier/internal/heuristics"
)

// AnalyzeRedirects converts recorded redirect behavior into contextual observations.
func AnalyzeRedirects(result *HTTPInspectionResult) ([]heuristics.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze redirects: result is nil")
	}
	var findings []heuristics.Finding
	if result.HTTPSDowngrade {
		findings = append(findings, finding("WEB_HTTPS_DOWNGRADE", "Redirect chain downgrades HTTPS to HTTP", "At least one redirect moves from HTTPS to unencrypted HTTP.", "web-transport", "HTTPS-to-HTTP redirect observed"))
	}
	if result.CrossOriginRedirect {
		findings = append(findings, finding("WEB_CROSS_ORIGIN_REDIRECT", "Redirect chain crosses origins", "At least one redirect changes scheme, hostname, or effective port; review the destination as a separate site.", "web-navigation", "cross-origin redirect observed"))
	}
	return sortedFindings(findings), nil
}
