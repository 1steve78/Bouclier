package webcheck

import (
	"fmt"
	"strings"

	"bouclier/internal/heuristics"
)

// AnalyzeInformationDisclosure reports selected technology-identifying headers.
func AnalyzeInformationDisclosure(result *HTTPInspectionResult) ([]heuristics.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze information disclosure: result is nil")
	}
	var findings []heuristics.Finding
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		for _, value := range values(result.Headers, name) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			// Header values can contain deployment-specific details; bound and
			// normalize them, but never interpret a product name as a vulnerability.
			if len(value) > 120 {
				value = value[:120]
			}
			findings = append(findings, finding("WEB_TECHNOLOGY_DISCLOSURE_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_")), "Response exposes technology information", "A response header identifies server or application technology; this observation alone does not establish a vulnerability.", "web-information-disclosure", strings.ToLower(name)+" header is present: "+value))
		}
	}
	return sortedFindings(findings), nil
}
