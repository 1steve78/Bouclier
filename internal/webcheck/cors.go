package webcheck

import (
	"fmt"
	"strings"

	"bouclier/internal/heuristics"
)

// AnalyzeCORS reports only behavior evidenced by the inspected response; it
// does not send Origin or preflight probes.
func AnalyzeCORS(result *HTTPInspectionResult) ([]heuristics.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze CORS: result is nil")
	}
	origins := values(result.Headers, "Access-Control-Allow-Origin")
	credentials := values(result.Headers, "Access-Control-Allow-Credentials")
	methods := values(result.Headers, "Access-Control-Allow-Methods")
	headers := values(result.Headers, "Access-Control-Allow-Headers")
	var findings []heuristics.Finding
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "null" {
			findings = append(findings, finding("WEB_CORS_NULL_ORIGIN", "CORS allows a null origin", "A null origin is shared by some sandboxed and opaque-origin contexts; this response alone does not show who can exploit it.", "web-cors", "access-control-allow-origin permits null"))
		}
		if origin == "*" && hasToken(credentials, "true") {
			findings = append(findings, finding("WEB_CORS_WILDCARD_WITH_CREDENTIALS", "CORS wildcard is combined with credentials", "Browsers reject the literal wildcard with credentials, but the combination suggests an inconsistent or overly broad policy.", "web-cors", "wildcard origin and allow-credentials true are both present"))
		}
	}
	for _, list := range [][]string{methods, headers} {
		for _, raw := range list {
			if strings.Contains(raw, "*") {
				findings = append(findings, finding("WEB_CORS_BROAD_ALLOWLIST", "CORS response contains a wildcard allowlist", "The response advertises a wildcard method or header allowlist; actual browser access also depends on origin and request context.", "web-cors", "wildcard in Access-Control-Allow-Methods or Access-Control-Allow-Headers"))
				break
			}
		}
	}
	return sortedFindings(findings), nil
}
