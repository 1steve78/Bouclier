package webcheck

import (
	"net/http"
	"strings"
	"testing"
)

func TestAnalyzeInformationDisclosure(t *testing.T) {
	result := &HTTPInspectionResult{Headers: http.Header{"Server": {"nginx/1.2"}, "X-Powered-By": {"Framework 2"}, "X-AspNet-Version": {"4.0"}, "X-Generator": {"CMS"}}}
	findings, err := AnalyzeInformationDisclosure(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings = %+v", findings)
	}
	for _, finding := range findings {
		if !strings.HasPrefix(finding.Code, "WEB_TECHNOLOGY_DISCLOSURE_") || strings.Contains(strings.ToLower(finding.Description), "vulnerable") {
			t.Fatalf("overstated disclosure: %+v", finding)
		}
	}
}
