package webcheck

import (
	"net/http"
	"testing"
)

func TestAnalyzeCORSIsContextual(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		want    string
	}{
		{"wildcard with credentials", http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Credentials": {"true"}}, "WEB_CORS_WILDCARD_WITH_CREDENTIALS"},
		{"null", http.Header{"Access-Control-Allow-Origin": {"null"}}, "WEB_CORS_NULL_ORIGIN"},
		{"wildcard alone", http.Header{"Access-Control-Allow-Origin": {"*"}}, ""},
		{"broad methods", http.Header{"Access-Control-Allow-Methods": {"GET, *"}}, "WEB_CORS_BROAD_ALLOWLIST"},
		{"missing", http.Header{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := AnalyzeCORS(&HTTPInspectionResult{Headers: tc.headers})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				if finding.Code == tc.want && tc.want != "" {
					found = true
				}
			}
			if tc.want != "" && !found {
				t.Fatalf("expected %s in %+v", tc.want, findings)
			}
			if tc.want == "" && len(findings) != 0 {
				t.Fatalf("unexpected findings: %+v", findings)
			}
		})
	}
}
