package risk

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogCoverageAudit(t *testing.T) {
	fset := token.NewFileSet()
	discoveredCodes := make(map[string][]string)

	packages := []string{
		"../../internal/heuristics",
		"../../internal/domain",
		"../../internal/registration",
		"../../internal/tlscheck",
		"../../internal/certanalysis",
		"../../internal/ct",
		"../../internal/tlsintel",
		"../../internal/webcheck",
		"../../internal/webintel",
		"../../internal/intel",
	}

	for _, pkg := range packages {
		filepath.WalkDir(pkg, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}

			ast.Inspect(node, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					val := strings.Trim(lit.Value, `"`)
					if isFindingCode(val) {
						discoveredCodes[val] = append(discoveredCodes[val], path)
					}
				}
				return true
			})
			return nil
		})
	}

	// Expand known template prefixes dynamically constructed in Phase 4
	delete(discoveredCodes, "WEB_CSP_DIRECTIVE_MISSING_")
	discoveredCodes["WEB_CSP_DIRECTIVE_MISSING_DEFAULT_SRC"] = []string{"internal/webcheck/headers.go"}
	discoveredCodes["WEB_CSP_DIRECTIVE_MISSING_SCRIPT_SRC"] = []string{"internal/webcheck/headers.go"}
	discoveredCodes["WEB_CSP_DIRECTIVE_MISSING_OBJECT_SRC"] = []string{"internal/webcheck/headers.go"}
	discoveredCodes["WEB_CSP_DIRECTIVE_MISSING_BASE_URI"] = []string{"internal/webcheck/headers.go"}

	delete(discoveredCodes, "WEB_HTML_MIXED_CONTENT_")
	discoveredCodes["WEB_HTML_MIXED_CONTENT_SCRIPT"] = []string{"internal/webcheck/html.go"}
	discoveredCodes["WEB_HTML_MIXED_CONTENT_IFRAME"] = []string{"internal/webcheck/html.go"}
	discoveredCodes["WEB_HTML_MIXED_CONTENT_STYLESHEET"] = []string{"internal/webcheck/html.go"}
	discoveredCodes["WEB_HTML_MIXED_CONTENT_OBJECT"] = []string{"internal/webcheck/html.go"}
	discoveredCodes["WEB_HTML_MIXED_CONTENT_EMBED"] = []string{"internal/webcheck/html.go"}

	delete(discoveredCodes, "WEB_TECHNOLOGY_DISCLOSURE_")
	discoveredCodes["WEB_TECHNOLOGY_DISCLOSURE_SERVER"] = []string{"internal/webcheck/disclosure.go"}
	discoveredCodes["WEB_TECHNOLOGY_DISCLOSURE_X_POWERED_BY"] = []string{"internal/webcheck/disclosure.go"}
	discoveredCodes["WEB_TECHNOLOGY_DISCLOSURE_X_ASPNET_VERSION"] = []string{"internal/webcheck/disclosure.go"}
	discoveredCodes["WEB_TECHNOLOGY_DISCLOSURE_X_GENERATOR"] = []string{"internal/webcheck/disclosure.go"}

	catalog := Catalog()
	catalogCodes := make(map[string]CatalogEntry)
	var unscoredCatalogEntries []string
	var scoredCatalogEntries []string
	for _, entry := range catalog {
		catalogCodes[entry.Code] = entry
		if !entry.ScoreEligible {
			unscoredCatalogEntries = append(unscoredCatalogEntries, entry.Code)
		} else {
			scoredCatalogEntries = append(scoredCatalogEntries, entry.Code)
		}
	}

	if len(catalog) != 86 {
		t.Fatalf("expected 86 catalog entries, got %d", len(catalog))
	}
	if len(discoveredCodes) != 86 {
		t.Fatalf("expected 86 discovered codes, got %d", len(discoveredCodes))
	}

	for code := range discoveredCodes {
		if _, ok := catalogCodes[code]; !ok {
			t.Errorf("discovered code %s is not in catalog", code)
		}
	}
	for code := range catalogCodes {
		if _, ok := discoveredCodes[code]; !ok {
			t.Errorf("catalog code %s was not discovered in source", code)
		}
	}

	t.Logf("Total discovered Phase 1-4 codes: %d", len(discoveredCodes))
	t.Logf("Total catalog entries: %d", len(catalog))
	t.Logf("Scored catalog entries: %d", len(scoredCatalogEntries))
	t.Logf("Intentionally unscored (excluded from scoring) catalog entries: %d", len(unscoredCatalogEntries))
}

func isFindingCode(s string) bool {
	prefixes := []string{"URL_", "BRAND_", "PHISHING_", "SUSPICIOUS_", "EXCESSIVE_", "LONG_", "NUMERIC_", "CERT_", "WEB_", "INTEL_"}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) && len(s) > len(p) {
			for _, r := range s {
				if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' {
					return false
				}
			}
			return true
		}
	}
	return false
}
