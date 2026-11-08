package heuristics

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAnalyzePatterns(t *testing.T) {
	longHost := strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + ".com"
	longEncoded := "/" + strings.Repeat("%61", 24)
	tests := []struct {
		name      string
		input     string
		wantCodes []string
	}{
		{name: "ordinary root", input: "https://example.com/"},
		{name: "ordinary www page", input: "https://www.example.com/about"},
		{name: "ordinary shop page", input: "https://shop.example.com/products"},
		{name: "userinfo obfuscation", input: "https://google.com@evil.example/login", wantCodes: []string{"URL_USERINFO", "PHISHING_KEYWORD"}},
		{name: "userinfo with credentials", input: "https://alice:secret-password@example.com/login?token=private", wantCodes: []string{"URL_USERINFO", "PHISHING_KEYWORD"}},
		{name: "many subdomains", input: "https://login.account.verify.example.com/", wantCodes: []string{"URL_MANY_SUBDOMAINS", "PHISHING_KEYWORD"}},
		{name: "long valid hostname", input: "https://" + longHost + "/", wantCodes: []string{"URL_LONG_HOSTNAME"}},
		{name: "hostname with many hyphens", input: "https://one-two-three-four-five.example/", wantCodes: []string{"URL_MANY_HOSTNAME_HYPHENS"}},
		{name: "long hostname digit run", input: "https://account12345678.example/", wantCodes: []string{"URL_HOSTNAME_DIGIT_RUN"}},
		{name: "deep path", input: "https://example.com/a/b/c/d/e/f/g/h/i/j", wantCodes: []string{"URL_DEEP_PATH"}},
		{name: "long path", input: "https://example.com/" + strings.Repeat("ab", maxPathLength/2), wantCodes: []string{"URL_LONG_PATH"}},
		{name: "repeated separators", input: "https://example.com/account//verify", wantCodes: []string{"URL_REPEATED_PATH_SEPARATORS", "PHISHING_KEYWORD"}},
		{name: "long encoded path section", input: "https://example.com" + longEncoded, wantCodes: []string{"URL_LONG_ENCODED_PATH"}},
		{name: "repeated path characters", input: "https://example.com/" + strings.Repeat("a", 40), wantCodes: []string{"URL_REPEATED_PATH_CHARACTERS"}},
		{name: "URL-like path prefix", input: "https://example.com/https://login.example.net/", wantCodes: []string{"URL_REPEATED_PATH_SEPARATORS", "URL_SCHEME_LIKE_PATH", "PHISHING_KEYWORD"}},
		{name: "IPv4 destination", input: "https://192.168.1.1/login", wantCodes: []string{"URL_IP_LITERAL", "PHISHING_KEYWORD"}},
		{name: "IPv6 destination", input: "https://[2001:db8::1]/login", wantCodes: []string{"URL_IP_LITERAL", "PHISHING_KEYWORD"}},
		{name: "empty path normalized", input: "https://example.com"},
		{name: "query terms ignored", input: "https://example.com/?next=https%3A%2F%2Fevil.example%2F%40paypal.com"},
		{name: "moderate encoded path", input: "https://example.com/%2Faccount%2Flogin", wantCodes: []string{"PHISHING_KEYWORD"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, classification := normalizedAndClassified(t, tt.input)
			got, err := AnalyzePatterns(u, classification)
			if err != nil {
				t.Fatalf("AnalyzePatterns() error = %v", err)
			}
			codes := make([]string, len(got))
			seen := make(map[string]bool, len(got))
			for i, finding := range got {
				codes[i] = finding.Code
				if finding.Code == "" || finding.Title == "" || finding.Description == "" || finding.Category == "" || finding.Evidence == "" {
					t.Errorf("finding has empty required field: %+v", finding)
				}
				if seen[finding.Code] {
					t.Errorf("duplicate finding code %q", finding.Code)
				}
				seen[finding.Code] = true
			}
			if !slices.Equal(codes, tt.wantCodes) {
				t.Fatalf("finding codes = %v, want %v", codes, tt.wantCodes)
			}
			for _, finding := range got {
				for _, secret := range []string{"secret-password", "private", "alice", "token"} {
					if strings.Contains(finding.Evidence, secret) {
						t.Errorf("finding evidence exposed %q: %+v", secret, finding)
					}
				}
			}
			again, err := AnalyzePatterns(u, classification)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatalf("results are not deterministic: first=%+v second=%+v err=%v", got, again, err)
			}
		})
	}
}

func TestAnalyzePatternsRejectsNilInputs(t *testing.T) {
	classification := &Classification{}
	if _, err := AnalyzePatterns(nil, classification); err == nil {
		t.Fatal("AnalyzePatterns(nil, classification) error = nil")
	}
	if _, err := AnalyzePatterns(&NormalizedURL{Hostname: "example.com"}, nil); err == nil {
		t.Fatal("AnalyzePatterns(url, nil) error = nil")
	}
	if _, err := AnalyzePatterns(&NormalizedURL{}, classification); err == nil {
		t.Fatal("AnalyzePatterns(empty hostname) error = nil")
	}
}

func TestAnalyzePatternsIncludesBrandSignals(t *testing.T) {
	u, classification := normalizedAndClassified(t, "https://paypa1.com/login")
	findings, err := AnalyzePatterns(u, classification)
	if err != nil {
		t.Fatalf("AnalyzePatterns() error = %v", err)
	}
	for _, finding := range findings {
		if finding.Code == "BRAND_CHARACTER_SUBSTITUTION" {
			return
		}
	}
	t.Fatalf("AnalyzePatterns() did not include brand match: %+v", findings)
}

func TestAnalyzePatternsIncludesTaskFiveSignalsInOrder(t *testing.T) {
	u, classification := normalizedAndClassified(t, "https://verify.bit.ly/login?wallet=private#account")
	findings, err := AnalyzePatterns(u, classification)
	if err != nil {
		t.Fatal(err)
	}
	codes := make([]string, 0, len(findings))
	for _, result := range findings {
		codes = append(codes, result.Code)
	}
	want := []string{"URL_SHORTENER", "PHISHING_KEYWORD"}
	if !slices.Equal(codes, want) {
		t.Fatalf("finding codes = %v, want %v", codes, want)
	}
	for _, result := range findings {
		if strings.Contains(result.Evidence, "private") || strings.Contains(result.Evidence, "wallet") {
			t.Errorf("finding evidence exposed query contents: %+v", result)
		}
	}
}

func TestPatternThresholds(t *testing.T) {
	tests := []struct {
		name  string
		input string
		code  string
	}{
		{name: "hostname at length limit", input: "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 32) + ".com/", code: "URL_LONG_HOSTNAME"},
		{name: "path at limit", input: "https://example.com/" + strings.Repeat("a", maxPathLength-1), code: "URL_LONG_PATH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, classification := normalizedAndClassified(t, tt.input)
			findings, err := AnalyzePatterns(u, classification)
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range findings {
				if finding.Code == tt.code {
					t.Fatalf("unexpected threshold finding: %+v", finding)
				}
			}
		})
	}
}

func normalizedAndClassified(t *testing.T, input string) (*NormalizedURL, *Classification) {
	t.Helper()
	u, err := NormalizeURL(input)
	if err != nil {
		t.Fatalf("NormalizeURL(%q): %v", input, err)
	}
	classification, err := ClassifyURL(u)
	if err != nil {
		t.Fatalf("ClassifyURL(%q): %v", input, err)
	}
	return u, classification
}

func FuzzAnalyzePatterns(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/",
		"https://google.com@evil.example/login?token=secret",
		"https://login.account.verify.example.com/",
		"https://192.168.1.1/login",
		"https://example.com/a/b/c/d/e/f/g/h/i/j",
		"https://example.com/https://login.example.net/",
		"not a URL",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		u, err := NormalizeURL(input)
		if err != nil {
			return
		}
		classification, err := ClassifyURL(u)
		if err != nil {
			t.Fatalf("ClassifyURL() failed for normalized URL: %v", err)
		}
		findings, err := AnalyzePatterns(u, classification)
		if err != nil {
			t.Fatalf("AnalyzePatterns() failed for normalized URL: %v", err)
		}
		seen := make(map[string]bool, len(findings))
		for _, finding := range findings {
			if finding.Code == "" || seen[finding.Code] {
				t.Fatalf("invalid or duplicate code in findings: %+v", findings)
			}
			seen[finding.Code] = true
		}
	})
}
