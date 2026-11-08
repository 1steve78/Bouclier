package heuristics

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAnalyzeURLValidInputs(t *testing.T) {
	inputs := []string{
		"https://example.com/",
		"http://example.com/",
		"http://192.0.2.1/",
		"https://[2001:db8::1]/",
		"https://bücher.example/",
		"https://xn--bcher-kva.example/",
		"https://example.com/path?token=secret#private",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result, err := AnalyzeURL(input)
			if err != nil {
				t.Fatalf("AnalyzeURL() error = %v", err)
			}
			if result == nil || result.NormalizedURL == nil || result.Classification == nil {
				t.Fatalf("incomplete analysis result: %#v", result)
			}
			if strings.Contains(result.OriginalURL, "?") || strings.Contains(result.OriginalURL, "#") || strings.Contains(result.OriginalURL, "secret") {
				t.Errorf("sanitized URL exposed sensitive input: %q", result.OriginalURL)
			}
			if result.NormalizedURL.Query != "" || result.NormalizedURL.Fragment != "" {
				t.Errorf("normalized result retained query or fragment: %+v", result.NormalizedURL)
			}
		})
	}
}

func TestAnalyzeURLInvalidInputs(t *testing.T) {
	inputs := []string{
		"", "example.com", "ftp://example.com/", "https://[bad/", "https://-invalid.example/", "https://xn--.example/",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result, err := AnalyzeURL(input)
			if err == nil || result != nil {
				t.Fatalf("AnalyzeURL(%q) = (%#v, %v), want error and nil result", input, result, err)
			}
		})
	}
}

func TestAnalyzeURLIntegratedSignals(t *testing.T) {
	tests := []struct {
		input string
		codes []string
	}{
		{"https://192.0.2.1/", []string{"URL_IP_LITERAL"}},
		{"https://paypa1.example/", []string{"BRAND_CHARACTER_SUBSTITUTION"}},
		{"https://news.example.xyz/", []string{"SUSPICIOUS_TLD"}},
		{"https://bit.ly/abc", []string{"URL_SHORTENER"}},
		{"https://example.com/login", []string{"PHISHING_KEYWORD"}},
		{"https://paypa1.xyz/login/verify?token=secret", []string{"BRAND_CHARACTER_SUBSTITUTION", "PHISHING_KEYWORD", "SUSPICIOUS_TLD"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := AnalyzeURL(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			codes := make([]string, 0, len(result.Findings))
			seen := make(map[string]bool)
			for _, finding := range result.Findings {
				codes = append(codes, finding.Code)
				if seen[finding.Code] {
					t.Errorf("duplicate finding code %q", finding.Code)
				}
				seen[finding.Code] = true
			}
			if !slices.Equal(codes, tt.codes) {
				t.Fatalf("finding codes = %v, want %v", codes, tt.codes)
			}
		})
	}
}

func TestAnalyzeURLDeterminismAndRedaction(t *testing.T) {
	input := "https://alice:super-secret@paypa1.xyz/login?token=query-secret#fragment-secret"
	first, err := AnalyzeURL(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeURL(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("results differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	serialized := first.OriginalURL + first.NormalizedURL.Original + first.NormalizedURL.Normalized + first.NormalizedURL.Query + first.NormalizedURL.Fragment
	for _, secret := range []string{"alice", "super-secret", "query-secret", "fragment-secret", "token="} {
		if strings.Contains(serialized, secret) {
			t.Errorf("analysis result exposed %q: %+v", secret, first)
		}
	}
	for i := 1; i < len(first.Findings); i++ {
		if first.Findings[i-1].Code > first.Findings[i].Code {
			t.Fatalf("findings are not code-sorted: %+v", first.Findings)
		}
	}
}

func FuzzAnalyzeURL(f *testing.F) {
	for _, seed := range []string{"https://example.com/", "https://paypa1.xyz/login?token=secret", "ftp://example.com", "https://bücher.example/", "not a URL"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		result, err := AnalyzeURL(raw)
		if err != nil {
			if result != nil {
				t.Fatalf("error returned with partial result: %#v", result)
			}
			return
		}
		if result == nil || result.NormalizedURL == nil || result.Classification == nil {
			t.Fatalf("success returned incomplete result: %#v", result)
		}
		for i := 1; i < len(result.Findings); i++ {
			if result.Findings[i-1].Code > result.Findings[i].Code {
				t.Fatalf("findings are not ordered: %+v", result.Findings)
			}
		}
	})
}
