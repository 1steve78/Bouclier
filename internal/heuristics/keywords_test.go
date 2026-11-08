package heuristics

import (
	"strings"
	"testing"
)

func TestDetectPhishingKeywords(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		want      bool
	}{
		{"host token", "https://login.example.com/", true},
		{"path token", "https://example.com/account/verify", true},
		{"mixed case", "https://example.com/LoGiN", true},
		{"substring is not a token", "https://example.com/loginpage", false},
		{"query ignored", "https://example.com/?next=login&token=secret", false},
		{"fragment ignored", "https://example.com/#/account", false},
		{"ordinary URL", "https://example.com/about", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, err := NormalizeURL(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := detectPhishingKeywords(u)
			if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != tt.want {
				t.Fatalf("got %v, want finding=%v", got, tt.want)
			}
			if got != nil && got.Code != "PHISHING_KEYWORD" {
				t.Fatalf("code = %q", got.Code)
			}
		})
	}
}

func TestDetectPhishingKeywordsDeduplicates(t *testing.T) {
	u, err := NormalizeURL("https://login.example.com/login?next=login")
	if err != nil {
		t.Fatal(err)
	}
	f, err := detectPhishingKeywords(u)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil || strings.Count(f.Evidence, "login (") != 1 {
		t.Fatalf("unexpected evidence: %#v", f)
	}
}

func FuzzKeywordTokens(f *testing.F) {
	for _, seed := range []string{"login", "login-page", "%2Fverify", "wallet123", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := NormalizeURL("https://example.com/" + raw)
		if err != nil {
			return
		}
		_, _ = detectPhishingKeywords(u)
	})
}
