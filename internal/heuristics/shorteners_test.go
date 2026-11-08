package heuristics

import "testing"

func TestDetectShortener(t *testing.T) {
	for _, tt := range []struct {
		url  string
		want bool
	}{
		{"https://bit.ly/abc", true}, {"https://sub.tinyurl.com/x", true},
		{"https://bit.ly.attacker.example/x", false}, {"https://example.com/bit.ly", false},
		{"https://BIT.LY/a", true}, {"https://192.0.2.1/", false},
	} {
		u, err := NormalizeURL(tt.url)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ClassifyURL(u)
		if err != nil {
			t.Fatal(err)
		}
		got, err := detectShortener(u, c)
		if err != nil {
			t.Fatalf("%s: %v", tt.url, err)
		}
		if (got != nil) != tt.want {
			t.Errorf("%s: got finding %v, want finding=%v", tt.url, got, tt.want)
		}
		if got != nil && got.Code != "URL_SHORTENER" {
			t.Errorf("code = %q", got.Code)
		}
	}
}
