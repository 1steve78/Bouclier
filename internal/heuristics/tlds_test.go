package heuristics

import "testing"

func TestPublicSuffixForHost(t *testing.T) {
	tests := []struct{ host, want string }{
		{"example.co.uk", "co.uk"},
		{"example.com.au", "com.au"},
		{"example.co.in", "co.in"},
		{"example.org.uk", "org.uk"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, err := publicSuffixForHost(tt.host)
			if err != nil || got != tt.want {
				t.Fatalf("publicSuffixForHost(%q) = %q, %v; want %q", tt.host, got, err, tt.want)
			}
		})
	}
}

func TestDetectSuspiciousTLD(t *testing.T) {
	for _, tt := range []struct {
		url  string
		want bool
	}{
		{"https://news.example.xyz/", true},
		{"https://example.com/", false},
		{"https://example.co.uk/", false},
		{"https://192.0.2.1/", false},
	} {
		u, err := NormalizeURL(tt.url)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ClassifyURL(u)
		if err != nil {
			t.Fatal(err)
		}
		got, err := detectSuspiciousTLD(u, c)
		if err != nil {
			t.Fatalf("%s: %v", tt.url, err)
		}
		if (got != nil) != tt.want {
			t.Errorf("%s: got finding %v, want finding=%v", tt.url, got, tt.want)
		}
		if got != nil && got.Code != "SUSPICIOUS_TLD" {
			t.Errorf("code = %q", got.Code)
		}
	}
}

func TestPublicSuffixForInvalidHost(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "bad..example.com", "localhost"} {
		if _, err := publicSuffixForHost(host); err == nil {
			t.Errorf("expected error for %q", host)
		}
	}
}
