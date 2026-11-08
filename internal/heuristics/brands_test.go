package heuristics

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "www.example.com", want: "example.com"},
		{host: "example.co.uk", want: "example.co.uk"},
		{host: "www.example.com.au", want: "example.com.au"},
		{host: "example.co.in", want: "example.co.in"},
		{host: "login.example.org.uk", want: "example.org.uk"},
		{host: "bücher.example", want: "xn--bcher-kva.example"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, err := RegistrableDomain(tt.host)
			if err != nil {
				t.Fatalf("RegistrableDomain() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("RegistrableDomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRegistrableDomainInvalid(t *testing.T) {
	for _, host := range []string{"", "127.0.0.1", "::1", "localhost", "bad..example", "xn--.example", " example.com "} {
		t.Run(host, func(t *testing.T) {
			if got, err := RegistrableDomain(host); err == nil {
				t.Fatalf("RegistrableDomain(%q) = %q, want error", host, got)
			}
		})
	}
}

func TestAnalyzeBrandImpersonation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCodes []string
	}{
		{name: "Google canonical is legitimate", input: "https://google.com/"},
		{name: "Google subdomain is legitimate", input: "https://accounts.google.com/login"},
		{name: "Google alias is legitimate", input: "https://mail.googlemail.com/"},
		{name: "Amazon multi-label alias is legitimate", input: "https://amazon.co.uk/"},
		{name: "misleading subdomain", input: "https://paypal.evil.example/", wantCodes: []string{"BRAND_MISLEADING_SUBDOMAIN"}},
		{name: "one character substitution", input: "https://paypa1.example/", wantCodes: []string{"BRAND_CHARACTER_SUBSTITUTION"}},
		{name: "ASCII confusable substitution", input: "https://g00gle.example/", wantCodes: []string{"BRAND_CHARACTER_SUBSTITUTION"}},
		{name: "edit distance", input: "https://gogle.example/", wantCodes: []string{"BRAND_SIMILAR_DOMAIN"}},
		{name: "transposition", input: "https://googel.example/", wantCodes: []string{"BRAND_SIMILAR_DOMAIN"}},
		{name: "exact brand token embedded with separators", input: "https://secure-paypal-login.example/", wantCodes: []string{"BRAND_EXACT_LABEL"}},
		{name: "notpaypal is not exact brand label", input: "https://notpaypal.example/"},
		{name: "unrelated domain", input: "https://example.org/"},
		{name: "IPv4 literal", input: "https://192.168.1.1/login"},
		{name: "IPv6 literal", input: "https://[2001:db8::1]/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := NormalizeURL(tt.input)
			if err != nil {
				t.Fatalf("NormalizeURL() error = %v", err)
			}
			got, err := AnalyzeBrandImpersonation(u)
			if err != nil {
				t.Fatalf("AnalyzeBrandImpersonation() error = %v", err)
			}
			codes := make([]string, len(got))
			for i, finding := range got {
				codes[i] = finding.Code
				if finding.Title == "" || finding.Description == "" || finding.Category != "brand-impersonation" || finding.Evidence == "" {
					t.Errorf("finding fields incomplete: %+v", finding)
				}
			}
			if !slices.Equal(codes, tt.wantCodes) {
				t.Fatalf("finding codes = %v, want %v", codes, tt.wantCodes)
			}
			again, err := AnalyzeBrandImpersonation(u)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatalf("results not deterministic: first=%+v second=%+v err=%v", got, again, err)
			}
		})
	}
}

func TestUnicodeAndPunycodeBrandComparison(t *testing.T) {
	unicodeURL, err := NormalizeURL("https://gοogle.example/login?token=secret")
	if err != nil {
		t.Fatalf("NormalizeURL(Unicode) error = %v", err)
	}
	punycodeURL, err := NormalizeURL("https://" + unicodeURL.Hostname + "/login?token=secret")
	if err != nil {
		t.Fatalf("NormalizeURL(Punycode) error = %v", err)
	}
	if unicodeURL.Hostname != punycodeURL.Hostname {
		t.Fatalf("ASCII hostnames differ: %q != %q", unicodeURL.Hostname, punycodeURL.Hostname)
	}
	if unicodeURL.OriginalHostname == punycodeURL.OriginalHostname {
		t.Fatalf("original hostnames were not preserved distinctly: %q", unicodeURL.OriginalHostname)
	}
	findings, err := AnalyzeBrandImpersonation(unicodeURL)
	if err != nil {
		t.Fatalf("AnalyzeBrandImpersonation(Unicode) error = %v", err)
	}
	if len(findings) != 1 || findings[0].Code != "BRAND_IDN_SIMILAR_DOMAIN" {
		t.Fatalf("Unicode findings = %+v, want one IDN finding", findings)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Evidence, "secret") || strings.Contains(finding.Evidence, "token=") {
			t.Fatalf("finding exposed query data: %+v", finding)
		}
	}
	punycodeFindings, err := AnalyzeBrandImpersonation(punycodeURL)
	if err != nil || !reflect.DeepEqual(findings, punycodeFindings) {
		t.Fatalf("Unicode and Punycode findings differ: unicode=%+v punycode=%+v err=%v", findings, punycodeFindings, err)
	}
}

func TestKnownBrandsReturnsDefensiveCopy(t *testing.T) {
	brands := KnownBrands()
	if len(brands) != 15 {
		t.Fatalf("KnownBrands() returned %d entries, want 15", len(brands))
	}
	brands[0].Name = "modified"
	if len(brands[0].Aliases) > 0 {
		brands[0].Aliases[0] = "modified.invalid"
	}
	for _, brand := range KnownBrands() {
		if brand.Name == "modified" {
			t.Fatal("KnownBrands() exposed mutable registry entry")
		}
		for _, alias := range brand.Aliases {
			if alias == "modified.invalid" {
				t.Fatal("KnownBrands() exposed mutable alias slice")
			}
		}
	}
}

func TestBrandRegistryDomainsAreNormalized(t *testing.T) {
	for _, brand := range KnownBrands() {
		if brand.Name == "" || brand.Category == "" || brand.Domain == "" {
			t.Fatalf("incomplete brand metadata: %+v", brand)
		}
		for _, domain := range append([]string{brand.Domain}, brand.Aliases...) {
			u, err := NormalizeURL("https://" + domain + "/")
			if err != nil || u.Hostname != domain {
				t.Errorf("brand %s domain %q failed normalization: url=%+v err=%v", brand.Name, domain, u, err)
			}
		}
	}
}

func FuzzAnalyzeBrandImpersonation(f *testing.F) {
	for _, input := range []string{
		"https://google.com/",
		"https://paypa1.com/login?token=secret",
		"https://g00gle.com/",
		"https://paypal.evil.example/",
		"https://bücher.example/",
		"https://gοogle.example/",
		"https://192.168.1.1/",
		"not a URL",
	} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		u, err := NormalizeURL(input)
		if err != nil {
			return
		}
		findings, err := AnalyzeBrandImpersonation(u)
		if err != nil {
			t.Fatalf("AnalyzeBrandImpersonation() error for normalized URL: %v", err)
		}
		for _, finding := range findings {
			if finding.Code == "" || finding.Title == "" || finding.Description == "" || finding.Evidence == "" {
				t.Fatalf("incomplete finding: %+v", finding)
			}
			if strings.Contains(finding.Evidence, "secret") || strings.Contains(finding.Evidence, "token=") {
				t.Fatalf("query data leaked into evidence: %+v", finding)
			}
		}
	})
}
