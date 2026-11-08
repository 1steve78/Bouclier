package heuristics

import (
	"reflect"
	"testing"
)

func TestExtractDomainInfo(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		registrable   string
		suffix        string
		subdomain     string
		subdomainTags []string
		domainTags    []string
		depth         int
	}{
		{name: "simple", input: "https://example.com/", registrable: "example.com", suffix: "com", domainTags: []string{"example", "com"}, depth: 2},
		{name: "single subdomain", input: "https://www.example.com/", registrable: "example.com", suffix: "com", subdomain: "www", subdomainTags: []string{"www"}, domainTags: []string{"example", "com"}, depth: 3},
		{name: "nested subdomains", input: "https://login.secure.example.co.uk/", registrable: "example.co.uk", suffix: "co.uk", subdomain: "login.secure", subdomainTags: []string{"login", "secure"}, domainTags: []string{"example", "co", "uk"}, depth: 5},
		{name: "co.uk", input: "https://example.co.uk/", registrable: "example.co.uk", suffix: "co.uk", domainTags: []string{"example", "co", "uk"}, depth: 3},
		{name: "com.au", input: "https://example.com.au/", registrable: "example.com.au", suffix: "com.au", domainTags: []string{"example", "com", "au"}, depth: 3},
		{name: "co.in", input: "https://example.co.in/", registrable: "example.co.in", suffix: "co.in", domainTags: []string{"example", "co", "in"}, depth: 3},
		{name: "Unicode", input: "https://bücher.example/", registrable: "xn--bcher-kva.example", suffix: "example", domainTags: []string{"xn--bcher-kva", "example"}, depth: 2},
		{name: "Punycode", input: "https://xn--bcher-kva.example/", registrable: "xn--bcher-kva.example", suffix: "example", domainTags: []string{"xn--bcher-kva", "example"}, depth: 2},
		{name: "trailing dot", input: "https://www.example.com./", registrable: "example.com", suffix: "com", subdomain: "www", subdomainTags: []string{"www"}, domainTags: []string{"example", "com"}, depth: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := NormalizeURL(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ExtractDomainInfo(u)
			if err != nil {
				t.Fatal(err)
			}
			if got.RegistrableDomain != tt.registrable || got.PublicSuffix != tt.suffix || got.Subdomain != tt.subdomain || got.DomainDepth != tt.depth {
				t.Fatalf("domain info = %+v", got)
			}
			if !reflect.DeepEqual(got.SubdomainLabels, tt.subdomainTags) || !reflect.DeepEqual(got.DomainLabels, tt.domainTags) {
				t.Errorf("labels = subdomain %v domain %v; want %v and %v", got.SubdomainLabels, got.DomainLabels, tt.subdomainTags, tt.domainTags)
			}
			if got.Hostname != u.Hostname {
				t.Errorf("canonical hostname = %q, want %q", got.Hostname, u.Hostname)
			}
			if got.OriginalHostname != u.OriginalHostname {
				t.Errorf("original hostname = %q, want %q", got.OriginalHostname, u.OriginalHostname)
			}
		})
	}
}

func TestExtractDomainInfoIPAddresses(t *testing.T) {
	for _, input := range []string{"https://192.0.2.1/", "https://[2001:db8::1]/"} {
		t.Run(input, func(t *testing.T) {
			u, err := NormalizeURL(input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ExtractDomainInfo(u)
			if err != nil {
				t.Fatal(err)
			}
			if !got.IsIPAddress || got.Hostname != u.Hostname || got.DomainDepth != 0 || got.PublicSuffix != "" || got.RegistrableDomain != "" {
				t.Fatalf("IP domain info = %+v", got)
			}
		})
	}
}

func TestExtractDomainInfoPublicSuffixOnly(t *testing.T) {
	u, err := NormalizeURL("https://com/")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ExtractDomainInfo(u)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicSuffix != "com" || got.RegistrableDomain != "" || len(got.DomainLabels) != 0 || got.DomainDepth != 1 {
		t.Fatalf("suffix-only info = %+v", got)
	}
}

func TestExtractDomainInfoCanonicalIDNEquivalence(t *testing.T) {
	unicodeURL, err := NormalizeURL("https://bücher.example/")
	if err != nil {
		t.Fatal(err)
	}
	punycodeURL, err := NormalizeURL("https://xn--bcher-kva.example/")
	if err != nil {
		t.Fatal(err)
	}
	unicodeInfo, err := ExtractDomainInfo(unicodeURL)
	if err != nil {
		t.Fatal(err)
	}
	punycodeInfo, err := ExtractDomainInfo(punycodeURL)
	if err != nil {
		t.Fatal(err)
	}
	if unicodeInfo.Hostname != punycodeInfo.Hostname || unicodeInfo.RegistrableDomain != punycodeInfo.RegistrableDomain || unicodeInfo.PublicSuffix != punycodeInfo.PublicSuffix || unicodeInfo.Subdomain != punycodeInfo.Subdomain || unicodeInfo.DomainDepth != punycodeInfo.DomainDepth {
		t.Fatalf("Unicode and Punycode structures differ: %+v versus %+v", unicodeInfo, punycodeInfo)
	}
	if unicodeInfo.OriginalHostname == punycodeInfo.OriginalHostname {
		t.Fatal("original submitted hostnames should retain their distinction")
	}
}

func TestExtractDomainInfoRejectsInvalidInputs(t *testing.T) {
	if _, err := ExtractDomainInfo(nil); err == nil {
		t.Fatal("nil URL must fail")
	}
	for _, u := range []*NormalizedURL{
		{},
		{Hostname: "bad..example"},
		{Hostname: "xn--.example"},
		{Hostname: "192.0.2.999"},
		{Hostname: "not-an-ip", IsIPAddress: true},
	} {
		if _, err := ExtractDomainInfo(u); err == nil {
			t.Errorf("ExtractDomainInfo(%+v) succeeded; want error", u)
		}
	}
}
