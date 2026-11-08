package heuristics

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAnalyzeDomainStructureFindings(t *testing.T) {
	longHostname := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + ".d.example.com"
	longLabel := strings.Repeat("a", longStructuredLabelLength+1) + ".example.com"
	tests := []struct {
		name string
		host string
		want []string
	}{
		{name: "ordinary", host: "example.com"},
		{name: "one subdomain", host: "www.example.com"},
		{name: "two ordinary nested subdomains", host: "shop.eu.example.com"},
		{name: "two sensitive nested subdomains", host: "login.secure.example.com", want: []string{"SUSPICIOUS_SUBDOMAIN_COMBINATION"}},
		{name: "deep subdomains", host: "a.b.c.d.e.example.com", want: []string{"EXCESSIVE_SUBDOMAIN_DEPTH"}},
		{name: "long hostname", host: longHostname, want: []string{"EXCESSIVE_SUBDOMAIN_DEPTH", "LONG_DOMAIN_LABEL", "LONG_HOSTNAME"}},
		{name: "long label", host: longLabel, want: []string{"LONG_DOMAIN_LABEL"}},
		{name: "excessive hyphens", host: "foo-bar-baz-qux-quux.example.com", want: []string{"EXCESSIVE_HYPHENS"}},
		{name: "hyphen run", host: "foo---bar.example.com", want: []string{"EXCESSIVE_HYPHENS"}},
		{name: "numeric heavy", host: "a12345.example.com", want: []string{"NUMERIC_HEAVY_LABEL"}},
		{name: "sensitive subdomain combination", host: "login.verify.example.com", want: []string{"SUSPICIOUS_SUBDOMAIN_COMBINATION"}},
		{name: "hyphenated sensitive labels", host: "secure-account.example.com", want: []string{"SUSPICIOUS_SUBDOMAIN_COMBINATION"}},
		{name: "public suffix only", host: "com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := domainInfoForHost(t, tt.host)
			got, err := AnalyzeDomainStructure(info)
			if err != nil {
				t.Fatal(err)
			}
			codes := make([]string, len(got))
			for i, finding := range got {
				codes[i] = finding.Code
				if finding.Title == "" || finding.Description == "" || finding.Category != "domain-structure" || finding.Evidence == "" {
					t.Errorf("incomplete or unexpected finding: %+v", finding)
				}
				if strings.Contains(finding.Evidence, tt.host) {
					t.Errorf("evidence reproduced full hostname: %+v", finding)
				}
			}
			if !slices.Equal(codes, tt.want) {
				t.Fatalf("finding codes = %v, want %v", codes, tt.want)
			}
		})
	}
}

func TestAnalyzeDomainStructureFalsePositiveSafeguards(t *testing.T) {
	for _, host := range []string{
		"www.example.com",
		"mail.example.com",
		"my-company.example.com",
		"cdn2.example.com",
		"api-v2.example.com",
		"login.example.com",
	} {
		t.Run(host, func(t *testing.T) {
			got, err := AnalyzeDomainStructure(domainInfoForHost(t, host))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Fatalf("ordinary structural pattern produced findings: %+v", got)
			}
		})
	}
}

func TestAnalyzeDomainStructureIPAndIDN(t *testing.T) {
	for _, raw := range []string{
		"https://192.0.2.1/",
		"https://[2001:db8::1]/",
		"https://bücher.example/",
		"https://xn--bcher-kva.example/",
	} {
		t.Run(raw, func(t *testing.T) {
			u, err := NormalizeURL(raw)
			if err != nil {
				t.Fatal(err)
			}
			info, err := ExtractDomainInfo(u)
			if err != nil {
				t.Fatal(err)
			}
			got, err := AnalyzeDomainStructure(info)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Fatalf("benign IP/IDN structure produced findings: %+v", got)
			}
		})
	}
}

func TestAnalyzeDomainStructureRejectsInvalidInfo(t *testing.T) {
	if _, err := AnalyzeDomainStructure(nil); err == nil {
		t.Fatal("nil DomainInfo must fail")
	}
	for _, info := range []*DomainInfo{
		{},
		{Hostname: "bad..example"},
		{Hostname: "example.com", RegistrableDomain: "evil.com", PublicSuffix: "com", DomainLabels: []string{"evil", "com"}, DomainDepth: 2},
		{Hostname: "192.0.2.1"},
		{Hostname: "not-an-ip", IsIPAddress: true},
	} {
		if _, err := AnalyzeDomainStructure(info); err == nil {
			t.Errorf("AnalyzeDomainStructure(%+v) succeeded; want error", info)
		}
	}
}

func TestAnalyzeDomainStructureDeterminism(t *testing.T) {
	info := domainInfoForHost(t, "login.verify.a12345.foo-bar-baz-qux.example.com")
	first, err := AnalyzeDomainStructure(info)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeDomainStructure(info)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated calls differ: first=%+v second=%+v", first, second)
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Code > first[i].Code {
			t.Fatalf("findings are not sorted: %+v", first)
		}
	}
}

func FuzzAnalyzeDomainStructure(f *testing.F) {
	for _, host := range []string{"example.com", "login.verify.example.com", "cdn2.example.com", "a12345.example.com", "foo---bar.example.com"} {
		f.Add(host)
	}
	f.Fuzz(func(t *testing.T, host string) {
		u, err := NormalizeURL("https://" + host + "/")
		if err != nil {
			return
		}
		info, err := ExtractDomainInfo(u)
		if err != nil {
			return
		}
		findings, err := AnalyzeDomainStructure(info)
		if err != nil {
			t.Fatalf("analysis failed for extracted info: %v", err)
		}
		seen := make(map[string]bool)
		for _, finding := range findings {
			if finding.Code == "" || seen[finding.Code] {
				t.Fatalf("empty or duplicate code: %+v", findings)
			}
			seen[finding.Code] = true
		}
	})
}

func domainInfoForHost(t *testing.T, host string) *DomainInfo {
	t.Helper()
	u, err := NormalizeURL("https://" + host + "/")
	if err != nil {
		t.Fatalf("NormalizeURL(%q): %v", host, err)
	}
	info, err := ExtractDomainInfo(u)
	if err != nil {
		t.Fatalf("ExtractDomainInfo(%q): %v", host, err)
	}
	return info
}
