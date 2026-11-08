package heuristics

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAnalyzeDomainBrandRelationships(t *testing.T) {
	tests := []struct {
		name string
		host string
		want []string
	}{
		{name: "Google official subdomain", host: "accounts.google.com"},
		{name: "Microsoft official subdomain", host: "login.microsoft.com"},
		{name: "Apple official subdomain", host: "support.apple.com"},
		{name: "known alias", host: "mail.googlemail.com"},
		{name: "misleading brand label in subdomain", host: "google.com.attacker.example", want: []string{"BRAND_MISLEADING_SUBDOMAIN"}},
		{name: "brand label directly in subdomain", host: "paypal.evil.example", want: []string{"BRAND_MISLEADING_SUBDOMAIN"}},
		{name: "PayPal substitution", host: "paypa1.example", want: []string{"BRAND_SIMILAR_REGISTRABLE_DOMAIN"}},
		{name: "Google substitution", host: "g00gle.example", want: []string{"BRAND_SIMILAR_REGISTRABLE_DOMAIN"}},
		{name: "Microsoft substitution", host: "micros0ft.example", want: []string{"BRAND_SIMILAR_REGISTRABLE_DOMAIN"}},
		{name: "edit distance", host: "gogle.example", want: []string{"BRAND_SIMILAR_REGISTRABLE_DOMAIN"}},
		{name: "exact brand component", host: "google-login.example", want: []string{"BRAND_IN_DOMAIN_LABEL"}},
		{name: "exact brand component on multi-label suffix", host: "google-login.co.uk", want: []string{"BRAND_IN_DOMAIN_LABEL"}},
		{name: "PayPal typo on multi-label suffix", host: "paypa1.co.uk", want: []string{"BRAND_SIMILAR_REGISTRABLE_DOMAIN"}},
		{name: "notpaypal is not exact", host: "notpaypal.example"},
		{name: "common terms are not brand names", host: "secure-login.example"},
		{name: "unrelated domain", host: "example.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AnalyzeDomainBrandRelationships(domainBrandInfoForHost(t, tt.host))
			if err != nil {
				t.Fatal(err)
			}
			codes := make([]string, len(got))
			for i, result := range got {
				codes[i] = result.Code
				if result.Title == "" || result.Description == "" || result.Category != "brand-impersonation" || result.Evidence == "" {
					t.Errorf("incomplete finding: %+v", result)
				}
				if strings.Contains(result.Evidence, tt.host) || strings.Contains(result.Evidence, "token=") {
					t.Errorf("finding contains raw host or query detail: %+v", result)
				}
			}
			if !slices.Equal(codes, tt.want) {
				t.Fatalf("finding codes = %v, want %v", codes, tt.want)
			}
		})
	}
}

func TestAnalyzeDomainBrandRelationshipsIgnoresURLPathAndQuery(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/google-login",
		"https://example.com/?next=paypal.com&token=private",
		"https://example.com/#google.com",
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
			findings, err := AnalyzeDomainBrandRelationships(info)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 0 {
				t.Fatalf("path/query/fragment brand text affected result: %+v", findings)
			}
		})
	}
}

func TestAnalyzeDomainBrandRelationshipsIDNAndPunycode(t *testing.T) {
	unicodeURL, err := NormalizeURL("https://gοogle.example/?token=private")
	if err != nil {
		t.Fatal(err)
	}
	punycodeURL, err := NormalizeURL("https://" + unicodeURL.Hostname + "/")
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
	unicodeFindings, err := AnalyzeDomainBrandRelationships(unicodeInfo)
	if err != nil {
		t.Fatal(err)
	}
	punycodeFindings, err := AnalyzeDomainBrandRelationships(punycodeInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(unicodeFindings, punycodeFindings) {
		t.Fatalf("Unicode and Punycode findings differ: %v != %v", unicodeFindings, punycodeFindings)
	}
	if len(unicodeFindings) != 1 || unicodeFindings[0].Code != "BRAND_IDN_SIMILAR_DOMAIN" {
		t.Fatalf("findings = %+v, want limited IDN signal", unicodeFindings)
	}
	if strings.Contains(unicodeFindings[0].Evidence, "private") || strings.Contains(unicodeFindings[0].Evidence, "token=") {
		t.Fatalf("finding exposed query data: %+v", unicodeFindings)
	}
}

func TestAnalyzeDomainBrandRelationshipsRejectsInvalidInfo(t *testing.T) {
	if _, err := AnalyzeDomainBrandRelationships(nil); err == nil {
		t.Fatal("nil DomainInfo must fail")
	}
	for _, info := range []*DomainInfo{
		{},
		{Hostname: "bad..example"},
		{Hostname: "example.com", RegistrableDomain: "attacker.com", PublicSuffix: "com", DomainLabels: []string{"attacker", "com"}, DomainDepth: 2},
		{Hostname: "192.0.2.1"},
		{Hostname: "wrong", IsIPAddress: true},
	} {
		if _, err := AnalyzeDomainBrandRelationships(info); err == nil {
			t.Errorf("AnalyzeDomainBrandRelationships(%+v) succeeded; want error", info)
		}
	}
}

func TestAnalyzeDomainBrandRelationshipsIPAndPublicSuffixOnly(t *testing.T) {
	for _, raw := range []string{"https://192.0.2.1/", "https://[2001:db8::1]/", "https://com/"} {
		t.Run(raw, func(t *testing.T) {
			u, err := NormalizeURL(raw)
			if err != nil {
				t.Fatal(err)
			}
			info, err := ExtractDomainInfo(u)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := AnalyzeDomainBrandRelationships(info)
			if err != nil || len(findings) != 0 {
				t.Fatalf("findings = %+v, err = %v; want no findings", findings, err)
			}
		})
	}
}

func TestAnalyzeDomainBrandRelationshipsDeterminism(t *testing.T) {
	info := domainBrandInfoForHost(t, "google.com.attacker.example")
	first, err := AnalyzeDomainBrandRelationships(info)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeDomainBrandRelationships(info)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated results differ: %+v vs %+v", first, second)
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Code > first[i].Code {
			t.Fatalf("findings are not sorted: %+v", first)
		}
	}
}

func FuzzAnalyzeDomainBrandRelationships(f *testing.F) {
	for _, host := range []string{"google.com", "google.com.attacker.example", "paypa1.example", "google-login.co.uk", "notpaypal.example"} {
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
		findings, err := AnalyzeDomainBrandRelationships(info)
		if err != nil {
			t.Fatalf("analysis failed on extracted domain info: %v", err)
		}
		seen := make(map[string]bool)
		for _, result := range findings {
			if result.Code == "" || seen[result.Code] {
				t.Fatalf("empty or duplicate finding code: %+v", findings)
			}
			seen[result.Code] = true
		}
	})
}

func domainBrandInfoForHost(t *testing.T, host string) *DomainInfo {
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
