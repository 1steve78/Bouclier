package domain

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/registration"
)

func TestAnalyzeDomainExtractionCases(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/",
		"https://login.secure.example.co.uk/",
		"https://bücher.example/",
		"https://xn--bcher-kva.example/",
		"https://192.0.2.1/",
		"https://[2001:db8::1]/",
	} {
		t.Run(raw, func(t *testing.T) {
			u, err := heuristics.NormalizeURL(raw)
			if err != nil {
				t.Fatal(err)
			}
			info, err := heuristics.ExtractDomainInfo(u)
			if err != nil {
				t.Fatal(err)
			}
			result, err := AnalyzeDomain(info)
			if err != nil {
				t.Fatal(err)
			}
			if result.DomainInfo != info {
				t.Fatal("analysis did not preserve supplied DomainInfo")
			}
			if result.Findings == nil {
				t.Fatal("Findings should be an initialized empty or populated slice")
			}
		})
	}
}

func TestAnalyzeDomainCombinedFindings(t *testing.T) {
	info := domainInfo(t, "https://google.com.attacker.evil.example/")
	result, err := AnalyzeDomain(info)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"BRAND_MISLEADING_SUBDOMAIN", "EXCESSIVE_SUBDOMAIN_DEPTH"}
	if codes := findingCodes(result.Findings); !slices.Equal(codes, want) {
		t.Fatalf("finding codes = %v, want %v", codes, want)
	}
}

func TestAnalyzeDomainLegitimateBrandAndTypo(t *testing.T) {
	for _, tt := range []struct {
		url  string
		code string
	}{
		{url: "https://accounts.google.com/"},
		{url: "https://login.microsoft.com/"},
		{url: "https://support.apple.com/"},
		{url: "https://paypa1.co.uk/", code: "BRAND_SIMILAR_REGISTRABLE_DOMAIN"},
	} {
		t.Run(tt.url, func(t *testing.T) {
			result, err := AnalyzeDomain(domainInfo(t, tt.url))
			if err != nil {
				t.Fatal(err)
			}
			if tt.code == "" {
				for _, finding := range result.Findings {
					if finding.Category == "brand-impersonation" {
						t.Fatalf("legitimate brand domain was flagged: %+v", result.Findings)
					}
				}
				return
			}
			for _, finding := range result.Findings {
				if finding.Code == tt.code {
					return
				}
			}
			t.Fatalf("expected %q in %+v", tt.code, result.Findings)
		})
	}
}

func TestAnalyzeDomainDeterminismAndDuplicateSuppression(t *testing.T) {
	info := domainInfo(t, "https://google.com.attacker.evil.example/")
	first, err := AnalyzeDomain(info)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeDomain(info)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("results differ: %+v and %+v", first, second)
	}
	duplicates := mergeFindings(
		[]heuristics.Finding{
			{Code: "A", Evidence: "same evidence", Title: "first"},
			{Code: "A", Evidence: "other", Title: "duplicate code"},
		},
		[]heuristics.Finding{
			{Code: "B", Evidence: " same evidence ", Title: "duplicate evidence"},
			{Code: "C", Evidence: "unique", Title: "kept"},
		},
	)
	if len(duplicates) != 2 || duplicates[0].Code != "A" || duplicates[1].Code != "C" {
		t.Fatalf("duplicate merge = %+v", duplicates)
	}
}

func TestAnalyzeDomainOptionalRegistrationAge(t *testing.T) {
	info := domainInfo(t, "https://example.com/")
	now := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	without, err := AnalyzeDomainWithRegistration(info, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if without.RegistrationAge != nil {
		t.Fatalf("unexpected registration analysis without data: %+v", without.RegistrationAge)
	}

	for _, tt := range []struct {
		name   string
		age    time.Duration
		redact bool
		status string
	}{
		{name: "very new", age: 2 * 24 * time.Hour, status: registration.AgeStatusVeryNew},
		{name: "established", age: 90 * 24 * time.Hour, status: registration.AgeStatusEstablished},
		{name: "missing creation date", status: registration.AgeStatusUnavailable},
		{name: "redacted creation date", redact: true, status: registration.AgeStatusRedacted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			regInfo := &registration.RegistrationInfo{IsRedacted: tt.redact}
			if tt.age != 0 {
				created := now.Add(-tt.age)
				regInfo.CreatedAt = &created
			}
			result, err := AnalyzeDomainWithRegistration(info, regInfo, now)
			if err != nil {
				t.Fatal(err)
			}
			if result.RegistrationAge == nil || result.RegistrationAge.Status != tt.status {
				t.Fatalf("registration age = %+v, want status %q", result.RegistrationAge, tt.status)
			}
			if !reflect.DeepEqual(result.Findings, without.Findings) {
				t.Fatalf("registration data altered hostname findings: %v vs %v", result.Findings, without.Findings)
			}
		})
	}
}

func TestAnalyzeDomainRegistrationFutureDateError(t *testing.T) {
	now := time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	result, err := AnalyzeDomainWithRegistration(domainInfo(t, "https://example.com/"), &registration.RegistrationInfo{CreatedAt: &future}, now)
	if err == nil || result != nil {
		t.Fatalf("future creation date returned result=%+v err=%v; want error and nil result", result, err)
	}
}

func TestAnalyzeDomainRejectsInvalidDomainInfo(t *testing.T) {
	for _, info := range []*heuristics.DomainInfo{nil, {}, {Hostname: "bad..example"}} {
		if _, err := AnalyzeDomain(info); err == nil {
			t.Errorf("AnalyzeDomain(%+v) succeeded; want error", info)
		}
	}
}

func domainInfo(t *testing.T, raw string) *heuristics.DomainInfo {
	t.Helper()
	u, err := heuristics.NormalizeURL(raw)
	if err != nil {
		t.Fatalf("NormalizeURL(%q): %v", raw, err)
	}
	info, err := heuristics.ExtractDomainInfo(u)
	if err != nil {
		t.Fatalf("ExtractDomainInfo(%q): %v", raw, err)
	}
	return info
}

func findingCodes(findings []heuristics.Finding) []string {
	codes := make([]string, len(findings))
	for i, finding := range findings {
		codes[i] = finding.Code
	}
	return codes
}
