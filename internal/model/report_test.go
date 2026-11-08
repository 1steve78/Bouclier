package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

var fixtureNames = []string{
	"report_low_risk.json",
	"report_suspicious.json",
	"report_high_risk.json",
	"report_confirmed_malicious.json",
	"report_message.json",
	"report_edge_cases.json",
}

func TestGoldenHashFixtures(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "testdata", "fixtures")
	manifest, err := os.ReadFile(filepath.Join(fixturesDir, "expected_hashes.json"))
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}
	var expected map[string]string
	if err := json.Unmarshal(manifest, &expected); err != nil {
		t.Fatalf("parse fixture manifest: %v", err)
	}

	for _, name := range fixtureNames {
		t.Run(name, func(t *testing.T) {
			report := readReportFixture(t, name)
			if err := report.Validate(); err != nil {
				t.Fatalf("validate report: %v", err)
			}
			hash, err := HashReport(report)
			if err != nil {
				t.Fatalf("hash report: %v", err)
			}
			if hash != expected[name] {
				t.Fatalf("hash mismatch: got %s want %s", hash, expected[name])
			}
		})
	}
}

func TestValidateReportInvariants(t *testing.T) {
	report := readReportFixture(t, "report_suspicious.json")
	if err := report.Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}

	bad := report
	bad.ReportHash = "invalid"
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid hash accepted")
	}

	lowRisk := report
	lowRisk.RiskLevel = RiskLevelLowRisk
	lowRisk.Score = 10
	lowRisk.Findings = append([]Finding(nil), report.Findings...)
	lowRisk.Findings[0].Severity = SeverityHigh
	if err := lowRisk.Validate(); err == nil {
		t.Fatal("low_risk with high severity should fail")
	}
}

func TestCanonicalRejectsFloatValues(t *testing.T) {
	_, err := canonicalEncode(map[string]any{"number": 1.5})
	if err == nil {
		t.Fatal("float should be rejected")
	}
}

func TestHashOrderIndependence(t *testing.T) {
	report := readReportFixture(t, "report_high_risk.json")
	first, err := HashReport(report)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}
	report.Findings[0], report.Findings[1] = report.Findings[1], report.Findings[0]
	second, err := HashReport(report)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}
	if first != second {
		t.Fatalf("hashes differ after shuffling findings: %s vs %s", first, second)
	}
}

func TestHashIgnoresMetadataFields(t *testing.T) {
	report := readReportFixture(t, "report_low_risk.json")
	first, err := HashReport(report)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}

	report.AIExplanation = &AIExplanation{
		Provider:    "ollama",
		Model:       "llama3",
		Text:        "An explanation",
		GeneratedAt: "2025-01-14T22:00:00Z",
	}
	report.Chain = &Chain{Status: ChainStatusConfirmed, TxHash: "0xabc"}
	second, err := HashReport(report)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}
	if first != second {
		t.Fatalf("excluded metadata altered hash: %s vs %s", first, second)
	}
}

func TestDuplicateFindingIDsAreAllowedAndCanonicalized(t *testing.T) {
	report := readReportFixture(t, "report_suspicious.json")
	duplicate := report.Findings[0]
	duplicate.Title = "Another finding for the same rule"
	duplicate.Evidence = []Evidence{{Key: "other", Value: "evidence"}}
	report.Findings = append(report.Findings, duplicate)
	if err := report.Validate(); err != nil {
		t.Fatalf("duplicate rule IDs should be allowed: %v", err)
	}

	first, err := HashReport(report)
	if err != nil {
		t.Fatalf("hash report with duplicate rule IDs: %v", err)
	}
	report.Findings[0], report.Findings[1] = report.Findings[1], report.Findings[0]
	second, err := HashReport(report)
	if err != nil {
		t.Fatalf("hash reordered report with duplicate rule IDs: %v", err)
	}
	if first != second {
		t.Fatalf("duplicate-ID finding order changed the hash: %s vs %s", first, second)
	}
}

func TestReportTimestampsRequireExactUTCSeconds(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		valid     bool
	}{
		{name: "valid UTC seconds", timestamp: "2025-01-14T22:00:00Z", valid: true},
		{name: "fractional seconds", timestamp: "2025-01-14T22:00:00.000Z"},
		{name: "positive offset", timestamp: "2025-01-14T22:00:00+00:00"},
		{name: "negative offset", timestamp: "2025-01-14T22:00:00-05:00"},
		{name: "missing Z", timestamp: "2025-01-14T22:00:00"},
		{name: "invalid date", timestamp: "2025-02-30T22:00:00Z"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := readReportFixture(t, "report_low_risk.json")
			report.ScannedAt = test.timestamp
			err := report.Validate()
			if test.valid && err != nil {
				t.Fatalf("valid timestamp rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid timestamp accepted")
			}
		})
	}
}

func TestAIExplanationTimestampsRequireExactUTCSeconds(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		valid     bool
	}{
		{name: "valid UTC seconds", timestamp: "2025-01-14T22:00:00Z", valid: true},
		{name: "fractional seconds", timestamp: "2025-01-14T22:00:00.000Z"},
		{name: "positive offset", timestamp: "2025-01-14T22:00:00+00:00"},
		{name: "negative offset", timestamp: "2025-01-14T22:00:00-05:00"},
		{name: "missing Z", timestamp: "2025-01-14T22:00:00"},
		{name: "invalid date", timestamp: "2025-02-30T22:00:00Z"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := readReportFixture(t, "report_low_risk.json")
			report.AIExplanation = &AIExplanation{
				Provider:    "ollama",
				Model:       "test",
				Text:        "Explanation",
				GeneratedAt: test.timestamp,
			}
			err := report.Validate()
			if test.valid && err != nil {
				t.Fatalf("valid timestamp rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid timestamp accepted")
			}
		})
	}
}

func TestMessageTargetLocationFieldsAreOptional(t *testing.T) {
	report := readReportFixture(t, "report_message.json")
	report.Target.NormalizedURL = ""
	report.Target.Host = ""
	report.Target.RegistrableDomain = ""
	if err := report.Validate(); err != nil {
		t.Fatalf("message report with omitted URL location fields rejected: %v", err)
	}
	canonical, err := CanonicalJSON(report)
	if err != nil {
		t.Fatalf("canonicalize message report: %v", err)
	}
	if !bytes.Contains(canonical, []byte(`"input":""`)) {
		t.Fatalf("required empty target.input was omitted: %s", canonical)
	}
	for _, field := range []string{`"normalized_url"`, `"host"`, `"registrable_domain"`} {
		if bytes.Contains(canonical, []byte(field)) {
			t.Errorf("empty optional target field %s was not omitted: %s", field, canonical)
		}
	}
}

func TestCanonicalStringEscapingAndInvalidUTF8(t *testing.T) {
	encoded, err := canonicalEncode(map[string]any{
		"s": "&<> ' \" \\ \t\n\u2028 😀",
	})
	if err != nil {
		t.Fatalf("canonicalize escaped string: %v", err)
	}
	want := `{"s":"&<> ' \" \\ \t\n` + "\u2028" + ` 😀"}`
	if string(encoded) != want {
		t.Fatalf("canonical string = %q, want %q", encoded, want)
	}

	if _, err := canonicalEncode(map[string]any{"invalid": string([]byte{0xff})}); err == nil {
		t.Fatal("invalid UTF-8 string accepted")
	}
	if _, err := canonicalEncode(map[string]any{string([]byte{0xff}): "value"}); err == nil {
		t.Fatal("invalid UTF-8 object key accepted")
	}
	for _, number := range []json.Number{"1e0", "-0"} {
		if _, err := canonicalEncode(number); err == nil {
			t.Errorf("non-canonical number %q accepted", number)
		}
	}

	report := readReportFixture(t, "report_edge_cases.json")
	report.Findings[0].Title = string([]byte{0xff})
	if _, err := CanonicalJSON(report); err == nil {
		t.Fatal("canonical report silently accepted invalid UTF-8 in a finding")
	}
}

func readReportFixture(t *testing.T, name string) Report {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return report
}
