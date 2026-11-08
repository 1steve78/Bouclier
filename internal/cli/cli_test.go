package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webintel"
)

func TestValidateScanOptions(t *testing.T) {
	cases := []struct {
		name    string
		opts    ScanOptions
		wantErr string
	}{
		{
			name:    "empty target",
			opts:    ScanOptions{Target: ""},
			wantErr: "target URL is required",
		},
		{
			name: "valid defaults",
			opts: ScanOptions{Target: "https://example.com"},
		},
		{
			name: "valid json format",
			opts: ScanOptions{Target: "https://example.com", Format: "json"},
		},
		{
			name: "valid markdown format",
			opts: ScanOptions{Target: "https://example.com", Format: "markdown"},
		},
		{
			name:    "invalid format",
			opts:    ScanOptions{Target: "https://example.com", Format: "xml"},
			wantErr: `invalid --format "xml"`,
		},
		{
			name: "valid ct scope exact",
			opts: ScanOptions{Target: "https://example.com", CTScope: "exact"},
		},
		{
			name: "valid ct scope registrable",
			opts: ScanOptions{Target: "https://example.com", CTScope: "registrable"},
		},
		{
			name:    "invalid ct scope",
			opts:    ScanOptions{Target: "https://example.com", CTScope: "wildcard"},
			wantErr: `invalid --ct-scope "wildcard"`,
		},
		{
			name:    "mutually exclusive verbose and quiet",
			opts:    ScanOptions{Target: "https://example.com", Verbose: true, Quiet: true},
			wantErr: "cannot use --verbose and --quiet together",
		},
		{
			name:    "negative timeout",
			opts:    ScanOptions{Target: "https://example.com", Timeout: -1 * time.Second},
			wantErr: "--timeout cannot be negative",
		},
		{
			name: "valid fail on risk threshold",
			opts: ScanOptions{Target: "https://example.com", FailOnRisk: intPtr(60)},
		},
		{
			name:    "fail on risk negative",
			opts:    ScanOptions{Target: "https://example.com", FailOnRisk: intPtr(-2)},
			wantErr: "--fail-on-risk must be between 0 and 100",
		},
		{
			name:    "fail on risk over 100",
			opts:    ScanOptions{Target: "https://example.com", FailOnRisk: intPtr(101)},
			wantErr: "--fail-on-risk must be between 0 and 100",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScanOptions(&tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := RunVersion(&buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Bouclier v"+AppVersion) {
		t.Fatalf("expected version %q in output:\n%s", AppVersion, out)
	}
	if !strings.Contains(out, "Go version:") {
		t.Fatalf("expected Go version in output:\n%s", out)
	}
	if !strings.Contains(out, "Platform:") {
		t.Fatalf("expected Platform in output:\n%s", out)
	}
}

func TestRunConfigShow(t *testing.T) {
	var buf bytes.Buffer
	cfg := config.Default()
	if err := RunConfigShow(cfg, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}
	for _, section := range []string{"application", "scanner", "storage", "threat_intelligence", "logging"} {
		if _, ok := decoded[section]; !ok {
			t.Errorf("missing config section %q", section)
		}
	}
}

func TestRunConfigShowSecretRedaction(t *testing.T) {
	fakePassword := "fake-secret-pass-98765"
	fakeToken := "fake-token-value-12345"
	fakeAPIKey := "fake-api-key-abcde"

	sensitiveURL := fmt.Sprintf("https://fakeuser:%s@feed.example.org/v1/indicators?token=%s&api_key=%s", fakePassword, fakeToken, fakeAPIKey)
	cfg := config.Default()
	cfg.ThreatIntel.FeedURLs = []string{sensitiveURL}

	var buf bytes.Buffer
	if err := RunConfigShow(cfg, &buf); err != nil {
		t.Fatalf("unexpected RunConfigShow error: %v", err)
	}

	out := buf.String()

	// 1. Output must be valid JSON
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, out)
	}

	// 2. Secret values must NEVER appear in the output
	for _, secret := range []string{fakePassword, fakeToken, fakeAPIKey} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q leaked in configuration output:\n%s", secret, out)
		}
	}

	// 3. Redacted indicator should be present
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output:\n%s", out)
	}

	// 4. Effective configuration must remain completely unmodified
	if len(cfg.ThreatIntel.FeedURLs) != 1 || cfg.ThreatIntel.FeedURLs[0] != sensitiveURL {
		t.Fatalf("effective configuration was mutated: got %v, want original %q", cfg.ThreatIntel.FeedURLs, sensitiveURL)
	}

	// 5. Empty or unset secrets are handled properly without error
	cfgEmpty := config.Default()
	cfgEmpty.ThreatIntel.FeedURLs = []string{}
	var bufEmpty bytes.Buffer
	if err := RunConfigShow(cfgEmpty, &bufEmpty); err != nil {
		t.Fatalf("unexpected error for empty feed URLs: %v", err)
	}
	if err := json.Unmarshal(bufEmpty.Bytes(), &decoded); err != nil {
		t.Fatalf("empty config output is not valid JSON: %v", err)
	}
}

func sampleAssessmentForTerminal(t *testing.T) *risk.RiskAssessment {
	t.Helper()
	findings, err := risk.NormalizeFindings([]risk.Observation{
		{Code: "WEB_HSTS_MISSING", Title: "Missing HSTS", Description: "Header absent", Evidence: "header missing", Source: risk.SourceWeb},
		{Code: "CERT_EXPIRED", Title: "Leaf certificate expired", Description: "Certificate validity ended", Evidence: "expired cert", Source: risk.SourceTLS},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := risk.CalculateRisk(findings, risk.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	assessment.Target = "https://example.com"
	assessment.AnalyzedAt = time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC)
	assessment.AnalysisCoverage = []risk.ComponentCoverage{
		{Component: "url_analysis", State: risk.ComponentCompleted},
		{Component: "domain_analysis", State: risk.ComponentCompleted},
		{Component: "tls_connection", State: risk.ComponentCompleted},
		{Component: "certificate_analysis", State: risk.ComponentCompleted},
		{Component: "ct_lookup", State: risk.ComponentSkipped, Detail: "disabled by user"},
	}
	assessment.Limitations = []string{"ct_lookup coverage is skipped; absence of findings is not a clean result"}
	return assessment
}

func TestFormatTerminal(t *testing.T) {
	a := sampleAssessmentForTerminal(t)

	t.Run("default formatting", func(t *testing.T) {
		out := FormatTerminal(a, TerminalOptions{NoColor: true})
		for _, expected := range []string{
			"BOUCLIER",
			"Website Security Assessment",
			"Target:       https://example.com",
			"Risk Score",
			"Findings",
			"Critical:",
			"High:",
			"Medium:",
			"Low:",
			"Top Risk Factors",
			"Analysis Coverage",
			"Detailed Findings (2)",
			"Limitations & Assessment Context",
			"Scoring Methodology",
		} {
			if !strings.Contains(out, expected) {
				t.Errorf("missing expected string %q in output:\n%s", expected, out)
			}
		}
		// Confirm no ANSI escapes when NoColor is true
		if strings.Contains(out, "\033[") {
			t.Fatalf("ANSI escape codes present despite NoColor=true")
		}
	})

	t.Run("color enabled", func(t *testing.T) {
		out := FormatTerminal(a, TerminalOptions{NoColor: false})
		if !strings.Contains(out, "\033[") {
			t.Fatalf("expected ANSI escape codes when color enabled")
		}
	})

	t.Run("quiet mode", func(t *testing.T) {
		out := FormatTerminal(a, TerminalOptions{NoColor: true, Quiet: true})
		if !strings.Contains(out, "Risk Score") || !strings.Contains(out, "Top Risk Factors") {
			t.Fatalf("quiet mode missing summary sections:\n%s", out)
		}
		if strings.Contains(out, "Detailed Findings") || strings.Contains(out, "Analysis Coverage") {
			t.Fatalf("quiet mode should omit detailed findings and coverage:\n%s", out)
		}
	})
}

func TestRenderAndWriteOutput(t *testing.T) {
	a := sampleAssessmentForTerminal(t)

	t.Run("stdout terminal", func(t *testing.T) {
		var buf bytes.Buffer
		err := RenderAndWrite(a, OutputOptions{Format: "terminal", NoColor: true}, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "BOUCLIER") {
			t.Fatalf("unexpected output: %s", buf.String())
		}
	})

	t.Run("stdout json", func(t *testing.T) {
		var buf bytes.Buffer
		err := RenderAndWrite(a, OutputOptions{Format: "json"}, &buf)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if decoded["schema_version"] != "bouclier-risk/v1" {
			t.Fatalf("expected schema_version bouclier-risk/v1, got %v", decoded["schema_version"])
		}
	})

	t.Run("stdout markdown", func(t *testing.T) {
		var buf bytes.Buffer
		err := RenderAndWrite(a, OutputOptions{Format: "markdown"}, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "# Bouclier Website Risk Assessment") {
			t.Fatalf("unexpected markdown: %s", buf.String())
		}
	})

	t.Run("file output json", func(t *testing.T) {
		tmpDir := t.TempDir()
		outFile := filepath.Join(tmpDir, "reports", "test_report.json")
		err := RenderAndWrite(a, OutputOptions{Format: "json", Output: outFile}, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("file content is not valid json: %v", err)
		}
	})

	t.Run("file output terminal strips color", func(t *testing.T) {
		tmpDir := t.TempDir()
		outFile := filepath.Join(tmpDir, "report.txt")
		err := RenderAndWrite(a, OutputOptions{Format: "terminal", Output: outFile, NoColor: false}, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "\033[") {
			t.Fatal("file output should never contain ANSI escape codes")
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		err := RenderAndWrite(a, OutputOptions{Format: "yaml"}, &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})
}

func TestRunScanEndToEndWithMock(t *testing.T) {
	// Mock websiteAnalyzer to avoid external network requests during unit tests
	origAnalyzer := websiteAnalyzer
	defer func() { websiteAnalyzer = origAnalyzer }()

	websiteAnalyzer = func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		tlsRes := &tlsintel.AnalysisResult{
			TargetHostname:    input.Hostname,
			Findings:          []certanalysis.Finding{{Code: "CERT_EXPIRED", Title: "Leaf certificate expired", Evidence: "expired"}},
			TLSStatus:         tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
			CertificateStatus: tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
			CTStatus:          tlsintel.ComponentStatus{State: tlsintel.StateCompleted},
			AnalyzedAt:        time.Now().UTC(),
		}
		return &webintel.AnalysisResult{
			RequestedURL:     input.Normalized,
			FinalURL:         input.Normalized,
			TLS:              tlsRes,
			Findings:         []heuristics.Finding{{Code: "WEB_HSTS_MISSING", Title: "Missing HSTS", Evidence: "absent"}},
			TLSStatus:        webintel.ComponentStatus{State: webintel.StateCompleted},
			HTTPStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
			RedirectsStatus:  webintel.ComponentStatus{State: webintel.StateCompleted},
			HeadersStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
			CookiesStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
			CORSStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
			HTMLStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
			DisclosureStatus: webintel.ComponentStatus{State: webintel.StateCompleted},
			AnalyzedAt:       time.Now().UTC(),
			Complete:         true,
		}, nil
	}

	t.Run("successful terminal scan", func(t *testing.T) {
		var buf bytes.Buffer
		opts := ScanOptions{
			Target:  "https://example.com",
			Format:  "terminal",
			NoColor: true,
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "BOUCLIER") || !strings.Contains(out, "example.com") {
			t.Fatalf("scan output missing header or target:\n%s", out)
		}
		if !strings.Contains(out, "CERT_EXPIRED") || !strings.Contains(out, "WEB_HSTS_MISSING") {
			t.Fatalf("scan output missing aggregated findings:\n%s", out)
		}
	})

	t.Run("successful json scan", func(t *testing.T) {
		var buf bytes.Buffer
		opts := ScanOptions{
			Target: "https://example.com",
			Format: "json",
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if decoded["target"] != "example.com" {
			t.Fatalf("expected target example.com, got %v", decoded["target"])
		}
	})

	t.Run("target without scheme defaults to https", func(t *testing.T) {
		var buf bytes.Buffer
		opts := ScanOptions{
			Target:  "example.com",
			Format:  "terminal",
			NoColor: true,
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if !strings.Contains(buf.String(), "example.com") {
			t.Fatalf("expected example.com in output:\n%s", buf.String())
		}
	})

	t.Run("invalid target returns error", func(t *testing.T) {
		var buf bytes.Buffer
		opts := ScanOptions{
			Target: "http://invalid port:99999",
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err == nil {
			t.Fatal("expected error for invalid target")
		}
	})

	t.Run("cancelled context stops scan", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancelled
		var buf bytes.Buffer
		opts := ScanOptions{
			Target: "https://example.com",
		}
		err := RunScan(ctx, config.Default(), opts, &buf)
		if err == nil {
			t.Fatal("expected error on cancelled context")
		}
	})

	t.Run("http target skips tls gracefully", func(t *testing.T) {
		websiteAnalyzer = func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
			return &webintel.AnalysisResult{
				RequestedURL:     input.Normalized,
				FinalURL:         input.Normalized,
				TLSStatus:        webintel.ComponentStatus{State: webintel.StateSkipped, Error: "TLS is not applicable to an HTTP URL"},
				HTTPStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
				RedirectsStatus:  webintel.ComponentStatus{State: webintel.StateCompleted},
				HeadersStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
				CookiesStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
				CORSStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
				HTMLStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
				DisclosureStatus: webintel.ComponentStatus{State: webintel.StateCompleted},
				AnalyzedAt:       time.Now().UTC(),
				Complete:         true,
			}, nil
		}

		var buf bytes.Buffer
		opts := ScanOptions{
			Target:  "http://example.com",
			Format:  "terminal",
			NoColor: true,
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "TLS Connection               Skipped") {
			t.Fatalf("expected TLS connection to be marked skipped:\n%s", out)
		}
	})

	t.Run("operational failure preserved in coverage and limitations", func(t *testing.T) {
		websiteAnalyzer = func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
			return &webintel.AnalysisResult{
				RequestedURL:     input.Normalized,
				FinalURL:         input.Normalized,
				TLSStatus:        webintel.ComponentStatus{State: webintel.StateFailed, Error: "connection reset"},
				HTTPStatus:       webintel.ComponentStatus{State: webintel.StateFailed, Error: "dial tcp connection refused"},
				RedirectsStatus:  webintel.ComponentStatus{State: webintel.StateSkipped},
				HeadersStatus:    webintel.ComponentStatus{State: webintel.StateSkipped},
				CookiesStatus:    webintel.ComponentStatus{State: webintel.StateSkipped},
				CORSStatus:       webintel.ComponentStatus{State: webintel.StateSkipped},
				HTMLStatus:       webintel.ComponentStatus{State: webintel.StateSkipped},
				DisclosureStatus: webintel.ComponentStatus{State: webintel.StateSkipped},
				AnalyzedAt:       time.Now().UTC(),
				Complete:         false,
			}, nil
		}

		var buf bytes.Buffer
		opts := ScanOptions{
			Target:  "https://offline-target.com",
			Format:  "terminal",
			NoColor: true,
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err != nil {
			t.Fatalf("operational failure should be aggregated without fatal scan error: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "Failed") {
			t.Fatalf("expected Failed state in coverage:\n%s", out)
		}
		if !strings.Contains(out, "absence of findings is not a clean result") {
			t.Fatalf("expected clean result limitation warning:\n%s", out)
		}
	})

	t.Run("ssrf blocked private ip target returns exit code 3 and preserves coverage", func(t *testing.T) {
		websiteAnalyzer = func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
			return &webintel.AnalysisResult{
				RequestedURL:     input.Normalized,
				FinalURL:         input.Normalized,
				TLSStatus:        webintel.ComponentStatus{State: webintel.StateSkipped, Error: "TLS is not applicable to an HTTP URL"},
				HTTPStatus:       webintel.ComponentStatus{State: webintel.StateFailed, Error: "inspect website: validate destination: host \"127.0.0.1\" resolved only to blocked or private addresses"},
				RedirectsStatus:  webintel.ComponentStatus{State: webintel.StateSkipped},
				HeadersStatus:    webintel.ComponentStatus{State: webintel.StateSkipped},
				CookiesStatus:    webintel.ComponentStatus{State: webintel.StateSkipped},
				CORSStatus:       webintel.ComponentStatus{State: webintel.StateSkipped},
				HTMLStatus:       webintel.ComponentStatus{State: webintel.StateSkipped},
				DisclosureStatus: webintel.ComponentStatus{State: webintel.StateSkipped},
				AnalyzedAt:       time.Now().UTC(),
				Complete:         false,
			}, nil
		}

		var buf bytes.Buffer
		opts := ScanOptions{
			Target:  "http://127.0.0.1",
			Format:  "terminal",
			NoColor: true,
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err == nil {
			t.Fatal("expected error for SSRF-blocked private IP target")
		}
		if code := ExitCode(err); code != ExitScanFailure {
			t.Fatalf("expected exit code %d (ExitScanFailure), got %d (err: %v)", ExitScanFailure, code, err)
		}
		out := buf.String()
		// Coverage table must still be rendered
		if !strings.Contains(out, "Analysis Coverage") {
			t.Fatalf("expected coverage table in output:\n%s", out)
		}
		if !strings.Contains(out, "HTTP Inspection              Failed") {
			t.Fatalf("expected HTTP Inspection Failed in output:\n%s", out)
		}
	})

	t.Run("fail on risk threshold exceeded triggers code 5", func(t *testing.T) {
		websiteAnalyzer = origAnalyzer
		defer func() { websiteAnalyzer = origAnalyzer }()
		// Mock analyzer that returns a high finding
		websiteAnalyzer = func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
			return &webintel.AnalysisResult{
				RequestedURL:     input.Normalized,
				FinalURL:         input.Normalized,
				Findings:         []heuristics.Finding{{Code: "BRAND_EXACT_LABEL", Title: "Impersonation", Evidence: "paypal"}},
				TLSStatus:        webintel.ComponentStatus{State: webintel.StateCompleted},
				HTTPStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
				RedirectsStatus:  webintel.ComponentStatus{State: webintel.StateCompleted},
				HeadersStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
				CookiesStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
				CORSStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
				HTMLStatus:       webintel.ComponentStatus{State: webintel.StateCompleted},
				DisclosureStatus: webintel.ComponentStatus{State: webintel.StateCompleted},
				AnalyzedAt:       time.Now().UTC(),
				Complete:         true,
			}, nil
		}

		var buf bytes.Buffer
		opts := ScanOptions{
			Target:     "https://example.com",
			FailOnRisk: intPtr(10), // threshold 10, finding will exceed it
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err == nil {
			t.Fatal("expected error when risk threshold is exceeded")
		}
		code := ExitCode(err)
		if code != ExitRiskThresholdExceeded {
			t.Fatalf("expected exit code %d, got %d (err: %v)", ExitRiskThresholdExceeded, code, err)
		}
	})

	t.Run("fail on risk threshold not exceeded returns success", func(t *testing.T) {
		var buf bytes.Buffer
		opts := ScanOptions{
			Target:     "https://example.com",
			FailOnRisk: intPtr(95), // threshold 95, finding will not exceed it
		}
		err := RunScan(context.Background(), config.Default(), opts, &buf)
		if err != nil {
			t.Fatalf("unexpected error when score below threshold: %v", err)
		}
	})
}

func intPtr(v int) *int {
	return &v
}

func TestExitCodes(t *testing.T) {
	if code := ExitCode(nil); code != ExitSuccess {
		t.Fatalf("nil error should return %d, got %d", ExitSuccess, code)
	}
	if code := ExitCode(NewExitError(ExitScanFailure, "scan failed")); code != ExitScanFailure {
		t.Fatalf("scan failure should return %d, got %d", ExitScanFailure, code)
	}
	if code := ExitCode(NewExitError(ExitOutputError, "output failed")); code != ExitOutputError {
		t.Fatalf("output error should return %d, got %d", ExitOutputError, code)
	}
	if code := ExitCode(NewExitError(ExitRiskThresholdExceeded, "threshold exceeded")); code != ExitRiskThresholdExceeded {
		t.Fatalf("threshold error should return %d, got %d", ExitRiskThresholdExceeded, code)
	}
}
