package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/intel"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
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

func TestHistoryCLI(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "history_cli.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	ctx := context.Background()

	// 1. Empty list
	var buf bytes.Buffer
	err := RunHistoryList(ctx, cfg, HistoryListOptions{}, &buf)
	if err != nil {
		t.Fatalf("empty history list error: %v", err)
	}
	if !strings.Contains(buf.String(), "No scan history found") {
		t.Fatalf("expected empty history message, got:\n%s", buf.String())
	}

	// 2. Populate scans using PersistScanAssessment
	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ass1 := sampleAssessmentForTerminal(t)
	ass1.Target = "https://site-a.com"
	rec1, err := PersistScanAssessment(ctx, repo, ass1, "https://site-a.com", time.Now().Add(-10*time.Minute), time.Now().Add(-9*time.Minute), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatal(err)
	}
	ass2 := sampleAssessmentForTerminal(t)
	ass2.Target = "https://phish-site.cc"
	rec2, err := PersistScanAssessment(ctx, repo, ass2, "https://phish-site.cc", time.Now().Add(-5*time.Minute), time.Now().Add(-4*time.Minute), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatal(err)
	}

	// 3. List in terminal format
	buf.Reset()
	err = RunHistoryList(ctx, cfg, HistoryListOptions{NoColor: true}, &buf)
	if err != nil {
		t.Fatalf("history list error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Scan History (Total: 2)") || !strings.Contains(out, "https://site-a.com") || !strings.Contains(out, "https://phish-site.cc") {
		t.Fatalf("unexpected history table:\n%s", out)
	}

	// 4. List in JSON format
	buf.Reset()
	err = RunHistoryList(ctx, cfg, HistoryListOptions{Format: "json"}, &buf)
	if err != nil {
		t.Fatalf("history list json error: %v", err)
	}
	var listResp HistoryListResponse
	if err := json.Unmarshal(buf.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal history json response: %v\nJSON:\n%s", err, buf.String())
	}
	if listResp.Total != 2 || len(listResp.Items) != 2 {
		t.Fatalf("expected 2 items in json response, got total %d, items %d", listResp.Total, len(listResp.Items))
	}

	// 5. Filter list by target
	buf.Reset()
	err = RunHistoryList(ctx, cfg, HistoryListOptions{Target: "phish", Format: "json"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	var filterResp HistoryListResponse
	if err := json.Unmarshal(buf.Bytes(), &filterResp); err != nil {
		t.Fatal(err)
	}
	if filterResp.Total != 1 || filterResp.Items[0].Target != "https://phish-site.cc" {
		t.Fatalf("expected 1 filtered match for phish, got %+v", filterResp)
	}

	// 6. Show history entry
	buf.Reset()
	err = RunHistoryShow(ctx, cfg, HistoryShowOptions{ID: rec1.ShortID(), Format: "markdown"}, &buf)
	if err != nil {
		t.Fatalf("history show error: %v", err)
	}
	if !strings.Contains(buf.String(), "# Bouclier Website Risk Assessment") || !strings.Contains(buf.String(), "site-a.com") {
		t.Fatalf("unexpected history show markdown:\n%s", buf.String())
	}

	// 7. Show invalid ID
	err = RunHistoryShow(ctx, cfg, HistoryShowOptions{ID: "non-existent-id"}, &buf)
	if err == nil || ExitCode(err) != ExitScanFailure {
		t.Fatalf("expected ExitScanFailure for non-existent scan ID, got %v", err)
	}

	// 8. Delete with cancellation
	buf.Reset()
	stdinCancel := strings.NewReader("n\n")
	err = RunHistoryDelete(ctx, cfg, HistoryDeleteOptions{ID: rec2.ShortID(), Stdin: stdinCancel}, &buf)
	if err != nil {
		t.Fatalf("history delete cancel error: %v", err)
	}
	if !strings.Contains(buf.String(), "Deletion cancelled") {
		t.Fatalf("expected deletion cancelled, got:\n%s", buf.String())
	}

	// 9. Delete with --yes bypass
	buf.Reset()
	err = RunHistoryDelete(ctx, cfg, HistoryDeleteOptions{ID: rec2.ShortID(), Yes: true}, &buf)
	if err != nil {
		t.Fatalf("history delete --yes error: %v", err)
	}
	if !strings.Contains(buf.String(), "deleted") {
		t.Fatalf("expected deleted confirmation, got:\n%s", buf.String())
	}

	// Verify only 1 scan remains
	buf.Reset()
	_ = RunHistoryList(ctx, cfg, HistoryListOptions{Format: "json"}, &buf)
	var afterDelete HistoryListResponse
	_ = json.Unmarshal(buf.Bytes(), &afterDelete)
	if afterDelete.Total != 1 {
		t.Fatalf("expected 1 scan after deletion, got %d", afterDelete.Total)
	}
}

func TestRunScanPersistsAssessment(t *testing.T) {
	restore := SetWebsiteAnalyzerForTesting(func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		return &webintel.AnalysisResult{
			RequestedURL: input.Normalized,
			FinalURL:     input.Normalized,
			HTTPStatus:   webintel.ComponentStatus{State: webintel.StateCompleted},
			TLSStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
		}, nil
	})
	defer restore()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "auto_save.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	var buf bytes.Buffer
	opts := ScanOptions{
		Target: "https://example.com",
		NoCT:   true,
	}

	if err := RunScan(context.Background(), cfg, opts, &buf); err != nil {
		t.Fatalf("run scan error: %v", err)
	}

	// Check that scan was automatically persisted to SQLite
	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer repo.Close()

	count, err := repo.CountScans(context.Background(), storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 persisted scan after RunScan, got %d", count)
	}

	list, err := repo.ListScans(context.Background(), storage.ListFilter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if !strings.Contains(list[0].Target, "example.com") {
		t.Fatalf("unexpected saved target: %s", list[0].Target)
	}
}

func TestOneCLIScanCreatesExactlyOneRecord(t *testing.T) {
	restore := SetWebsiteAnalyzerForTesting(func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		return &webintel.AnalysisResult{
			RequestedURL: input.Normalized,
			FinalURL:     input.Normalized,
			HTTPStatus:   webintel.ComponentStatus{State: webintel.StateCompleted},
			TLSStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
		}, nil
	})
	defer restore()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "single_record.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	var buf bytes.Buffer
	opts := ScanOptions{
		Target: "https://site-one.com",
		NoCT:   true,
	}

	// First scan
	if err := RunScan(context.Background(), cfg, opts, &buf); err != nil {
		t.Fatalf("first scan error: %v", err)
	}

	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	count, err := repo.CountScans(ctx, storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 record after first scan, got %d", count)
	}

	// Second scan against different target
	buf.Reset()
	opts2 := ScanOptions{
		Target: "https://site-two.com",
		NoCT:   true,
	}
	if err := RunScan(context.Background(), cfg, opts2, &buf); err != nil {
		t.Fatalf("second scan error: %v", err)
	}

	count, err = repo.CountScans(ctx, storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected exactly 2 records after second scan, got %d", count)
	}
}

func TestCancelledScanDoesNotPersist(t *testing.T) {
	restore := SetWebsiteAnalyzerForTesting(func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		return nil, context.Canceled
	})
	defer restore()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cancelled.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	opts := ScanOptions{
		Target: "https://cancelled.org",
		NoCT:   true,
	}

	_ = RunScan(ctx, cfg, opts, &buf)

	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer repo.Close()

	count, err := repo.CountScans(context.Background(), storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0 records for cancelled scan, got %d", count)
	}
}

func TestSSRFBlockedScanPersistsWithFailedStatus(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "ssrf.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	var buf bytes.Buffer
	opts := ScanOptions{
		Target: "http://127.0.0.1/",
		NoCT:   true,
	}

	err := RunScan(context.Background(), cfg, opts, &buf)
	if err == nil {
		t.Fatal("expected SSRF failure error for 127.0.0.1")
	}

	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer repo.Close()

	list, err := repo.ListScans(context.Background(), storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 record persisted for SSRF blocked scan, got %d", len(list))
	}
	if list[0].Status != storage.StatusFailed {
		t.Fatalf("expected status %q, got %q", storage.StatusFailed, list[0].Status)
	}
}

func TestPersistedMetadataCompleteness(t *testing.T) {
	restore := SetWebsiteAnalyzerForTesting(func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		return &webintel.AnalysisResult{
			RequestedURL: input.Normalized,
			FinalURL:     input.Normalized,
			HTTPStatus:   webintel.ComponentStatus{State: webintel.StateCompleted},
			TLSStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
		}, nil
	})
	defer restore()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "metadata.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	var buf bytes.Buffer
	opts := ScanOptions{
		Target: "https://meta-audit.org",
		NoCT:   true,
	}

	if err := RunScan(context.Background(), cfg, opts, &buf); err != nil {
		t.Fatalf("run scan error: %v", err)
	}

	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	list, err := repo.ListScans(ctx, storage.ListFilter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("expected 1 scan, got %+v", list)
	}
	rec := list[0]

	// 1. Scan ID
	if rec.ID == "" || len(rec.ID) < 16 {
		t.Fatalf("invalid scan ID: %q", rec.ID)
	}
	// 2. Sanitized target
	if !strings.Contains(rec.Target, "meta-audit.org") {
		t.Fatalf("invalid target: %q", rec.Target)
	}
	// 3. Started and completed timestamps
	if rec.StartedAt.IsZero() || rec.CompletedAt.IsZero() {
		t.Fatalf("zero timestamp: started=%v completed=%v", rec.StartedAt, rec.CompletedAt)
	}
	// 4. Duration
	if rec.DurationMs < 0 {
		t.Fatalf("negative duration: %d", rec.DurationMs)
	}
	// 5. Scan status
	if rec.Status != storage.StatusCompleted && rec.Status != storage.StatusPartial {
		t.Fatalf("unexpected status: %v", rec.Status)
	}
	// 6. Overall score and classification
	if rec.OverallScore < 0 || rec.OverallScore > 100 {
		t.Fatalf("invalid score: %d", rec.OverallScore)
	}
	if rec.Classification == "" {
		t.Fatal("empty classification")
	}
	// 7. Policy ID and version
	if rec.PolicyID != "bouclier-default" || rec.PolicyVersion == "" {
		t.Fatalf("invalid policy metadata: id=%s version=%s", rec.PolicyID, rec.PolicyVersion)
	}
	// 8. Report schema version
	if rec.SchemaVersion != "bouclier-risk/v1" {
		t.Fatalf("invalid schema version: %s", rec.SchemaVersion)
	}
	// 9. Creation timestamp
	if rec.CreatedAt.IsZero() {
		t.Fatal("zero creation timestamp")
	}
	// 10. Complete sanitized assessment in scan_reports
	report, err := repo.GetScanReport(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetScanReport failed: %v", err)
	}
	if report.Assessment == nil {
		t.Fatal("assessment in report is nil")
	}
	if report.Assessment.SchemaVersion != "bouclier-risk/v1" {
		t.Fatalf("unexpected assessment schema version: %s", report.Assessment.SchemaVersion)
	}
	if len(report.Assessment.AnalysisCoverage) == 0 {
		t.Fatal("expected non-empty analysis coverage in persisted assessment")
	}
}

func TestEndToEndPersistenceLifecycleFlow(t *testing.T) {
	restore := SetWebsiteAnalyzerForTesting(func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		return &webintel.AnalysisResult{
			RequestedURL: input.Normalized,
			FinalURL:     input.Normalized,
			HTTPStatus:   webintel.ComponentStatus{State: webintel.StateCompleted},
			TLSStatus:    webintel.ComponentStatus{State: webintel.StateCompleted},
		}, nil
	})
	defer restore()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "lifecycle_flow.db")
	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	ctx := context.Background()
	var buf bytes.Buffer

	// Step 1: Scan a target
	scanOpts := ScanOptions{
		Target: "https://lifecycle-audit.org",
		NoCT:   true,
	}
	if err := RunScan(ctx, cfg, scanOpts, &buf); err != nil {
		t.Fatalf("step 1 scan error: %v", err)
	}

	// Step 2: Verify exactly one database record is created
	db1, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open db1: %v", err)
	}
	count, err := db1.CountScans(ctx, storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("step 2: expected exactly 1 record, got %d", count)
	}
	list1, err := db1.ListScans(ctx, storage.ListFilter{})
	if err != nil || len(list1) != 1 {
		t.Fatalf("step 2 list failed: %+v", list1)
	}
	scanID := list1[0].ID

	// Step 3: Exit the application (close database connection)
	if err := db1.Close(); err != nil {
		t.Fatalf("step 3 close db1: %v", err)
	}

	// Step 4: Restart it (re-open database at same path)
	db2, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("step 4 re-open db2: %v", err)
	}
	defer db2.Close()

	// Step 5: Retrieve the scan using history list and history show
	buf.Reset()
	if err := RunHistoryList(ctx, cfg, HistoryListOptions{Format: "json"}, &buf); err != nil {
		t.Fatalf("step 5 history list error: %v", err)
	}
	var listResp HistoryListResponse
	if err := json.Unmarshal(buf.Bytes(), &listResp); err != nil {
		t.Fatalf("step 5 unmarshal list error: %v", err)
	}
	if listResp.Total != 1 || listResp.Items[0].ID != scanID {
		t.Fatalf("step 5 list mismatch: %+v", listResp)
	}

	buf.Reset()
	if err := RunHistoryShow(ctx, cfg, HistoryShowOptions{ID: scanID, Format: "terminal"}, &buf); err != nil {
		t.Fatalf("step 5 history show error: %v", err)
	}
	if !strings.Contains(buf.String(), "lifecycle-audit.org") {
		t.Fatalf("step 5 show missing target in output:\n%s", buf.String())
	}

	// Step 6: Export JSON and Markdown
	jsonPath := filepath.Join(tmpDir, "exported-report.json")
	if err := RunHistoryShow(ctx, cfg, HistoryShowOptions{ID: scanID, Format: "json", Output: jsonPath}, &bytes.Buffer{}); err != nil {
		t.Fatalf("step 6 export json error: %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil || len(jsonData) == 0 {
		t.Fatalf("step 6 empty json export: %v", err)
	}

	mdPath := filepath.Join(tmpDir, "exported-report.md")
	if err := RunHistoryShow(ctx, cfg, HistoryShowOptions{ID: scanID, Format: "markdown", Output: mdPath}, &bytes.Buffer{}); err != nil {
		t.Fatalf("step 6 export markdown error: %v", err)
	}
	mdData, err := os.ReadFile(mdPath)
	if err != nil || !strings.Contains(string(mdData), "# Bouclier Website Risk Assessment") {
		t.Fatalf("step 6 invalid markdown export: %v", err)
	}

	// Step 7: Delete the scan
	buf.Reset()
	if err := RunHistoryDelete(ctx, cfg, HistoryDeleteOptions{ID: scanID, Yes: true}, &buf); err != nil {
		t.Fatalf("step 7 delete error: %v", err)
	}

	// Step 8: Confirm both metadata and report are deleted
	_, err = db2.GetScan(ctx, scanID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("step 8 expected ErrNotFound for scan record, got %v", err)
	}
	_, err = db2.GetScanReport(ctx, scanID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("step 8 expected ErrNotFound for scan report, got %v", err)
	}
	count, err = db2.CountScans(ctx, storage.ListFilter{})
	if err != nil || count != 0 {
		t.Fatalf("step 8 expected 0 scans, got %d", count)
	}

	// Step 9: Repeat persistence flow through TUI scan pipeline
	tuiScanOpts := ScanOptions{
		Target:  "https://tui-lifecycle.org",
		Storage: db2,
		NoCT:    true,
	}
	res, err := ExecuteScanPipeline(ctx, cfg, tuiScanOpts, nil)
	if err != nil {
		t.Fatalf("step 9 tui scan pipeline error: %v", err)
	}
	if res.ScanRecord == nil {
		t.Fatal("step 9 expected non-nil ScanRecord from pipeline")
	}

	// Verify exactly 1 scan persisted from TUI flow
	count, err = db2.CountScans(ctx, storage.ListFilter{})
	if err != nil || count != 1 {
		t.Fatalf("step 9 expected 1 scan from TUI flow, got %d", count)
	}
	tuiList, err := db2.ListScans(ctx, storage.ListFilter{})
	if err != nil || len(tuiList) != 1 || !strings.Contains(tuiList[0].Target, "tui-lifecycle.org") {
		t.Fatalf("step 9 unexpected tui scan record: %+v", tuiList)
	}
}

func TestScanPipelineWithThreatIntelligence(t *testing.T) {
	origAnalyzer := websiteAnalyzer
	defer func() { websiteAnalyzer = origAnalyzer }()
	websiteAnalyzer = func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
		return &webintel.AnalysisResult{
			RequestedURL:     input.Normalized,
			FinalURL:         input.Normalized,
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

	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	_ = repo.RegisterSource(ctx, storage.IntelSource{
		ID:           "test-feed",
		Name:         "Security Intel Source",
		ProviderType: "local_file",
		Endpoint:     "/feed.json",
		Enabled:      true,
	})

	now := time.Now().UTC()
	future := now.Add(48 * time.Hour)
	_, _, err = repo.SaveIndicatorBatch(ctx, "test-feed", []storage.IntelIndicator{
		{
			Type:       "domain",
			Value:      "malicious-target.com",
			Category:   "phishing",
			Confidence: 95,
			Severity:   "high",
			ExpiresAt:  &future,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	opts := ScanOptions{
		Target:  "https://malicious-target.com/login",
		Storage: repo,
		NoCT:    true,
	}

	res, err := ExecuteScanPipeline(ctx, config.Default(), opts, nil)
	if err != nil {
		t.Fatalf("scan pipeline error: %v", err)
	}

	if res.Assessment == nil {
		t.Fatal("expected non-nil assessment")
	}

	// Verify threat intelligence coverage
	if res.Assessment.Intelligence == nil {
		t.Fatal("expected non-nil Intelligence coverage block in assessment")
	}
	if res.Assessment.Intelligence.MatchesCount != 1 {
		t.Errorf("expected 1 match, got %d", res.Assessment.Intelligence.MatchesCount)
	}
	if !res.Assessment.Intelligence.Ran {
		t.Errorf("expected Intelligence.Ran to be true")
	}

	// Verify finding generated
	foundIntelFinding := false
	for _, f := range res.Assessment.Findings {
		if f.Code == intel.CodeIntelMaliciousDomain {
			foundIntelFinding = true
			if f.ScoreImpact <= 0 {
				t.Errorf("expected positive score impact for intelligence finding, got %d", f.ScoreImpact)
			}
			break
		}
	}
	if !foundIntelFinding {
		t.Errorf("expected finding %s in assessment findings", intel.CodeIntelMaliciousDomain)
	}
}
