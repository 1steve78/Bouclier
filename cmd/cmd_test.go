package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/cli"
	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webintel"
)

func executeCommand(args ...string) (string, error) {
	cmd := newRootCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func executeCommandWithStreams(args ...string) (stdout string, stderr string, err error) {
	cmd := newRootCommand()
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func mockWebsiteAnalyzer() func() {
	return cli.SetWebsiteAnalyzerForTesting(func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error) {
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
	})
}

func TestRootCommandHelp(t *testing.T) {
	out, err := executeCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, expected := range []string{"bouclier", "tui", "scan", "mcp", "serve", "version", "config", "Examples:"} {
		if !strings.Contains(out, expected) {
			t.Errorf("root help missing %q:\n%s", expected, out)
		}
	}
}

func TestTUICommandHelp(t *testing.T) {
	out, err := executeCommand("tui", "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, expected := range []string{"tui", "interactive", "--no-color"} {
		if !strings.Contains(out, expected) {
			t.Errorf("tui help missing %q:\n%s", expected, out)
		}
	}
}

func TestTUICommandNonInteractiveError(t *testing.T) {
	_, err := executeCommand("tui")
	if err == nil {
		t.Fatal("expected error when running tui in non-interactive test environment")
	}
	if !strings.Contains(err.Error(), "requires an interactive terminal") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if cli.ExitCode(err) != cli.ExitInvalidUsage {
		t.Fatalf("expected exit code %d, got %d", cli.ExitInvalidUsage, cli.ExitCode(err))
	}
}

func TestServeCommandConfigurationValidation(t *testing.T) {
	_, err := executeCommand("serve", "--host", "0.0.0.0")
	if err == nil || !strings.Contains(err.Error(), "unspecified address") {
		t.Fatalf("serve accepted a wildcard host, error = %v", err)
	}
}

func TestServeCommandBindFailureUsesGeneralExitCode(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	_, err = executeCommand("serve", "--port", strconv.Itoa(port))
	if err == nil {
		t.Fatal("serve succeeded while the configured port was already in use")
	}
	if got := cli.ExitCode(err); got != cli.ExitGeneralError {
		t.Fatalf("serve exit code = %d, want general error %d (%v)", got, cli.ExitGeneralError, err)
	}
}

func TestVersionCommand(t *testing.T) {
	out, err := executeCommand("version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "Bouclier v0.1.0-dev") {
		t.Fatalf("version output missing expected version:\n%s", out)
	}
	if !strings.Contains(out, "Go version:") {
		t.Fatalf("version output missing Go version:\n%s", out)
	}
}

func TestConfigShowCommand(t *testing.T) {
	out, err := executeCommand("config", "show")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("config show did not output valid JSON: %v\nOutput:\n%s", err, out)
	}
	if _, ok := decoded["scanner"]; !ok {
		t.Fatalf("config output missing scanner section")
	}
	if _, ok := decoded["http_server"]; !ok {
		t.Fatalf("config output missing http_server section")
	}
}

func TestConfigShowWithCustomFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "custom.json")
	customContent := `{
  "application": {"name": "Bouclier", "version": "0.1.0-dev", "environment": "test"},
  "scanner": {"http_timeout": "12s", "tls_handshake_timeout": "7s", "max_redirects": 3, "max_concurrent_scans": 5, "user_agent": "CustomAgent/1.0"},
  "storage": {"database_path": "test.db", "cache_ttl": "12h"},
  "threat_intelligence": {"feed_update_interval": "12h", "feed_urls": []},
  "logging": {"level": "warn", "structured": true}
}`
	if err := os.WriteFile(cfgFile, []byte(customContent), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := executeCommand("--config", cfgFile, "config", "show")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "CustomAgent/1.0") {
		t.Fatalf("custom config not reflected in output:\n%s", out)
	}
}

func TestConfigShowSecretRedactionInCommand(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "secret_config.json")
	fakeSecret := "fake-super-secret-token-12345"
	sensitiveURL := fmt.Sprintf("https://user:%s@feed.example.com/api?token=%s", fakeSecret, fakeSecret)

	content := fmt.Sprintf(`{
  "application": {"name": "Bouclier", "version": "0.1.0-dev", "environment": "test"},
  "scanner": {"http_timeout": "8s", "tls_handshake_timeout": "5s", "max_redirects": 5, "max_concurrent_scans": 10, "user_agent": "Bouclier/0.1.0-dev"},
  "storage": {"database_path": "test.db", "cache_ttl": "24h"},
  "threat_intelligence": {"feed_update_interval": "24h", "feed_urls": [%q]},
  "logging": {"level": "info", "structured": false}
}`, sensitiveURL)

	if err := os.WriteFile(cfgFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := executeCommand("--config", cfgFile, "config", "show")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Valid JSON
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("config show output is not valid JSON: %v\nOutput:\n%s", err, out)
	}

	// 2. Secret must never appear
	if strings.Contains(out, fakeSecret) {
		t.Fatalf("fake secret was printed in plaintext in config show output:\n%s", out)
	}

	// 3. Redacted marker present
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in output:\n%s", out)
	}

	// 4. File on disk remains unchanged
	diskBytes, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diskBytes), fakeSecret) {
		t.Fatalf("effective configuration file on disk was modified")
	}
}

func TestScanArgumentValidation(t *testing.T) {
	t.Run("missing url argument", func(t *testing.T) {
		_, err := executeCommand("scan")
		if err == nil {
			t.Fatal("expected error when no url argument is provided")
		}
		if !strings.Contains(err.Error(), "accepts 1 arg(s), received 0") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("too many arguments", func(t *testing.T) {
		_, err := executeCommand("scan", "https://one.example", "https://two.example")
		if err == nil {
			t.Fatal("expected error when multiple url arguments are provided")
		}
		if !strings.Contains(err.Error(), "accepts 1 arg(s), received 2") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid flag", func(t *testing.T) {
		_, err := executeCommand("scan", "https://example.com", "--unknown-flag")
		if err == nil {
			t.Fatal("expected error on unknown flag")
		}
	})
}

func TestScanCommandExecution(t *testing.T) {
	restore := mockWebsiteAnalyzer()
	defer restore()

	t.Run("terminal scan stdout", func(t *testing.T) {
		out, err := executeCommand("scan", "https://example.com", "--no-color")
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if !strings.Contains(out, "BOUCLIER") || !strings.Contains(out, "Risk Score") {
			t.Fatalf("scan missing expected header or score:\n%s", out)
		}
	})

	t.Run("json scan stdout", func(t *testing.T) {
		out, err := executeCommand("scan", "https://example.com", "--format", "json")
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(out), &decoded); err != nil {
			t.Fatalf("scan did not output valid JSON: %v\nOutput:\n%s", err, out)
		}
		if decoded["schema_version"] != "bouclier-risk/v1" {
			t.Fatalf("expected schema_version bouclier-risk/v1, got %v", decoded["schema_version"])
		}
	})

	t.Run("markdown scan file output", func(t *testing.T) {
		tmpDir := t.TempDir()
		outFile := filepath.Join(tmpDir, "report.md")
		out, err := executeCommand("scan", "https://example.com", "--format", "markdown", "--output", outFile)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if out != "" {
			t.Fatalf("expected no stdout when writing to file, got:\n%s", out)
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "# Bouclier Website Risk Assessment") {
			t.Fatalf("markdown file missing expected header:\n%s", string(data))
		}
	})

	t.Run("scan with flags no-ct and ct-scope", func(t *testing.T) {
		out, err := executeCommand("scan", "https://example.com", "--no-ct", "--ct-scope", "registrable", "--timeout", "10s", "--no-color")
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if !strings.Contains(out, "example.com") {
			t.Fatalf("scan output missing target:\n%s", out)
		}
	})

	t.Run("scan stdout is clean json and verbose logs go to stderr", func(t *testing.T) {
		stdout, stderr, err := executeCommandWithStreams("scan", "https://example.com", "--format", "json", "--verbose")
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
			t.Fatalf("stdout is not valid JSON (contaminated by logs): %v\nOutput:\n%s", err, stdout)
		}
		if len(stderr) == 0 {
			t.Fatal("expected verbose logging to appear on stderr")
		}
	})

	t.Run("scan with fail-on-risk triggers exit code 5", func(t *testing.T) {
		_, err := executeCommand("scan", "https://example.com", "--fail-on-risk", "5")
		if err == nil {
			t.Fatal("expected error when score exceeds threshold")
		}
		if cli.ExitCode(err) != cli.ExitRiskThresholdExceeded {
			t.Fatalf("expected exit code %d, got %d", cli.ExitRiskThresholdExceeded, cli.ExitCode(err))
		}
	})

	t.Run("syntax error returns exit code 2", func(t *testing.T) {
		_, err := executeCommand("scan")
		if err == nil {
			t.Fatal("expected error for missing argument")
		}
		if cli.ExitCode(err) != cli.ExitInvalidUsage {
			t.Fatalf("expected exit code %d, got %d", cli.ExitInvalidUsage, cli.ExitCode(err))
		}
	})

	t.Run("markdown scan stdout", func(t *testing.T) {
		stdout, stderr, err := executeCommandWithStreams("scan", "https://example.com", "--format", "markdown", "--verbose")
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if !strings.Contains(stdout, "# Bouclier Website Risk Assessment") {
			t.Fatalf("stdout missing markdown header:\n%s", stdout)
		}
		if len(stderr) == 0 {
			t.Fatal("expected verbose logging on stderr")
		}
	})

	t.Run("json scan file output", func(t *testing.T) {
		tmpDir := t.TempDir()
		outFile := filepath.Join(tmpDir, "report.json")
		out, err := executeCommand("scan", "https://example.com", "--format", "json", "--output", outFile)
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if out != "" {
			t.Fatalf("expected no stdout when writing to file, got:\n%s", out)
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("file did not contain valid JSON: %v", err)
		}
		if decoded["schema_version"] != "bouclier-risk/v1" {
			t.Fatalf("unexpected schema_version: %v", decoded["schema_version"])
		}
	})

	t.Run("ssrf blocked private ip returns exit code 3", func(t *testing.T) {
		stdout, stderr, err := executeCommandWithStreams("scan", "http://127.0.0.1")
		if err == nil {
			t.Fatal("expected error for SSRF-blocked private IP target")
		}
		if cli.ExitCode(err) != cli.ExitScanFailure {
			t.Fatalf("expected exit code %d (ExitScanFailure), got %d (err: %v)", cli.ExitScanFailure, cli.ExitCode(err), err)
		}
		if !strings.Contains(stdout, "Analysis Coverage") {
			t.Fatalf("expected coverage table in stdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, "HTTP Inspection") {
			t.Fatalf("expected HTTP Inspection in coverage table:\n%s", stdout)
		}
		if !strings.Contains(stderr, "SSRF") && !strings.Contains(err.Error(), "SSRF") {
			t.Fatalf("expected SSRF error explanation in stderr or err, got stderr=%q err=%v", stderr, err)
		}
	})

	t.Run("output write error returns exit code 4", func(t *testing.T) {
		invalidPath := filepath.Join(string([]byte{0}), "invalid.json")
		_, err := executeCommand("scan", "https://example.com", "--output", invalidPath)
		if err == nil {
			t.Fatal("expected error on invalid output path")
		}
		if cli.ExitCode(err) != cli.ExitOutputError {
			t.Fatalf("expected exit code %d (ExitOutputError), got %d (err: %v)", cli.ExitOutputError, cli.ExitCode(err), err)
		}
	})
}

func TestHistoryCommandHierarchy(t *testing.T) {
	restore := mockWebsiteAnalyzer()
	defer restore()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cobra_history.db")
	cfgPath := filepath.Join(tmpDir, "config.json")

	cfgJSON := fmt.Sprintf(`{
		"application": {"name": "Bouclier", "version": "0.1.0-dev", "environment": "test"},
		"storage": {"database_path": %q, "cache_ttl": "24h"}
	}`, dbPath)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Run a scan so history has an entry
	_, err := executeCommand("scan", "https://history-target.org", "--config", cfgPath, "--no-ct")
	if err != nil {
		t.Fatalf("initial scan error: %v", err)
	}

	// 2. Help command
	out, err := executeCommand("history", "--help")
	if err != nil {
		t.Fatalf("history --help error: %v", err)
	}
	if !strings.Contains(out, "history list") || !strings.Contains(out, "history show") || !strings.Contains(out, "history delete") {
		t.Fatalf("unexpected history help output:\n%s", out)
	}

	// 3. history list terminal
	out, err = executeCommand("history", "list", "--config", cfgPath, "--no-color")
	if err != nil {
		t.Fatalf("history list error: %v", err)
	}
	if !strings.Contains(out, "Scan History") || !strings.Contains(out, "history-target.org") {
		t.Fatalf("expected scan in history list output:\n%s", out)
	}

	// 4. history list JSON
	out, err = executeCommand("history", "list", "--config", cfgPath, "--format", "json")
	if err != nil {
		t.Fatalf("history list json error: %v", err)
	}
	var listResp cli.HistoryListResponse
	if err := json.Unmarshal([]byte(out), &listResp); err != nil {
		t.Fatalf("failed to decode history list json: %v\nJSON:\n%s", err, out)
	}
	if listResp.Total != 1 || len(listResp.Items) != 1 {
		t.Fatalf("expected 1 item, got total %d, items %d", listResp.Total, len(listResp.Items))
	}
	scanID := listResp.Items[0].ID

	// 5. history show JSON
	out, err = executeCommand("history", "show", scanID, "--config", cfgPath, "--format", "json")
	if err != nil {
		t.Fatalf("history show json error: %v", err)
	}
	var decodedReport map[string]any
	if err := json.Unmarshal([]byte(out), &decodedReport); err != nil {
		t.Fatalf("failed to decode show json report: %v", err)
	}
	if decodedReport["schema_version"] != "bouclier-risk/v1" {
		t.Fatalf("unexpected schema version: %v", decodedReport["schema_version"])
	}

	// 6. history show markdown
	out, err = executeCommand("history", "show", scanID, "--config", cfgPath, "--format", "markdown")
	if err != nil {
		t.Fatalf("history show markdown error: %v", err)
	}
	if !strings.Contains(out, "# Bouclier Website Risk Assessment") {
		t.Fatalf("unexpected markdown show output:\n%s", out)
	}

	// 7. history delete --yes
	out, err = executeCommand("history", "delete", scanID, "--config", cfgPath, "--yes")
	if err != nil {
		t.Fatalf("history delete error: %v", err)
	}
	if !strings.Contains(out, "deleted") {
		t.Fatalf("expected deleted message, got:\n%s", out)
	}

	// 8. Verify list is now empty
	out, err = executeCommand("history", "list", "--config", cfgPath, "--format", "json")
	if err != nil {
		t.Fatalf("history list after delete error: %v", err)
	}
	_ = json.Unmarshal([]byte(out), &listResp)
	if listResp.Total != 0 {
		t.Fatalf("expected 0 scans after deletion, got %d", listResp.Total)
	}

	// 9. history show missing arg returns error
	_, err = executeCommand("history", "show")
	if err == nil || cli.ExitCode(err) != cli.ExitInvalidUsage {
		t.Fatalf("expected ExitInvalidUsage for show with no args, got %v", err)
	}

	// 10. history delete missing arg returns error
	_, err = executeCommand("history", "delete")
	if err == nil || cli.ExitCode(err) != cli.ExitInvalidUsage {
		t.Fatalf("expected ExitInvalidUsage for delete with no args, got %v", err)
	}
}

func TestHistoryListScoreFilterFlags(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "filter_flags.db")
	cfgPath := filepath.Join(tmpDir, "config.json")

	cfgJSON := fmt.Sprintf(`{
		"storage": {"database_path": %q}
	}`, dbPath)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Insert 3 records with scores 15, 50, 85
	s1 := storage.ScanRecord{ID: "scan-low-15", Target: "https://site-15.org", OverallScore: 15, Classification: risk.RiskLow, StartedAt: time.Now().Add(-10 * time.Minute)}
	s2 := storage.ScanRecord{ID: "scan-med-50", Target: "https://site-50.org", OverallScore: 50, Classification: risk.RiskElevated, StartedAt: time.Now().Add(-5 * time.Minute)}
	s3 := storage.ScanRecord{ID: "scan-high-85", Target: "https://site-85.org", OverallScore: 85, Classification: risk.RiskCritical, StartedAt: time.Now()}
	_ = repo.SaveScan(ctx, s1, nil)
	_ = repo.SaveScan(ctx, s2, nil)
	_ = repo.SaveScan(ctx, s3, nil)
	_ = repo.Close()

	// 1. Valid range matching scan-med-50 (inclusive boundary)
	out, err := executeCommand("history", "list", "--config", cfgPath, "--min-score", "50", "--max-score", "85", "--format", "json")
	if err != nil {
		t.Fatalf("history list filter error: %v", err)
	}
	var resp cli.HistoryListResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 {
		t.Fatalf("expected 2 scans between 50 and 85, got %d", resp.Total)
	}

	// 2. Exact boundary match min=50 max=50
	out, err = executeCommand("history", "list", "--config", cfgPath, "--min-score", "50", "--max-score", "50", "--format", "json")
	if err != nil {
		t.Fatalf("history list exact boundary error: %v", err)
	}
	resp = cli.HistoryListResponse{}
	_ = json.Unmarshal([]byte(out), &resp)
	if resp.Total != 1 || resp.Items[0].ID != "scan-med-50" {
		t.Fatalf("expected exactly scan-med-50, got: %+v", resp)
	}

	// 3. Rejection of negative min-score
	_, err = executeCommand("history", "list", "--config", cfgPath, "--min-score", "-5")
	if err == nil || cli.ExitCode(err) != cli.ExitInvalidUsage {
		t.Fatalf("expected ExitInvalidUsage for negative min-score, got %v", err)
	}

	// 4. Rejection of max-score > 100
	_, err = executeCommand("history", "list", "--config", cfgPath, "--max-score", "105")
	if err == nil || cli.ExitCode(err) != cli.ExitInvalidUsage {
		t.Fatalf("expected ExitInvalidUsage for max-score > 100, got %v", err)
	}

	// 5. Rejection when min-score > max-score
	_, err = executeCommand("history", "list", "--config", cfgPath, "--min-score", "90", "--max-score", "20")
	if err == nil || cli.ExitCode(err) != cli.ExitInvalidUsage {
		t.Fatalf("expected ExitInvalidUsage when min > max, got %v", err)
	}
}

func TestExecutableExitCodes(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "bouclier-test.exe")
	buildCmd := exec.Command("go", "build", "-o", binPath, "bouclier")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test executable: %v\nOutput: %s", err, string(out))
	}

	t.Run("ssrf private loopback target exits with code 3", func(t *testing.T) {
		cmd := exec.Command(binPath, "scan", "http://127.0.0.1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected non-zero exit code for SSRF blocked target")
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %v", err)
		}
		if exitErr.ExitCode() != 3 {
			t.Fatalf("expected exit code 3 for SSRF blocked target, got %d. Output:\n%s", exitErr.ExitCode(), string(out))
		}
		if !strings.Contains(string(out), "blocked by SSRF protection") {
			t.Fatalf("expected SSRF error explanation in output:\n%s", string(out))
		}
	})

	t.Run("ssrf private rfc1918 target exits with code 3", func(t *testing.T) {
		cmd := exec.Command(binPath, "scan", "http://10.0.0.1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected non-zero exit code for SSRF blocked target")
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %v", err)
		}
		if exitErr.ExitCode() != 3 {
			t.Fatalf("expected exit code 3 for SSRF blocked target, got %d. Output:\n%s", exitErr.ExitCode(), string(out))
		}
	})

	t.Run("invalid usage missing argument exits with code 2", func(t *testing.T) {
		cmd := exec.Command(binPath, "scan")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected non-zero exit code for missing scan argument")
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %v", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2 for invalid usage, got %d. Output:\n%s", exitErr.ExitCode(), string(out))
		}
	})

	t.Run("invalid usage unsupported format exits with code 2", func(t *testing.T) {
		cmd := exec.Command(binPath, "scan", "--format", "unsupported", "http://example.com")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected non-zero exit code for invalid format")
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %v", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2 for invalid usage, got %d. Output:\n%s", exitErr.ExitCode(), string(out))
		}
	})
}
