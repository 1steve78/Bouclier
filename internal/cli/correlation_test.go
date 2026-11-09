package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/report"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
)

func TestRunHistoryCorrelateRendersTrendAndFindings(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.DatabasePath = filepath.Join(t.TempDir(), "correlation.db")
	ctx := context.Background()
	db, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	common := risk.NormalizedFinding{Code: "WEB_CSP", Title: "Weak CSP", Evidence: "unsafe-eval"}
	added := risk.NormalizedFinding{Code: "TLS_WEAK", Title: "Weak TLS", Evidence: "TLS 1.0"}
	for i, assessment := range []*risk.RiskAssessment{
		{Target: "https://example.com/a", OverallScore: 20, Classification: risk.RiskGuarded, Findings: []risk.NormalizedFinding{common}},
		{Target: "https://example.com/b", OverallScore: 65, Classification: risk.RiskHigh, Findings: []risk.NormalizedFinding{common, added}},
	} {
		when := start.Add(time.Duration(i) * time.Hour)
		_, err := PersistScanAssessment(ctx, db, assessment, assessment.Target, when, when.Add(time.Second), time.Second, storage.StatusCompleted)
		if err != nil {
			t.Fatal(err)
		}
	}
	other := &risk.RiskAssessment{Target: "https://sub.example.com", OverallScore: 99}
	when := start.Add(3 * time.Hour)
	if _, err := PersistScanAssessment(ctx, db, other, other.Target, when, when.Add(time.Second), time.Second, storage.StatusCompleted); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := RunHistoryCorrelate(ctx, cfg, HistoryCorrelateOptions{Target: "EXAMPLE.com"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Risk score trend") || !strings.Contains(out.String(), "+1 new") ||
		!strings.Contains(out.String(), "65") || strings.Contains(out.String(), "99") {
		t.Fatalf("unexpected correlation output:\n%s", out.String())
	}

	out.Reset()
	if err := RunHistoryCorrelate(ctx, cfg, HistoryCorrelateOptions{Target: "example.com", Format: "json"}, &out); err != nil {
		t.Fatal(err)
	}
	var result report.Correlation
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Scans) != 2 || result.Scans[1].NewFindings[0].Code != "TLS_WEAK" {
		t.Fatalf("JSON correlation did not contain exact-host trend and finding delta: %+v", result)
	}
}

func TestCanonicalCorrelationHostRejectsInvalidTargets(t *testing.T) {
	for _, target := range []string{"", "http://user:pass@example.com", "file:///etc/passwd"} {
		if _, err := canonicalCorrelationHost(target); err == nil {
			t.Errorf("canonicalCorrelationHost(%q) unexpectedly succeeded", target)
		}
	}
	host, err := canonicalCorrelationHost("HTTPS://Example.COM/path")
	if err != nil || host != "example.com" {
		t.Fatalf("canonical host = %q, err=%v", host, err)
	}
}
