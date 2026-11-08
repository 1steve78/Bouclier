package cli

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/intel"
	"bouclier/internal/storage"
)

func TestSourceRegistrationAndSecretRedaction(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "intel_test.db")

	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	ctx := context.Background()
	var out bytes.Buffer

	// 1. Register a new HTTPS source with an authentication secret via environment variable
	secretToken := "Bearer super-secret-api-token-xyz987"
	secretEnvVar := "PARTNER_FEED_TOKEN"
	t.Setenv(secretEnvVar, secretToken)

	addOpts := IntelSourceAddOptions{
		ID:             "source-secret",
		Name:           "Secret Partner Feed",
		ProviderType:   "https_feed",
		Endpoint:       "https://partner.example.com/feed.json",
		Format:         "json",
		AuthHeaderEnv:  secretEnvVar,
		Attribution:    "Partner Intel Inc",
		UpdateInterval: 6 * time.Hour,
	}

	if err := RunIntelSourceAdd(ctx, cfg, addOpts, &out); err != nil {
		t.Fatalf("RunIntelSourceAdd failed: %v", err)
	}

	// 2. Verify source settings survive application restart
	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open database after restart: %v", err)
	}
	src, err := repo.GetSource(ctx, "source-secret")
	if err != nil {
		t.Fatalf("get source after restart: %v", err)
	}
	if src.AuthHeaderEnv != secretEnvVar {
		t.Errorf("expected AuthHeaderEnv to survive restart, got %q", src.AuthHeaderEnv)
	}
	if src.UpdateInterval != 6*time.Hour {
		t.Errorf("expected UpdateInterval 6h, got %v", src.UpdateInterval)
	}
	repo.Close()

	// Verify that the secret value was NEVER written to the database file
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read raw db file: %v", err)
	}
	if bytes.Contains(dbBytes, []byte(secretToken)) || bytes.Contains(dbBytes, []byte("super-secret")) {
		t.Fatalf("CRITICAL SECURITY LEAK: secret token found in raw SQLite database bytes")
	}

	// 3. Verify secrets are excluded from JSON CLI output
	out.Reset()
	if err := RunIntelSources(ctx, cfg, IntelSourcesOptions{Format: "json"}, &out); err != nil {
		t.Fatalf("RunIntelSources json failed: %v", err)
	}
	jsonOutput := out.String()
	if strings.Contains(jsonOutput, secretToken) || strings.Contains(jsonOutput, "super-secret") {
		t.Errorf("SECURITY LEAK: secret token found in JSON sources output: %s", jsonOutput)
	}

	// 4. Verify secrets are excluded from terminal CLI output
	out.Reset()
	if err := RunIntelSources(ctx, cfg, IntelSourcesOptions{Format: "terminal"}, &out); err != nil {
		t.Fatalf("RunIntelSources terminal failed: %v", err)
	}
	termOutput := out.String()
	if strings.Contains(termOutput, secretToken) || strings.Contains(termOutput, "super-secret") {
		t.Errorf("SECURITY LEAK: secret token found in terminal sources output: %s", termOutput)
	}

	// 5. Test Disable and Enable
	out.Reset()
	if err := RunIntelSourceSetEnabled(ctx, cfg, "source-secret", false, &out); err != nil {
		t.Fatalf("disable source failed: %v", err)
	}
	repo, _ = storage.Open(dbPath)
	src, _ = repo.GetSource(ctx, "source-secret")
	repo.Close()
	if src.Enabled {
		t.Errorf("expected source to be disabled")
	}

	// 6. Test Remove
	out.Reset()
	if err := RunIntelSourceRemove(ctx, cfg, "source-secret", &out); err != nil {
		t.Fatalf("remove source failed: %v", err)
	}
	repo, _ = storage.Open(dbPath)
	_, err = repo.GetSource(ctx, "source-secret")
	repo.Close()
	if err == nil {
		t.Errorf("expected error after deleting source, got nil")
	}
}

func TestDisabledSourcesExcludedFromSync(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "intel_sync_test.db")

	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	ctx := context.Background()
	var out bytes.Buffer

	// Register disabled local source
	dummyFile := filepath.Join(tempDir, "empty.json")
	_ = os.WriteFile(dummyFile, []byte("[]"), 0644)

	addOpts := IntelSourceAddOptions{
		ID:           "disabled-src",
		Name:         "Disabled Feed",
		ProviderType: "local_file",
		Endpoint:     dummyFile,
		Disabled:     true,
	}
	if err := RunIntelSourceAdd(ctx, cfg, addOpts, &out); err != nil {
		t.Fatalf("add disabled source: %v", err)
	}

	// 1. General sync: should find 0 enabled sources to update
	out.Reset()
	if err := RunIntelUpdate(ctx, cfg, IntelUpdateOptions{}, &out); err != nil {
		t.Fatalf("general update returned unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "No enabled sources to update") {
		t.Errorf("expected 'No enabled sources to update', got: %s", out.String())
	}

	// 2. Targeted sync of disabled source: must reject with error
	out.Reset()
	err := RunIntelUpdate(ctx, cfg, IntelUpdateOptions{SourceID: "disabled-src"}, &out)
	if err == nil {
		t.Errorf("expected error updating disabled source directly, got nil")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected error mentioning 'disabled', got: %v", err)
	}
}

func TestFeedUpdateAtomicityWithLocalHTTPServer(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "atomicity_test.db")

	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	ctx := context.Background()

	// Server state variables
	var httpStatus int = http.StatusOK
	var serverPayload string = ""
	var capturedAuthHeader string = ""

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		_, _ = w.Write([]byte(serverPayload))
	})

	ts := httptest.NewTLSServer(handler)
	defer ts.Close()

	// Create test HTTPSFeedProvider configured for local test TLS server
	testFeedProvider := intel.NewHTTPSFeedProvider()
	testFeedProvider.AllowPrivateForTesting = true
	testFeedProvider.Dialer = (&net.Dialer{}).DialContext

	registry := intel.NewProviderRegistry()
	registry.Register("https_feed", testFeedProvider)
	registry.Register("local_file", intel.NewLocalFileProvider())

	// Register test source
	authSecret := "Bearer token-feed-123"
	authEnvVar := "TEST_REMOTE_FEED_SECRET"
	t.Setenv(authEnvVar, authSecret)

	var out bytes.Buffer
	addOpts := IntelSourceAddOptions{
		ID:             "remote-feed-1",
		Name:           "Remote Test Feed",
		ProviderType:   "https_feed",
		Endpoint:       ts.URL + "/threats.json",
		Format:         "json",
		AuthHeaderEnv:  authEnvVar,
		UpdateInterval: 12 * time.Hour,
	}
	if err := RunIntelSourceAdd(ctx, cfg, addOpts, &out); err != nil {
		t.Fatalf("register test source: %v", err)
	}

	// -------------------------------------------------------------
	// SCENARIO 1: Fully successful feed update commits consistently
	// -------------------------------------------------------------
	httpStatus = http.StatusOK
	serverPayload = `[
		{
			"type": "domain",
			"value": "initial-bad-actor.com",
			"category": "phishing",
			"confidence": 92,
			"severity": "high"
		},
		{
			"type": "ipv4",
			"value": "198.51.100.55",
			"category": "c2",
			"confidence": 85,
			"severity": "high"
		}
	]`

	out.Reset()
	if err := RunIntelUpdateWithRegistry(ctx, cfg, IntelUpdateOptions{}, &out, registry); err != nil {
		t.Fatalf("Scenario 1 update failed: %v, output: %s", err, out.String())
	}

	if capturedAuthHeader != authSecret {
		t.Errorf("expected server to receive auth header %q, got %q", authSecret, capturedAuthHeader)
	}

	repo, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := repo.GetIntelStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalIndicators != 2 {
		t.Fatalf("Scenario 1: expected 2 indicators committed, got %d", stats.TotalIndicators)
	}
	run, err := repo.GetLatestSyncRun(ctx, "remote-feed-1")
	if err != nil || run == nil {
		t.Fatalf("Scenario 1: expected sync run recorded, err=%v", err)
	}
	if run.Status != "success" || run.ImportedCount != 2 || run.RejectedCount != 0 {
		t.Errorf("Scenario 1: unexpected sync run state: %+v", run)
	}
	repo.Close()

	// -------------------------------------------------------------
	// SCENARIO 2: Failed download does NOT destroy existing indicators
	// -------------------------------------------------------------
	httpStatus = http.StatusInternalServerError
	serverPayload = `{"error": "internal database outage"}`

	out.Reset()
	err = RunIntelUpdateWithRegistry(ctx, cfg, IntelUpdateOptions{}, &out, registry)
	if err == nil {
		t.Errorf("Scenario 2: expected error on 500 response, got nil")
	}

	repo, _ = storage.Open(dbPath)
	stats, _ = repo.GetIntelStats(ctx)
	if stats.TotalIndicators != 2 {
		t.Fatalf("CRITICAL INTEGRITY FAILURE: failed download destroyed existing indicators! expected 2, got %d", stats.TotalIndicators)
	}
	run, _ = repo.GetLatestSyncRun(ctx, "remote-feed-1")
	if run.Status != "failed" || run.ErrorMessage == "" {
		t.Errorf("Scenario 2: expected sync run to record 'failed' status and error message, got: %+v", run)
	}
	repo.Close()

	// -------------------------------------------------------------
	// SCENARIO 3: Malformed feed does not replace valid existing records
	// -------------------------------------------------------------
	httpStatus = http.StatusOK
	serverPayload = `[ {"type": "domain", "value": "broken-record` // Truncated / malformed JSON

	out.Reset()
	err = RunIntelUpdateWithRegistry(ctx, cfg, IntelUpdateOptions{}, &out, registry)
	if err == nil {
		t.Errorf("Scenario 3: expected error on malformed feed, got nil")
	}

	repo, _ = storage.Open(dbPath)
	stats, _ = repo.GetIntelStats(ctx)
	if stats.TotalIndicators != 2 {
		t.Fatalf("CRITICAL INTEGRITY FAILURE: malformed feed replaced or dropped existing indicators! expected 2, got %d", stats.TotalIndicators)
	}
	run, _ = repo.GetLatestSyncRun(ctx, "remote-feed-1")
	if run.Status != "failed" {
		t.Errorf("Scenario 3: expected sync run 'failed', got: %s", run.Status)
	}
	repo.Close()

	// -------------------------------------------------------------
	// SCENARIO 4: Partial feed ingestion reports explicit partial status
	// -------------------------------------------------------------
	httpStatus = http.StatusOK
	serverPayload = `[
		{
			"type": "domain",
			"value": "new-valid-threat.com",
			"category": "malware",
			"confidence": 95,
			"severity": "critical"
		},
		{
			"type": "ipv4",
			"value": "999.999.999.999",
			"category": "malware",
			"confidence": 50,
			"severity": "low"
		}
	]`

	out.Reset()
	if err := RunIntelUpdateWithRegistry(ctx, cfg, IntelUpdateOptions{}, &out, registry); err != nil {
		t.Fatalf("Scenario 4: partial update returned unexpected top-level error: %v", err)
	}

	repo, _ = storage.Open(dbPath)
	stats, _ = repo.GetIntelStats(ctx)
	// 2 initial + 1 new valid = 3 total indicators
	if stats.TotalIndicators != 3 {
		t.Errorf("Scenario 4: expected 3 total indicators, got %d", stats.TotalIndicators)
	}
	run, _ = repo.GetLatestSyncRun(ctx, "remote-feed-1")
	if run.Status != "partial" {
		t.Errorf("Scenario 4: expected status 'partial', got %q", run.Status)
	}
	if run.ImportedCount != 1 || run.RejectedCount != 1 {
		t.Errorf("Scenario 4: expected imported=1, rejected=1, got: imported=%d, rejected=%d",
			run.ImportedCount, run.RejectedCount)
	}
	repo.Close()

	// -------------------------------------------------------------
	// SCENARIO 5: Cancelled context aborts and rolls back uncommitted changes
	// -------------------------------------------------------------
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately before execution

	out.Reset()
	err = RunIntelUpdateWithRegistry(cancelCtx, cfg, IntelUpdateOptions{}, &out, registry)
	if err == nil {
		t.Errorf("Scenario 5: expected error on cancelled context, got nil")
	}

	repo, _ = storage.Open(dbPath)
	stats, _ = repo.GetIntelStats(ctx)
	if stats.TotalIndicators != 3 {
		t.Errorf("Scenario 5: expected indicator count to remain 3 after rollback, got %d", stats.TotalIndicators)
	}
	repo.Close()
}
