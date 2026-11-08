package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/intel"
	"bouclier/internal/storage"
)

func setupTestDB(t *testing.T) (*config.Config, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_bouclier.db")

	cfg := config.Default()
	cfg.Storage.DatabasePath = dbPath

	return cfg, func() {}
}

func TestIntelCLICommands(t *testing.T) {
	cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// 1. Status with empty DB
	root := newRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "status", "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel status: %v", err)
	}
	if !strings.Contains(buf.String(), "Total Indicators:      0") {
		t.Errorf("expected 0 indicators in output, got: %s", buf.String())
	}

	// 2. Import a bundle
	bundlePath := filepath.Join(t.TempDir(), "test_bundle.json")
	now := time.Now().UTC()
	future := now.Add(48 * time.Hour)
	bundle, err := intel.CreateBundle([]intel.Indicator{
		{
			Type:       intel.TypeDomain,
			Value:      "phish-target.com",
			SourceID:   "community-feed",
			SourceName: "Community Threat Feed",
			Category:   "phishing",
			Confidence: 90,
			Severity:   "high",
			ExpiresAt:  &future,
		},
		{
			Type:       intel.TypeURL,
			Value:      "https://credential-stealer.org/login",
			SourceID:   "community-feed",
			SourceName: "Community Threat Feed",
			Category:   "credential-theft",
			Confidence: 95,
			Severity:   "critical",
			ExpiresAt:  &future,
		},
	}, intel.ExportOptions{})
	if err != nil {
		t.Fatalf("create test bundle: %v", err)
	}
	if err := intel.WriteBundle(bundlePath, bundle); err != nil {
		t.Fatalf("write test bundle: %v", err)
	}

	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "import", bundlePath, "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel import: %v", err)
	}
	if !strings.Contains(buf.String(), "Import completed successfully: 2 imported") {
		t.Errorf("expected 2 imported in output, got: %s", buf.String())
	}

	// 3. Status after import
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "status", "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel status after import: %v", err)
	}
	if !strings.Contains(buf.String(), "Total Indicators:      2") {
		t.Errorf("expected 2 indicators, got: %s", buf.String())
	}

	// 4. Sources list
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "sources", "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel sources: %v", err)
	}
	if !strings.Contains(buf.String(), "bundle-import") {
		t.Errorf("expected bundle-import in sources list, got: %s", buf.String())
	}

	// 5. Search indicators
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "search", "phish-target", "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel search: %v", err)
	}
	if !strings.Contains(buf.String(), "phish-target.com") {
		t.Errorf("expected phish-target.com in search results, got: %s", buf.String())
	}

	// 6. Export indicators
	exportPath := filepath.Join(t.TempDir(), "exported_bundle.json")
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "export", exportPath, "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel export: %v", err)
	}
	if !strings.Contains(buf.String(), "Exported 2 indicators") {
		t.Errorf("expected 2 exported indicators, got: %s", buf.String())
	}

	// Verify exported file
	expFile, err := os.Open(exportPath)
	if err != nil {
		t.Fatalf("open exported file: %v", err)
	}
	defer expFile.Close()
	expBundle, err := intel.ReadBundle(expFile)
	if err != nil {
		t.Fatalf("read exported bundle: %v", err)
	}
	if expBundle.Manifest.IndicatorCount != 2 {
		t.Errorf("expected 2 indicators in exported bundle manifest, got %d", expBundle.Manifest.IndicatorCount)
	}

	// 7. Prune dry-run and execution
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "prune", "--dry-run", "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel prune dry-run: %v", err)
	}
	if !strings.Contains(buf.String(), "[Dry Run]") {
		t.Errorf("expected dry-run in prune output, got: %s", buf.String())
	}
}

func TestIntelUpdateLocalFeed(t *testing.T) {
	cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// Create local feed file fixture
	feedPath := filepath.Join(t.TempDir(), "feed.json")
	feedData := `[
		{"type": "domain", "value": "sync-feed-threat.com", "category": "malware", "confidence": 88, "severity": "high"}
	]`
	if err := os.WriteFile(feedPath, []byte(feedData), 0600); err != nil {
		t.Fatal(err)
	}

	// Register source in db
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	err = repo.RegisterSource(context.Background(), storage.IntelSource{
		ID:           "test-feed-source",
		Name:         "Automated Feed Source",
		ProviderType: "local_file",
		Endpoint:     feedPath,
		Enabled:      true,
		Format:       "json",
	})
	repo.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Run update
	root := newRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "update", "test-feed-source", "--config", createTestConfigFile(t, cfg)})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel update: %v", err)
	}

	if !strings.Contains(buf.String(), "[SUCCESS] Imported: 1") {
		t.Errorf("expected 1 imported in update output, got: %s", buf.String())
	}
}

func TestIntelSourcesSubcommands(t *testing.T) {
	cfg, cleanup := setupTestDB(t)
	defer cleanup()

	configFile := createTestConfigFile(t, cfg)

	// 1a. Attempting to use deprecated/removed --auth-header flag must fail
	root := newRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"intel", "sources", "add",
		"bad-feed", "Bad Feed", "https_feed", "https://intel.example.com/feed.json",
		"--auth-header", "Bearer raw-secret",
		"--config", configFile,
	})
	if err := root.Execute(); err == nil {
		t.Fatalf("expected error using removed --auth-header flag, got nil")
	}

	// 1b. Add source via CLI with --auth-header-env
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"intel", "sources", "add",
		"custom-feed", "Custom Threat Feed", "https_feed", "https://intel.example.com/feed.json",
		"--format", "json",
		"--auth-header-env", "CUSTOM_FEED_AUTH_TOKEN",
		"--attribution", "Custom Threat Lab",
		"--interval", "12h",
		"--config", configFile,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel sources add failed: %v", err)
	}
	if !strings.Contains(buf.String(), "registered successfully") {
		t.Errorf("expected success message, got: %s", buf.String())
	}

	// 2. List sources via 'intel sources list'
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "sources", "list", "--config", configFile})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel sources list failed: %v", err)
	}
	if !strings.Contains(buf.String(), "custom-feed") {
		t.Errorf("expected custom-feed in sources list, got: %s", buf.String())
	}

	// 3. Disable source via 'intel sources disable'
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "sources", "disable", "custom-feed", "--config", configFile})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel sources disable failed: %v", err)
	}
	if !strings.Contains(buf.String(), "disabled") {
		t.Errorf("expected disabled confirmation, got: %s", buf.String())
	}

	// 4. Enable source via 'intel sources enable'
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "sources", "enable", "custom-feed", "--config", configFile})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel sources enable failed: %v", err)
	}
	if !strings.Contains(buf.String(), "enabled") {
		t.Errorf("expected enabled confirmation, got: %s", buf.String())
	}

	// 5. Remove source via 'intel sources remove'
	root = newRootCommand()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"intel", "sources", "remove", "custom-feed", "--config", configFile})
	if err := root.Execute(); err != nil {
		t.Fatalf("intel sources remove failed: %v", err)
	}
	if !strings.Contains(buf.String(), "removed successfully") {
		t.Errorf("expected remove confirmation, got: %s", buf.String())
	}
}

func createTestConfigFile(t *testing.T, cfg *config.Config) string {
	t.Helper()
	tmpFile := filepath.Join(t.TempDir(), "bouclier_config.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	return tmpFile
}
