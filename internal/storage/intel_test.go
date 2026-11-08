package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestIntelSourceCRUD(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	src := IntelSource{
		ID:             "feed-1",
		Name:           "ThreatFeed Alpha",
		ProviderType:   "local_file",
		Endpoint:       "/path/to/feed.json",
		Enabled:        true,
		UpdateInterval: 12 * time.Hour,
		Attribution:    "Alpha Security Research",
		Format:         "json",
	}

	if err := db.RegisterSource(ctx, src); err != nil {
		t.Fatalf("register source: %v", err)
	}

	got, err := db.GetSource(ctx, "feed-1")
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if got.Name != "ThreatFeed Alpha" || !got.Enabled || got.UpdateInterval != 12*time.Hour {
		t.Errorf("unexpected source retrieved: %+v", got)
	}

	// Update source
	src.Name = "ThreatFeed Alpha Updated"
	if err := db.UpdateSource(ctx, src); err != nil {
		t.Fatalf("update source: %v", err)
	}
	gotUpdated, err := db.GetSource(ctx, "feed-1")
	if err != nil {
		t.Fatalf("get updated source: %v", err)
	}
	if gotUpdated.Name != "ThreatFeed Alpha Updated" {
		t.Errorf("expected updated name, got %s", gotUpdated.Name)
	}

	// Disable source
	if err := db.SetSourceEnabled(ctx, "feed-1", false); err != nil {
		t.Fatalf("disable source: %v", err)
	}
	gotDisabled, err := db.GetSource(ctx, "feed-1")
	if err != nil {
		t.Fatalf("get disabled source: %v", err)
	}
	if gotDisabled.Enabled {
		t.Errorf("expected source to be disabled")
	}

	// List sources
	sources, err := db.ListSources(ctx)
	if err != nil {
		t.Fatalf("list sources: %v", err)
	}
	if len(sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(sources))
	}

	// Delete source
	if err := db.DeleteSource(ctx, "feed-1"); err != nil {
		t.Fatalf("delete source: %v", err)
	}
	_, err = db.GetSource(ctx, "feed-1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestSaveIndicatorBatchAndLookup(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Must register source first due to foreign key
	src := IntelSource{
		ID:           "source-test",
		Name:         "Source Test",
		ProviderType: "local_file",
		Endpoint:     "/test.json",
		Enabled:      true,
	}
	if err := db.RegisterSource(ctx, src); err != nil {
		t.Fatalf("register source: %v", err)
	}

	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-1 * time.Hour)

	batch := []IntelIndicator{
		{
			ID:         "ind-1",
			Type:       "domain",
			Value:      "evil-phish.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   "critical",
			ExpiresAt:  &future,
		},
		{
			ID:         "ind-2",
			Type:       "url",
			Value:      "https://badsite.org/login",
			Category:   "credential-theft",
			Confidence: 85,
			Severity:   "high",
			ExpiresAt:  &future,
		},
		{
			ID:         "ind-3",
			Type:       "ipv4",
			Value:      "198.51.100.22",
			Category:   "c2",
			Confidence: 70,
			Severity:   "medium",
			ExpiresAt:  &past, // expired!
		},
	}

	imported, updated, err := db.SaveIndicatorBatch(ctx, "source-test", batch)
	if err != nil {
		t.Fatalf("save indicator batch: %v", err)
	}
	if imported != 3 || updated != 0 {
		t.Errorf("expected 3 imported, 0 updated; got imported=%d, updated=%d", imported, updated)
	}

	// Re-saving with an update
	batchUpdate := []IntelIndicator{
		{
			ID:         "ind-1",
			Type:       "domain",
			Value:      "evil-phish.com",
			Category:   "phishing",
			Confidence: 99, // updated
			Severity:   "critical",
			ExpiresAt:  &future,
		},
	}
	imported2, updated2, err := db.SaveIndicatorBatch(ctx, "source-test", batchUpdate)
	if err != nil {
		t.Fatalf("save indicator update: %v", err)
	}
	if imported2 != 0 || updated2 != 1 {
		t.Errorf("expected 0 imported, 1 updated; got imported=%d, updated=%d", imported2, updated2)
	}

	// Lookup active indicators
	queries := []IndicatorQuery{
		{Type: "domain", Value: "evil-phish.com"},
		{Type: "url", Value: "https://badsite.org/login"},
		{Type: "ipv4", Value: "198.51.100.22"}, // expired! should be omitted
	}
	results, err := db.LookupIndicators(ctx, queries)
	if err != nil {
		t.Fatalf("lookup indicators: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 unexpired results, got %d", len(results))
	}
	if results[0].Value != "evil-phish.com" || results[0].Confidence != 99 {
		t.Errorf("expected updated evil-phish.com with confidence 99, got %+v", results[0])
	}
}

func TestSearchAndPruneIndicators(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	src := IntelSource{
		ID:           "src-prune",
		Name:         "Source Prune",
		ProviderType: "local_file",
		Endpoint:     "/data.json",
		Enabled:      true,
	}
	if err := db.RegisterSource(ctx, src); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	future := now.Add(48 * time.Hour)
	past := now.Add(-2 * time.Hour)

	batch := []IntelIndicator{
		{Type: "domain", Value: "active-bank-phish.com", Category: "phishing", Confidence: 95, Severity: "critical", ExpiresAt: &future},
		{Type: "domain", Value: "active-crypto-scam.com", Category: "phishing", Confidence: 80, Severity: "high", ExpiresAt: &future},
		{Type: "domain", Value: "expired-old-threat.org", Category: "malware", Confidence: 60, Severity: "medium", ExpiresAt: &past},
	}
	if _, _, err := db.SaveIndicatorBatch(ctx, "src-prune", batch); err != nil {
		t.Fatal(err)
	}

	// Search by substring
	results, total, err := db.SearchIndicators(ctx, "crypto", 10, 0)
	if err != nil {
		t.Fatalf("search indicators: %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Errorf("expected 1 result for 'crypto', got total=%d, len=%d", total, len(results))
	}

	// Prune dry-run
	dryCount, err := db.PruneExpiredIndicators(ctx, now, true)
	if err != nil {
		t.Fatalf("prune dry-run: %v", err)
	}
	if dryCount != 1 {
		t.Errorf("expected dry-run count 1, got %d", dryCount)
	}

	// Actual prune
	pruned, err := db.PruneExpiredIndicators(ctx, now, false)
	if err != nil {
		t.Fatalf("prune execution: %v", err)
	}
	if pruned != 1 {
		t.Errorf("expected 1 pruned indicator, got %d", pruned)
	}

	// Verify stats
	stats, err := db.GetIntelStats(ctx)
	if err != nil {
		t.Fatalf("get intel stats: %v", err)
	}
	if stats.TotalIndicators != 2 {
		t.Errorf("expected 2 indicators remaining, got %d", stats.TotalIndicators)
	}
	if stats.TotalSources != 1 || stats.EnabledSources != 1 {
		t.Errorf("expected 1 total and enabled source, got total=%d, enabled=%d", stats.TotalSources, stats.EnabledSources)
	}
}

func TestSyncRunRecording(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	src := IntelSource{
		ID:           "sync-src",
		Name:         "Sync Source",
		ProviderType: "local_file",
		Endpoint:     "/feed.json",
		Enabled:      true,
	}
	if err := db.RegisterSource(ctx, src); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	run := IntelSyncRun{
		ID:            "run-1",
		SourceID:      "sync-src",
		StartedAt:     now.Add(-5 * time.Second),
		CompletedAt:   now,
		Status:        "success",
		ImportedCount: 150,
		UpdatedCount:  10,
		SkippedCount:  0,
		RejectedCount: 2,
	}

	if err := db.RecordSyncRun(ctx, run); err != nil {
		t.Fatalf("record sync run: %v", err)
	}

	latest, err := db.GetLatestSyncRun(ctx, "sync-src")
	if err != nil {
		t.Fatalf("get latest sync run: %v", err)
	}
	if latest == nil {
		t.Fatalf("expected non-nil latest sync run")
	}
	if latest.ImportedCount != 150 || latest.Status != "success" {
		t.Errorf("unexpected sync run details: %+v", latest)
	}
}

func TestLegacyPlaintextSecretRemovalMigration(t *testing.T) {
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "legacy_v4.db")

	// 1. Manually initialize a database up to migration 4 with a legacy plaintext auth_header
	rawDB, err := sql.Open("sqlite", dbFile)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}

	// Apply migrations 1 through 4
	for i := 0; i < 4; i++ {
		m := migrations[i]
		if _, err := rawDB.Exec(m.SQL); err != nil {
			t.Fatalf("apply migration %d: %v", m.Version, err)
		}
		// Record in schema_migrations
		_, _ = rawDB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT);`)
		_, _ = rawDB.Exec(`INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?);`,
			m.Version, time.Now().UTC().Format(time.RFC3339Nano), m.Description)
	}

	// Insert a legacy source with a plaintext auth_header and associated indicators
	legacySecret := "Bearer plaintext-super-secret-12345"
	_, err = rawDB.Exec(`
INSERT INTO intel_sources (
    id, name, provider_type, endpoint, enabled, update_interval_seconds,
    auth_header, attribution, license, format, created_at, updated_at
) VALUES (
    'legacy-feed', 'Legacy Partner Feed', 'https_feed', 'https://partner.org/feed.json', 1, 3600,
    ?, 'Partner Attribution', 'Proprietary', 'json', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
);`, legacySecret)
	if err != nil {
		t.Fatalf("insert legacy source: %v", err)
	}

	// Insert indicator belonging to this source
	_, err = rawDB.Exec(`
INSERT INTO intel_indicators (
    id, source_id, source_name, indicator_type, value, category, confidence, severity, ingested_at
) VALUES (
    'ind-1', 'legacy-feed', 'Legacy Partner Feed', 'domain', 'legacy-threat.com', 'phishing', 95, 'high', '2026-01-01T00:00:00Z'
);`)
	if err != nil {
		t.Fatalf("insert indicator: %v", err)
	}
	rawDB.Close()

	// 2. Open via standard Bouclier storage.Open(), which will run Migration 5
	db, err := Open(dbFile)
	if err != nil {
		t.Fatalf("open db through Bouclier: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Verify legacy plaintext column no longer exists or returns error if queried
	var legacyColVal string
	queryErr := db.db.QueryRowContext(ctx, `SELECT auth_header FROM intel_sources WHERE id = 'legacy-feed'`).Scan(&legacyColVal)
	if queryErr == nil {
		t.Errorf("expected query for dropped auth_header column to fail, but succeeded with value: %q", legacyColVal)
	}

	// Verify source metadata is fully preserved
	src, err := db.GetSource(ctx, "legacy-feed")
	if err != nil {
		t.Fatalf("GetSource: %v", err)
	}
	if src.Name != "Legacy Partner Feed" || src.Endpoint != "https://partner.org/feed.json" || !src.Enabled || src.Attribution != "Partner Attribution" {
		t.Errorf("unexpected preserved source metadata: %+v", src)
	}
	if src.AuthHeaderEnv != "" {
		t.Errorf("expected empty auth_header_env for migrated source, got: %q", src.AuthHeaderEnv)
	}

	// Verify associated indicators are fully preserved
	inds, err := db.LookupIndicators(ctx, []IndicatorQuery{{Type: "domain", Value: "legacy-threat.com"}})
	if err != nil {
		t.Fatalf("LookupIndicators: %v", err)
	}
	if len(inds) != 1 || inds[0].Value != "legacy-threat.com" {
		t.Errorf("expected preserved indicator, got: %+v", inds)
	}
}
