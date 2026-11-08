package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"bouclier/internal/risk"
)

func sampleAssessment(target string, score int, classification risk.RiskClass) *risk.RiskAssessment {
	return &risk.RiskAssessment{
		SchemaVersion:  "bouclier-risk/v1",
		Target:         target,
		AnalyzedAt:     time.Now().UTC(),
		OverallScore:   score,
		Classification: classification,
		PolicyID:       "bouclier-default",
		PolicyVersion:  "1.0",
		Findings: []risk.NormalizedFinding{
			{
				Code:        "URL_TEST_FINDING",
				Title:       "Test finding title",
				Description: "Test finding description",
				Severity:    risk.SeverityLow,
				Confidence:  risk.ConfidenceHigh,
				ScoreImpact: 6,
			},
		},
		AnalysisCoverage: []risk.ComponentCoverage{
			{Component: "url_analysis", State: risk.ComponentCompleted},
		},
	}
}

func TestDatabaseInitAndMigration(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	defer db.Close()

	sqlDB, err := db.SQLDB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}

	var version int
	err = sqlDB.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query migration version: %v", err)
	}
	if version < 1 {
		t.Fatalf("expected migration version >= 1, got %d", version)
	}
}

func TestSaveAndGetScan(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	assessment := sampleAssessment("https://example.com", 25, risk.RiskGuarded)

	rec := ScanRecord{
		ID:             "scan-test-12345678-abcd",
		Target:         "https://example.com",
		StartedAt:      time.Now().UTC().Add(-2 * time.Second),
		CompletedAt:    time.Now().UTC(),
		DurationMs:     2000,
		OverallScore:   25,
		Classification: risk.RiskGuarded,
		PolicyID:       "bouclier-default",
		PolicyVersion:  "1.0",
		Status:         StatusCompleted,
		SchemaVersion:  "bouclier-risk/v1",
	}

	if err := db.SaveScan(ctx, rec, assessment); err != nil {
		t.Fatalf("save scan: %v", err)
	}

	// 1. Get by exact ID
	got, err := db.GetScan(ctx, rec.ID)
	if err != nil {
		t.Fatalf("get scan exact: %v", err)
	}
	if got.ID != rec.ID || got.Target != rec.Target || got.OverallScore != 25 {
		t.Fatalf("retrieved scan mismatch: %+v", got)
	}

	// 2. Get by short prefix
	prefix := "scan-test-1234"
	gotPrefix, err := db.GetScan(ctx, prefix)
	if err != nil {
		t.Fatalf("get scan prefix: %v", err)
	}
	if gotPrefix.ID != rec.ID {
		t.Fatalf("expected %s, got %s", rec.ID, gotPrefix.ID)
	}

	// 3. Get report and verify assessment deserialization
	rep, err := db.GetScanReport(ctx, rec.ID)
	if err != nil {
		t.Fatalf("get report: %v", err)
	}
	if rep.Assessment == nil {
		t.Fatal("expected unmarshaled assessment in report, got nil")
	}
	if rep.Assessment.OverallScore != 25 || rep.Assessment.Target != "https://example.com" {
		t.Fatalf("deserialized assessment mismatch: %+v", rep.Assessment)
	}
	if rep.ReportHash == "" {
		t.Fatal("expected a stored report integrity hash")
	}

	// 4. GetScanEntry
	entry, err := db.GetScanEntry(ctx, prefix)
	if err != nil {
		t.Fatalf("get scan entry: %v", err)
	}
	if entry.Record.ID != rec.ID || entry.Assessment == nil || entry.Assessment.OverallScore != 25 {
		t.Fatalf("scan entry mismatch: %+v", entry)
	}
}

func TestDuplicateScanRejection(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	rec := ScanRecord{
		ID:     "dup-id-001",
		Target: "https://dup.com",
	}
	if err := db.SaveScan(ctx, rec, nil); err != nil {
		t.Fatal(err)
	}

	// Re-saving same ID must fail with ErrDuplicateScan
	err = db.SaveScan(ctx, rec, nil)
	if err == nil || !errors.Is(err, ErrDuplicateScan) {
		t.Fatalf("expected ErrDuplicateScan, got %v", err)
	}
}

func TestAmbiguousIDPrefix(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_ = db.SaveScan(ctx, ScanRecord{ID: "prefix-match-001", Target: "https://a.com"}, nil)
	_ = db.SaveScan(ctx, ScanRecord{ID: "prefix-match-002", Target: "https://b.com"}, nil)

	_, err = db.GetScan(ctx, "prefix-match")
	if err == nil || !errors.Is(err, ErrAmbiguousID) {
		t.Fatalf("expected ErrAmbiguousID for common prefix, got %v", err)
	}

	// But exact match still succeeds
	got, err := db.GetScan(ctx, "prefix-match-001")
	if err != nil || got.ID != "prefix-match-001" {
		t.Fatalf("expected exact match to succeed, got %v, err: %v", got, err)
	}
}

func TestListAndFiltering(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	scans := []ScanRecord{
		{ID: "id-1", Target: "https://alpha.example.com", OverallScore: 10, Classification: risk.RiskLow, StartedAt: time.Now().Add(-30 * time.Minute)},
		{ID: "id-2", Target: "https://beta.security.org", OverallScore: 45, Classification: risk.RiskElevated, StartedAt: time.Now().Add(-20 * time.Minute)},
		{ID: "id-3", Target: "https://gamma.phish.cc", OverallScore: 85, Classification: risk.RiskCritical, StartedAt: time.Now().Add(-10 * time.Minute)},
		{ID: "id-4", Target: "https://delta.example.com", OverallScore: 0, Classification: risk.RiskLow, StartedAt: time.Now().Add(-5 * time.Minute)},
	}

	for _, s := range scans {
		if err := db.SaveScan(ctx, s, nil); err != nil {
			t.Fatalf("save %s: %v", s.ID, err)
		}
	}

	// 1. List all (default sort started_at DESC)
	list, err := db.ListScans(ctx, ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("expected 4 scans, got %d", len(list))
	}
	if list[0].ID != "id-4" || list[3].ID != "id-1" {
		t.Fatalf("expected id-4 first (most recent), got %s", list[0].ID)
	}

	// 2. Filter by Target substring
	list, err = db.ListScans(ctx, ListFilter{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 matches for example.com, got %d", len(list))
	}

	// 3. Filter by Classification
	list, err = db.ListScans(ctx, ListFilter{Classification: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "id-3" {
		t.Fatalf("expected 1 critical scan (id-3), got %v", list)
	}

	// 4. Filter by MinScore / MaxScore
	minScore := 40
	maxScore := 90
	list, err = db.ListScans(ctx, ListFilter{MinScore: &minScore, MaxScore: &maxScore})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 { // id-2 (45) and id-3 (85)
		t.Fatalf("expected 2 scans between 40-90, got %d", len(list))
	}

	// 5. Pagination (Limit 2, Offset 1)
	list, err = db.ListScans(ctx, ListFilter{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "id-3" || list[1].ID != "id-2" {
		t.Fatalf("unexpected paginated result: %+v", list)
	}

	// 6. CountScans
	count, err := db.CountScans(ctx, ListFilter{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
}

func TestFilterValidation(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()

	// Negative offset
	_, err = db.ListScans(ctx, ListFilter{Offset: -1})
	if err == nil || !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("expected ErrInvalidFilter for negative offset, got %v", err)
	}

	// Score > 100
	invalidScore := 105
	_, err = db.ListScans(ctx, ListFilter{MinScore: &invalidScore})
	if err == nil || !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("expected ErrInvalidFilter for score > 100, got %v", err)
	}

	// MinScore > MaxScore
	min := 50
	max := 20
	_, err = db.ListScans(ctx, ListFilter{MinScore: &min, MaxScore: &max})
	if err == nil || !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("expected ErrInvalidFilter for min > max, got %v", err)
	}
}

func TestDeleteScanCascade(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	rec := ScanRecord{ID: "del-test-12345", Target: "https://delete.me"}
	if err := db.SaveScan(ctx, rec, sampleAssessment(rec.Target, 10, risk.RiskLow)); err != nil {
		t.Fatal(err)
	}

	// Delete by prefix
	if err := db.DeleteScan(ctx, "del-test"); err != nil {
		t.Fatalf("delete scan: %v", err)
	}

	// Verify scan record deleted
	_, err = db.GetScan(ctx, rec.ID)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for deleted scan, got %v", err)
	}

	// Verify scan report cascaded
	_, err = db.GetScanReport(ctx, rec.ID)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cascaded report, got %v", err)
	}

	// Deleting non-existent scan returns ErrNotFound
	err = db.DeleteScan(ctx, "nonexistent-id")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting non-existent ID, got %v", err)
	}
}

func TestConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concurrent.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	workers := 10

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				rec := ScanRecord{
					Target:       "https://concurrent.test",
					OverallScore: workerID*10 + j,
				}
				if err := db.SaveScan(ctx, rec, nil); err != nil {
					t.Errorf("worker %d save error: %v", workerID, err)
				}
			}
		}(i)
	}
	wg.Wait()

	count, err := db.CountScans(ctx, ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != workers*5 {
		t.Fatalf("expected %d total records, got %d", workers*5, count)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist.db")

	// Phase 1: Open and write
	db1, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	rec := ScanRecord{
		ID:           "reopen-scan-001",
		Target:       "https://reopen.test",
		OverallScore: 42,
	}
	if err := db1.SaveScan(context.Background(), rec, sampleAssessment(rec.Target, 42, risk.RiskElevated)); err != nil {
		t.Fatal(err)
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	// Phase 2: Re-open same file
	db2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db2.Close()

	got, err := db2.GetScan(context.Background(), rec.ID)
	if err != nil {
		t.Fatalf("get scan after reopen: %v", err)
	}
	if got.ID != rec.ID || got.OverallScore != 42 {
		t.Fatalf("unexpected scan after reopen: %+v", got)
	}
}

func TestScoreFilterInclusiveBoundaries(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_ = db.SaveScan(ctx, ScanRecord{ID: "scan-30", Target: "https://site-30.org", OverallScore: 30}, nil)
	_ = db.SaveScan(ctx, ScanRecord{ID: "scan-50", Target: "https://site-50.org", OverallScore: 50}, nil)
	_ = db.SaveScan(ctx, ScanRecord{ID: "scan-70", Target: "https://site-70.org", OverallScore: 70}, nil)

	// 1. MinScore exactly 50 matches 50 and 70 (inclusive)
	score50 := 50
	list, err := db.ListScans(ctx, ListFilter{MinScore: &score50})
	if err != nil || len(list) != 2 {
		t.Fatalf("expected 2 scans with MinScore=50, got %d (err: %v)", len(list), err)
	}

	// 2. MaxScore exactly 50 matches 30 and 50 (inclusive)
	list, err = db.ListScans(ctx, ListFilter{MaxScore: &score50})
	if err != nil || len(list) != 2 {
		t.Fatalf("expected 2 scans with MaxScore=50, got %d (err: %v)", len(list), err)
	}

	// 3. MinScore=50 AND MaxScore=50 matches only 50
	list, err = db.ListScans(ctx, ListFilter{MinScore: &score50, MaxScore: &score50})
	if err != nil || len(list) != 1 || list[0].ID != "scan-50" {
		t.Fatalf("expected exactly scan-50, got: %+v (err: %v)", list, err)
	}

	// 4. MinScore=51 excludes 50
	score51 := 51
	list, err = db.ListScans(ctx, ListFilter{MinScore: &score51})
	if err != nil || len(list) != 1 || list[0].ID != "scan-70" {
		t.Fatalf("expected only scan-70 with MinScore=51, got: %+v", list)
	}

	// 5. MaxScore=49 excludes 50
	score49 := 49
	list, err = db.ListScans(ctx, ListFilter{MaxScore: &score49})
	if err != nil || len(list) != 1 || list[0].ID != "scan-30" {
		t.Fatalf("expected only scan-30 with MaxScore=49, got: %+v", list)
	}
}

func TestMalformedReportJSONHandling(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	sqlDB, err := db.SQLDB()
	if err != nil {
		t.Fatal(err)
	}

	// Insert scan record directly
	recID := "malformed-json-scan"
	_, err = sqlDB.ExecContext(ctx, `INSERT INTO scans (id, target, started_at, completed_at, duration_ms, overall_score, classification, status, created_at)
		VALUES (?, 'https://malformed.org', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 100, 20, 'low', 'completed', '2026-01-01T00:00:00Z')`, recID)
	if err != nil {
		t.Fatal(err)
	}

	// Insert corrupt report_json
	corruptJSON := `{"schema_version": "bouclier-risk/v1", "incomplete_json": `
	_, err = sqlDB.ExecContext(ctx, `INSERT INTO scan_reports (scan_id, report_json, created_at) VALUES (?, ?, '2026-01-01T00:00:00Z')`, recID, corruptJSON)
	if err != nil {
		t.Fatal(err)
	}

	// GetScanReport should not crash or panic; returns report with Assessment=nil
	rep, err := db.GetScanReport(ctx, recID)
	if err != nil {
		t.Fatalf("expected GetScanReport to succeed, got %v", err)
	}
	if rep.ReportJSON != corruptJSON {
		t.Fatalf("expected raw corrupt JSON preserved, got %s", rep.ReportJSON)
	}
	if rep.Assessment != nil {
		t.Fatal("expected Assessment to be nil for malformed JSON")
	}

	// GetScanEntry should succeed with Assessment=nil
	entry, err := db.GetScanEntry(ctx, recID)
	if err != nil {
		t.Fatalf("GetScanEntry failed: %v", err)
	}
	if entry.Assessment != nil {
		t.Fatal("expected entry.Assessment to be nil for malformed JSON")
	}
}

func TestForeignKeyEnforcement(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sqlDB, err := db.SQLDB()
	if err != nil {
		t.Fatal(err)
	}

	// Try inserting a scan_report referencing non-existent scan_id
	_, err = sqlDB.ExecContext(context.Background(), `INSERT INTO scan_reports (scan_id, report_json, created_at) VALUES ('non-existent-scan', '{}', '2026-01-01T00:00:00Z')`)
	if err == nil {
		t.Fatal("expected foreign key constraint violation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("expected foreign key error, got: %v", err)
	}
}

func TestMigrationRollbackOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "migration_rollback.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sqlDB, err := db.SQLDB()
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to apply a bogus migration that fails midway
	badMigration := migration{
		Version:     999,
		Description: "bogus migration",
		SQL:         `CREATE TABLE table_ok (id INT); INVALID SQL SYNTAX HERE;`,
	}
	ctx := context.Background()
	err = applyMigration(ctx, sqlDB, badMigration)
	if err == nil {
		t.Fatal("expected migration failure")
	}

	// Verify rollback: table_ok must NOT exist
	var tableName string
	err = sqlDB.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='table_ok'`).Scan(&tableName)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected table_ok to be rolled back, got table: %s (err: %v)", tableName, err)
	}

	// Verify version 999 was NOT recorded in schema_migrations
	var versionCount int
	_ = sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=999`).Scan(&versionCount)
	if versionCount != 0 {
		t.Fatalf("expected version 999 not recorded, count=%d", versionCount)
	}
}
