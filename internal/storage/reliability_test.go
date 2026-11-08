package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"bouclier/internal/risk"
	"github.com/google/uuid"
)

func createTestAssessment(score int) *risk.RiskAssessment {
	return &risk.RiskAssessment{
		SchemaVersion:  "bouclier-risk/v1",
		Target:         "https://example.com/test",
		AnalyzedAt:     time.Now().UTC(),
		OverallScore:   score,
		Classification: risk.RiskLow,
		PolicyID:       "bouclier-default",
		PolicyVersion:  "1",
		Findings: []risk.NormalizedFinding{
			{
				Code:             "TEST_FINDING",
				Title:            "Test Finding",
				Description:      "A synthetic finding for concurrency testing.",
				Severity:         risk.SeverityLow,
				Confidence:       risk.ConfidenceHigh,
				Classification:   risk.FindingClassified,
				ScoreImpact:      score,
				DeduplicationKey: "test-finding-key",
			},
		},
		SeverityCounts: []risk.SeverityCount{
			{Severity: risk.SeverityLow, Count: 1},
		},
		CategoryContributions: []risk.CategoryContribution{
			{Category: "test", Score: score, Cap: 50},
		},
		AnalysisCoverage: []risk.ComponentCoverage{
			{Component: "test", State: risk.ComponentCompleted},
		},
		ScoringMethod: "weighted-sum-capped",
	}
}

func TestConcurrentScansWritingHistory(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_scans.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	concurrency := 10
	scansPerGoroutine := 10
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency*scansPerGoroutine)

	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-start // Align goroutine launch

			for j := 0; j < scansPerGoroutine; j++ {
				scanID := uuid.NewString()
				rec := ScanRecord{
					ID:             scanID,
					Target:         fmt.Sprintf("https://worker%d-scan%d.example.com", workerID, j),
					StartedAt:      time.Now().UTC(),
					CompletedAt:    time.Now().UTC(),
					DurationMs:     50,
					OverallScore:   workerID * 5,
					Classification: risk.RiskLow,
					PolicyID:       "bouclier-default",
					PolicyVersion:  "1",
					Status:         StatusCompleted,
					SchemaVersion:  "bouclier-risk/v1",
					CreatedAt:      time.Now().UTC(),
				}
				assessment := createTestAssessment(rec.OverallScore)

				if err := db.SaveScan(ctx, rec, assessment); err != nil {
					errCh <- fmt.Errorf("worker %d save scan %d: %w", workerID, j, err)
				}
			}
		}(i)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent save error: %v", err)
	}

	count, err := db.CountScans(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("CountScans failed: %v", err)
	}
	expectedCount := concurrency * scansPerGoroutine
	if count != expectedCount {
		t.Fatalf("expected %d scans in database, got %d", expectedCount, count)
	}
}

func TestConcurrentIndicatorSyncAndLookups(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_intel.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	srcID := "concurrent-feed"
	err = db.RegisterSource(ctx, IntelSource{
		ID:           srcID,
		Name:         "Concurrent Feed",
		ProviderType: "local_file",
		Endpoint:     "/dev/null",
		Enabled:      true,
		Format:       "json",
	})
	if err != nil {
		t.Fatalf("RegisterSource: %v", err)
	}

	var wg sync.WaitGroup
	readers := 8
	writers := 4
	stop := make(chan struct{})
	errCh := make(chan error, readers+writers)

	// Writers: repeatedly upserting batches
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stop:
					return
				default:
					i++
					batch := []IntelIndicator{
						{
							ID:         fmt.Sprintf("ind-%d-%d", workerID, i%20),
							SourceID:   srcID,
							SourceName: "Concurrent Feed",
							Type:       "domain",
							Value:      fmt.Sprintf("threat-%d-%d.com", workerID, i%20),
							Category:   "phishing",
							Confidence: 85,
							Severity:   "high",
							IngestedAt: time.Now().UTC(),
							Metadata:   map[string]string{},
						},
					}
					_, _, err := db.SaveIndicatorBatch(ctx, srcID, batch)
					if err != nil {
						errCh <- fmt.Errorf("writer %d batch %d: %w", workerID, i, err)
						return
					}
				}
			}
		}(w)
	}

	// Readers: repeatedly looking up indicators
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stop:
					return
				default:
					i++
					queries := []IndicatorQuery{
						{Type: "domain", Value: fmt.Sprintf("threat-%d-%d.com", readerID%writers, i%20)},
					}
					_, err := db.LookupIndicatorsAt(ctx, queries, time.Now().UTC())
					if err != nil {
						errCh <- fmt.Errorf("reader %d query %d: %w", readerID, i, err)
						return
					}
				}
			}
		}(r)
	}

	// Let concurrency run for 200 milliseconds
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent intel operation failed: %v", err)
	}
}

func TestTransactionRollbackPreservesIntegrity(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "rollback_test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	sqlDB, err := db.SQLDB()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Begin manual transaction
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO scans (id, target, started_at, completed_at, duration_ms, overall_score, classification, status, created_at)
VALUES ('rollback-scan-1', 'https://rollback.example.com', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 10, 0, 'low', 'completed', '2026-01-01T00:00:00Z')
`)
	if err != nil {
		t.Fatal(err)
	}

	// Rollback transaction
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	// Verify scan does not exist
	_, err = db.GetScan(ctx, "rollback-scan-1")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after rollback, got: %v", err)
	}
}

func TestContextCancellationAbortsStorageOperation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "cancel_storage.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	rec := ScanRecord{
		ID:        "cancelled-scan",
		Target:    "https://cancelled.example.com",
		CreatedAt: time.Now().UTC(),
	}

	err = db.SaveScan(cancelCtx, rec, nil)
	if err == nil {
		t.Fatalf("expected error on cancelled context, got nil")
	}
}

func TestMalformedStoredReportHandling(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "malformed_report.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	sqlDB, err := db.SQLDB()
	if err != nil {
		t.Fatal(err)
	}

	scanID := "corrupted-report-scan"
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Insert scan and intentionally corrupt JSON report in database
	_, err = sqlDB.ExecContext(ctx, `
INSERT INTO scans (id, target, started_at, completed_at, duration_ms, overall_score, classification, status, created_at)
VALUES (?, 'https://corrupt.example.com', ?, ?, 10, 0, 'low', 'completed', ?);
`, scanID, now, now, now)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sqlDB.ExecContext(ctx, `
INSERT INTO scan_reports (scan_id, report_json, created_at, report_hash)
VALUES (?, '{"schema_version": "bouclier-risk/v1", corrupt_json...', ?, '0xinvalid');
`, scanID, now)
	if err != nil {
		t.Fatal(err)
	}

	// GetScanReport should succeed without panic, returning raw ReportJSON with Assessment == nil
	report, err := db.GetScanReport(ctx, scanID)
	if err != nil {
		t.Fatalf("expected GetScanReport to succeed, got: %v", err)
	}
	if report.Assessment != nil {
		t.Errorf("expected Assessment to be nil for malformed JSON")
	}
	if !strings.Contains(report.ReportJSON, "corrupt_json") {
		t.Errorf("expected ReportJSON to retain raw string, got: %s", report.ReportJSON)
	}

	// GetScanEntry should also succeed safely without panic
	entry, err := db.GetScanEntry(ctx, scanID)
	if err != nil {
		t.Fatalf("expected GetScanEntry to succeed, got: %v", err)
	}
	if entry.Assessment != nil {
		t.Errorf("expected Assessment to be nil for malformed JSON")
	}
	if entry.Record.ID != scanID {
		t.Errorf("expected Record ID %s, got %s", scanID, entry.Record.ID)
	}
}

func TestDatabaseReopenAfterInterruption(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "reopen_test.db")

	db1, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	rec := ScanRecord{
		ID:        "surviving-scan-1",
		Target:    "https://survive.example.com",
		CreatedAt: time.Now().UTC(),
	}
	if err := db1.SaveScan(ctx, rec, nil); err != nil {
		t.Fatal(err)
	}
	db1.Close()

	// Reopen database
	db2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen database: %v", err)
	}
	defer db2.Close()

	got, err := db2.GetScan(ctx, "surviving-scan-1")
	if err != nil {
		t.Fatalf("failed to get scan after reopen: %v", err)
	}
	if got.ID != "surviving-scan-1" {
		t.Errorf("expected ID surviving-scan-1, got %s", got.ID)
	}
}
