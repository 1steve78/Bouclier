package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"bouclier/internal/risk"
	"github.com/google/uuid"
)

func BenchmarkSaveScan(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench_save.db")
	db, err := Open(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	assessment := &risk.RiskAssessment{
		SchemaVersion:  "bouclier-risk/v1",
		Target:         "https://example.com/bench",
		AnalyzedAt:     time.Now().UTC(),
		OverallScore:   42,
		Classification: risk.RiskGuarded,
		PolicyID:       "bouclier-default",
		PolicyVersion:  "1",
		Findings:       []risk.NormalizedFinding{},
		SeverityCounts: []risk.SeverityCount{},
		ScoringMethod:  "weighted-sum-capped",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := ScanRecord{
			ID:             uuid.NewString(),
			Target:         "https://example.com/bench",
			StartedAt:      time.Now().UTC(),
			CompletedAt:    time.Now().UTC(),
			DurationMs:     25,
			OverallScore:   42,
			Classification: risk.RiskGuarded,
			PolicyID:       "bouclier-default",
			PolicyVersion:  "1",
			Status:         StatusCompleted,
			SchemaVersion:  "bouclier-risk/v1",
			CreatedAt:      time.Now().UTC(),
		}
		if err := db.SaveScan(ctx, rec, assessment); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetScan(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench_get.db")
	db, err := Open(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	scanID := uuid.NewString()
	rec := ScanRecord{
		ID:             scanID,
		Target:         "https://example.com/target",
		StartedAt:      time.Now().UTC(),
		CompletedAt:    time.Now().UTC(),
		DurationMs:     30,
		OverallScore:   10,
		Classification: risk.RiskLow,
		PolicyID:       "bouclier-default",
		PolicyVersion:  "1",
		Status:         StatusCompleted,
		SchemaVersion:  "bouclier-risk/v1",
		CreatedAt:      time.Now().UTC(),
	}
	if err := db.SaveScan(ctx, rec, nil); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := db.GetScan(ctx, scanID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkLookupScale(b *testing.B, count int) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("bench_scale_%d.db", count))
	db, err := Open(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	srcID := "scale-feed"
	_ = db.RegisterSource(ctx, IntelSource{
		ID:           srcID,
		Name:         "Scale Feed",
		ProviderType: "local_file",
		Endpoint:     "/dev/null",
		Enabled:      true,
		Format:       "json",
	})

	indicators := make([]IntelIndicator, 0, count)
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		indicators = append(indicators, IntelIndicator{
			ID:         fmt.Sprintf("scale-%d", i),
			SourceID:   srcID,
			SourceName: "Scale Feed",
			Type:       "domain",
			Value:      fmt.Sprintf("threat-site-%d.example.com", i),
			Category:   "phishing",
			Confidence: 90,
			Severity:   "high",
			IngestedAt: now,
		})
	}
	_, _, err = db.SaveIndicatorBatch(ctx, srcID, indicators)
	if err != nil {
		b.Fatal(err)
	}

	queries := []IndicatorQuery{
		{Type: "domain", Value: fmt.Sprintf("threat-site-%d.example.com", count/2)},
		{Type: "domain", Value: "non-existent-threat-domain.org"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := db.LookupIndicatorsAt(ctx, queries, now)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLookupIndicators_100(b *testing.B) {
	benchmarkLookupScale(b, 100)
}

func BenchmarkLookupIndicators_1000(b *testing.B) {
	benchmarkLookupScale(b, 1000)
}

func BenchmarkLookupIndicators_5000(b *testing.B) {
	benchmarkLookupScale(b, 5000)
}
