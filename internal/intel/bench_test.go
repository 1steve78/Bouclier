package intel

import (
	"context"
	"strings"
	"testing"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/storage"
)

func BenchmarkNormalizeIndicatorDomain(b *testing.B) {
	domainVal := "sub.login-portal.evil-domain.co.uk"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NormalizeIndicator(TypeDomain, domainVal)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizeIndicatorURL(b *testing.B) {
	urlVal := "https://phishing-site.example.org/login/index.php?token=xyz123"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NormalizeIndicator(TypeURL, urlVal)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseJSONIndicators_100Records(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("[\n")
	for i := 0; i < 100; i++ {
		if i > 0 {
			sb.WriteString(",\n")
		}
		sb.WriteString(`{"type":"domain","value":"threat-`)
		sb.WriteString(string(rune('a' + (i % 26))))
		sb.WriteString(`.example.com","category":"phishing","confidence":90,"severity":"high"}`)
	}
	sb.WriteString("\n]")
	payload := sb.String()

	cfg := SourceConfig{ID: "bench-source", Name: "Bench Source"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := ParseIndicators(strings.NewReader(payload), "json", cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseCSVIndicators_100Rows(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("type,value,category,confidence,severity,description\n")
	for i := 0; i < 100; i++ {
		sb.WriteString(`domain,phish-`)
		sb.WriteString(string(rune('a' + (i % 26))))
		sb.WriteString(`.badsite.org,phishing,85,high,Test threat\n`)
	}
	payload := sb.String()

	cfg := SourceConfig{ID: "bench-csv", Name: "Bench CSV"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := ParseIndicators(strings.NewReader(payload), "csv", cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchTarget(b *testing.B) {
	norm, err := heuristics.NormalizeURL("https://threat-site.example.com/login")
	if err != nil {
		b.Fatal(err)
	}
	domainInfo, _ := heuristics.ExtractDomainInfo(norm)
	coords := ExtractCoordinates(norm, domainInfo, []string{"198.51.100.5"})

	db, err := storage.Open(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_ = db.RegisterSource(ctx, storage.IntelSource{
		ID:           "feed-1",
		Name:         "Feed 1",
		ProviderType: "local_file",
		Endpoint:     "/dev/null",
		Enabled:      true,
	})
	now := time.Now().UTC()
	_, _, _ = db.SaveIndicatorBatch(ctx, "feed-1", []storage.IntelIndicator{
		{
			ID:         "ind-1",
			SourceID:   "feed-1",
			SourceName: "Feed 1",
			Type:       "domain",
			Value:      "threat-site.example.com",
			Category:   "phishing",
			Confidence: 95,
			Severity:   "critical",
			IngestedAt: now,
		},
	})

	matcher := NewMatcher(db)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := matcher.MatchTarget(ctx, coords)
		if err != nil {
			b.Fatal(err)
		}
	}
}
