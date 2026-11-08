package intel

import (
	"context"
	"testing"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
)

func TestIntelligenceMatching(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Register source
	src := storage.IntelSource{
		ID:           "test-source",
		Name:         "Community Threat Feed",
		ProviderType: "local_file",
		Endpoint:     "/data.json",
		Enabled:      true,
	}
	if err := db.RegisterSource(ctx, src); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	freshTime := now.Add(-2 * 24 * time.Hour)
	staleTime := now.Add(-120 * 24 * time.Hour)
	future := now.Add(48 * time.Hour)
	past := now.Add(-24 * time.Hour)

	indicators := []storage.IntelIndicator{
		{
			ID:         "ind-url",
			Type:       string(TypeURL),
			Value:      "https://phish.example.com/login",
			Category:   "credential-theft",
			Confidence: 95,
			Severity:   string(risk.SeverityCritical),
			LastSeen:   &freshTime,
			ExpiresAt:  &future,
		},
		{
			ID:         "ind-domain",
			Type:       string(TypeDomain),
			Value:      "bad-host.phish.example.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   string(risk.SeverityHigh),
			LastSeen:   &freshTime,
			ExpiresAt:  &future,
		},
		{
			ID:         "ind-reg-domain",
			Type:       string(TypeDomain),
			Value:      "malicious-domain.com",
			Category:   "malware",
			Confidence: 85,
			Severity:   string(risk.SeverityHigh),
			LastSeen:   &staleTime, // Stale!
			ExpiresAt:  &future,
		},
		{
			ID:         "ind-ip",
			Type:       string(TypeIPv4),
			Value:      "198.51.100.99",
			Category:   "c2",
			Confidence: 80,
			Severity:   string(risk.SeverityHigh),
			LastSeen:   &freshTime,
			ExpiresAt:  &future,
		},
		{
			ID:         "ind-expired",
			Type:       string(TypeDomain),
			Value:      "expired-threat.com",
			Category:   "phishing",
			Confidence: 99,
			Severity:   string(risk.SeverityCritical),
			LastSeen:   &past,
			ExpiresAt:  &past, // Expired!
		},
	}

	if _, _, err := db.SaveIndicatorBatch(ctx, "test-source", indicators); err != nil {
		t.Fatal(err)
	}

	matcher := NewMatcher(db)

	// Test 1: Exact URL match
	normURL, _ := heuristics.NormalizeURL("https://phish.example.com/login")
	coords1 := ExtractCoordinates(normURL, nil, nil)
	summary1, err := matcher.MatchTarget(ctx, coords1)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(summary1.Matches) != 1 {
		t.Fatalf("expected 1 match for URL, got %d", len(summary1.Matches))
	}
	if summary1.Matches[0].MatchType != MatchExactURL {
		t.Errorf("expected MatchExactURL, got %v", summary1.Matches[0].MatchType)
	}
	if summary1.Matches[0].Freshness != "fresh" {
		t.Errorf("expected fresh indicator, got %s", summary1.Matches[0].Freshness)
	}

	// Test 2: Substring non-match: URL with different path should NOT match
	diffURL, _ := heuristics.NormalizeURL("https://phish.example.com/other-safe-path")
	coords2 := ExtractCoordinates(diffURL, nil, nil)
	summary2, err := matcher.MatchTarget(ctx, coords2)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(summary2.Matches) != 0 {
		t.Errorf("expected 0 matches for non-matching path, got %d", len(summary2.Matches))
	}

	// Test 3: Registrable domain match (with stale classification)
	subURL, _ := heuristics.NormalizeURL("https://login.secure.malicious-domain.com/index.html")
	domainInfo, _ := heuristics.ExtractDomainInfo(subURL)
	coords3 := ExtractCoordinates(subURL, domainInfo, nil)
	summary3, err := matcher.MatchTarget(ctx, coords3)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(summary3.Matches) != 1 {
		t.Fatalf("expected 1 match for registrable domain, got %d", len(summary3.Matches))
	}
	if summary3.Matches[0].MatchType != MatchRegistrableDomain {
		t.Errorf("expected MatchRegistrableDomain, got %v", summary3.Matches[0].MatchType)
	}
	if summary3.Matches[0].Freshness != "stale" {
		t.Errorf("expected stale indicator, got %s", summary3.Matches[0].Freshness)
	}

	// Test 4: Substring non-match on domain (e.g. not-malicious-domain.com should NOT match)
	unrelatedURL, _ := heuristics.NormalizeURL("https://not-malicious-domain.com")
	unrelatedDomainInfo, _ := heuristics.ExtractDomainInfo(unrelatedURL)
	coords4 := ExtractCoordinates(unrelatedURL, unrelatedDomainInfo, nil)
	summary4, err := matcher.MatchTarget(ctx, coords4)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(summary4.Matches) != 0 {
		t.Errorf("expected 0 matches for unrelated domain, got %d", len(summary4.Matches))
	}

	// Test 5: Exact IP match
	ipURL, _ := heuristics.NormalizeURL("https://example.org")
	coords5 := ExtractCoordinates(ipURL, nil, []string{"198.51.100.99"})
	summary5, err := matcher.MatchTarget(ctx, coords5)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(summary5.Matches) != 1 {
		t.Fatalf("expected 1 match for IP, got %d", len(summary5.Matches))
	}
	if summary5.Matches[0].MatchType != MatchExactIP {
		t.Errorf("expected MatchExactIP, got %v", summary5.Matches[0].MatchType)
	}

	// Test 6: Expired indicator must NOT match
	expURL, _ := heuristics.NormalizeURL("https://expired-threat.com")
	expInfo, _ := heuristics.ExtractDomainInfo(expURL)
	coords6 := ExtractCoordinates(expURL, expInfo, nil)
	summary6, err := matcher.MatchTarget(ctx, coords6)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(summary6.Matches) != 0 {
		t.Errorf("expected 0 matches for expired indicator, got %d", len(summary6.Matches))
	}
}

func TestNilRepositoryMatcher(t *testing.T) {
	matcher := NewMatcher(nil)
	summary, err := matcher.MatchTarget(context.Background(), TargetCoordinates{NormalizedURL: "https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error with nil repo: %v", err)
	}
	if !summary.DatabaseUnavailable {
		t.Errorf("expected DatabaseUnavailable to be true")
	}
	if len(summary.Matches) != 0 {
		t.Errorf("expected 0 matches")
	}
}

func TestIndicatorFreshnessAndExpirationBoundaries(t *testing.T) {
	refTime := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

	// 1. Indicator expired 1 second ago
	expPast := refTime.Add(-1 * time.Second)
	indExpired := Indicator{
		Type:      TypeDomain,
		Value:     "expired-1s.com",
		ExpiresAt: &expPast,
	}
	if !indExpired.IsExpired(refTime) {
		t.Errorf("expected indicator expiring 1s ago to be expired")
	}

	// 2. Indicator expiring 1 second in future
	expFuture := refTime.Add(1 * time.Second)
	indActive := Indicator{
		Type:      TypeDomain,
		Value:     "active-1s.com",
		ExpiresAt: &expFuture,
	}
	if indActive.IsExpired(refTime) {
		t.Errorf("expected indicator expiring 1s in future to NOT be expired")
	}

	// 3. Indicator with no expiration (nil)
	indIndefinite := Indicator{
		Type:      TypeDomain,
		Value:     "no-expiration.com",
		ExpiresAt: nil,
	}
	if indIndefinite.IsExpired(refTime) {
		t.Errorf("expected indicator with nil ExpiresAt to NOT be expired")
	}

	// 4. Indicator expiring at exact reference time (expires_at <= refTime -> expired)
	expExact := refTime
	indExact := Indicator{
		Type:      TypeDomain,
		Value:     "exact-expired.com",
		ExpiresAt: &expExact,
	}
	if !indExact.IsExpired(refTime) {
		t.Errorf("expected indicator expiring at exact reference time to be expired")
	}

	// 5. Stale indicator at exactly the stale threshold (last_seen == ref - 90d -> fresh)
	lastSeenExact90d := refTime.Add(-90 * 24 * time.Hour)
	indExact90d := Indicator{
		Type:     TypeDomain,
		Value:    "boundary-90d.com",
		LastSeen: &lastSeenExact90d,
	}
	freshnessExact := CalculateFreshness(indExact90d, refTime)
	if freshnessExact != "fresh" {
		t.Errorf("expected indicator at exact 90-day threshold to be 'fresh', got %s", freshnessExact)
	}

	// 6. Stale indicator 1 second past the stale threshold (last_seen < ref - 90d -> stale)
	lastSeenPast90d := refTime.Add(-90*24*time.Hour - 1*time.Second)
	indStale := Indicator{
		Type:     TypeDomain,
		Value:    "stale.com",
		LastSeen: &lastSeenPast90d,
	}
	freshnessStale := CalculateFreshness(indStale, refTime)
	if freshnessStale != "stale" {
		t.Errorf("expected indicator older than 90 days to be 'stale', got %s", freshnessStale)
	}

	// 7. Fresh indicator 1 second newer than 90 days (last_seen > ref - 90d -> fresh)
	lastSeenWithin90d := refTime.Add(-90*24*time.Hour + 1*time.Second)
	indFreshBoundary := Indicator{
		Type:     TypeDomain,
		Value:    "fresh-boundary.com",
		LastSeen: &lastSeenWithin90d,
	}
	freshnessBoundary := CalculateFreshness(indFreshBoundary, refTime)
	if freshnessBoundary != "fresh" {
		t.Errorf("expected indicator at 90d-1s boundary to be 'fresh', got %s", freshnessBoundary)
	}
}

func TestMatchingWithDeterministicTimeBoundaries(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	_ = db.RegisterSource(ctx, storage.IntelSource{
		ID:           "boundary-source",
		Name:         "Boundary Source",
		ProviderType: "local_file",
		Endpoint:     "/data.json",
		Enabled:      true,
	})

	tRef := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	expPast := tRef.Add(-1 * time.Second)
	expFuture := tRef.Add(1 * time.Second)
	lastSeenExact90d := tRef.Add(-90 * 24 * time.Hour)
	lastSeenPast90d := tRef.Add(-90*24*time.Hour - 1*time.Second)
	lastSeenWithin90d := tRef.Add(-90*24*time.Hour + 1*time.Second)

	inds := []storage.IntelIndicator{
		{
			ID:         "ind-exp-past",
			SourceID:   "boundary-source",
			Type:       string(TypeDomain),
			Value:      "expired-just-now.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   string(risk.SeverityHigh),
			ExpiresAt:  &expPast,
		},
		{
			ID:         "ind-exp-future",
			SourceID:   "boundary-source",
			Type:       string(TypeDomain),
			Value:      "active-for-now.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   string(risk.SeverityHigh),
			ExpiresAt:  &expFuture,
		},
		{
			ID:         "ind-no-expiry",
			SourceID:   "boundary-source",
			Type:       string(TypeDomain),
			Value:      "permanent-threat.com",
			Category:   "phishing",
			Confidence: 95,
			Severity:   string(risk.SeverityHigh),
			ExpiresAt:  nil,
		},
		{
			ID:         "ind-exact-90d",
			SourceID:   "boundary-source",
			Type:       string(TypeDomain),
			Value:      "exact-90d.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   string(risk.SeverityHigh),
			LastSeen:   &lastSeenExact90d,
		},
		{
			ID:         "ind-past-90d",
			SourceID:   "boundary-source",
			Type:       string(TypeDomain),
			Value:      "past-90d.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   string(risk.SeverityHigh),
			LastSeen:   &lastSeenPast90d,
		},
		{
			ID:         "ind-within-90d",
			SourceID:   "boundary-source",
			Type:       string(TypeDomain),
			Value:      "within-90d.com",
			Category:   "phishing",
			Confidence: 90,
			Severity:   string(risk.SeverityHigh),
			LastSeen:   &lastSeenWithin90d,
		},
	}
	if _, _, err := db.SaveIndicatorBatch(ctx, "boundary-source", inds); err != nil {
		t.Fatalf("save batch: %v", err)
	}

	matcher := NewMatcher(db)

	// Target 1: Expired 1 second ago -> must not match
	coords1 := TargetCoordinates{Hostname: "expired-just-now.com"}
	sum1, err := matcher.MatchTargetAt(ctx, coords1, tRef)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(sum1.Matches) != 0 {
		t.Errorf("expected 0 matches for expired indicator, got %d", len(sum1.Matches))
	}

	// Target 2: Expiring in 1 second -> must match
	coords2 := TargetCoordinates{Hostname: "active-for-now.com"}
	sum2, err := matcher.MatchTargetAt(ctx, coords2, tRef)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(sum2.Matches) != 1 {
		t.Errorf("expected 1 match for active indicator, got %d", len(sum2.Matches))
	}

	// Target 3: No expiration -> must match
	coords3 := TargetCoordinates{Hostname: "permanent-threat.com"}
	sum3, err := matcher.MatchTargetAt(ctx, coords3, tRef)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(sum3.Matches) != 1 {
		t.Errorf("expected 1 match for no expiration indicator, got %d", len(sum3.Matches))
	}

	// Target 4: Exactly 90 days old -> matches as fresh
	coords4 := TargetCoordinates{Hostname: "exact-90d.com"}
	sum4, err := matcher.MatchTargetAt(ctx, coords4, tRef)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(sum4.Matches) != 1 || sum4.Matches[0].Freshness != "fresh" {
		t.Errorf("expected 1 fresh match at exact 90d boundary, got: %+v", sum4.Matches)
	}

	// Target 5: 1 second older than 90 days -> matches as stale
	coords5 := TargetCoordinates{Hostname: "past-90d.com"}
	sum5, err := matcher.MatchTargetAt(ctx, coords5, tRef)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(sum5.Matches) != 1 || sum5.Matches[0].Freshness != "stale" {
		t.Errorf("expected 1 stale match for >90d indicator, got: %+v", sum5.Matches)
	}

	// Target 6: 1 second newer than 90 days -> matches as fresh
	coords6 := TargetCoordinates{Hostname: "within-90d.com"}
	sum6, err := matcher.MatchTargetAt(ctx, coords6, tRef)
	if err != nil {
		t.Fatalf("match target: %v", err)
	}
	if len(sum6.Matches) != 1 || sum6.Matches[0].Freshness != "fresh" {
		t.Errorf("expected 1 fresh match for <90d indicator, got: %+v", sum6.Matches)
	}
}
