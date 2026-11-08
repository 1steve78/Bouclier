package intel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
)

// MatchType describes the precision of a threat intelligence hit.
type MatchType string

const (
	MatchExactURL          MatchType = "exact_url"
	MatchExactDomain       MatchType = "exact_domain"
	MatchRegistrableDomain MatchType = "registrable_domain"
	MatchExactIP           MatchType = "exact_ip"
)

// Match describes an individual indicator hit against a scan target.
type Match struct {
	Indicator   Indicator `json:"indicator"`
	MatchType   MatchType `json:"match_type"`
	Freshness   string    `json:"freshness"` // "fresh", "stale"
	Explanation string    `json:"explanation"`
}

// MatchSummary aggregates all hits from an intelligence lookup.
type MatchSummary struct {
	Target               string     `json:"target"`
	Matches              []Match    `json:"matches"`
	IndicatorsConsidered int        `json:"indicators_considered"`
	Ran                  bool       `json:"ran"`
	DatabaseStale        bool       `json:"database_stale"`
	DatabaseUnavailable  bool       `json:"database_unavailable"`
	LastSyncTime         *time.Time `json:"last_sync_time,omitempty"`
	ConfiguredSources    int        `json:"configured_sources"`
	EnabledSources       int        `json:"enabled_sources"`
	Detail               string     `json:"detail,omitempty"`
}

// TargetCoordinates specifies the URL, domain, registrable domain, and IPs for matching.
type TargetCoordinates struct {
	NormalizedURL     string
	Hostname          string
	RegistrableDomain string
	IPs               []string
}

// ExtractCoordinates derives matching coordinates from normalized URL and optional resolved IPs.
func ExtractCoordinates(u *heuristics.NormalizedURL, domainInfo *heuristics.DomainInfo, resolvedIPs []string) TargetCoordinates {
	coords := TargetCoordinates{
		IPs: resolvedIPs,
	}
	if u != nil {
		coords.NormalizedURL = u.Normalized
		coords.Hostname = strings.ToLower(u.Hostname)
	}
	if domainInfo != nil {
		if coords.Hostname == "" {
			coords.Hostname = strings.ToLower(domainInfo.Hostname)
		}
		coords.RegistrableDomain = strings.ToLower(domainInfo.RegistrableDomain)
	}
	return coords
}

// Matcher queries local threat intelligence storage for target matches.
type Matcher struct {
	repo storage.Repository
}

// NewMatcher creates a matcher backed by the local repository.
func NewMatcher(repo storage.Repository) *Matcher {
	return &Matcher{repo: repo}
}

// MatchTarget executes deterministic local matching against stored intelligence.
func (m *Matcher) MatchTarget(ctx context.Context, coords TargetCoordinates) (*MatchSummary, error) {
	return m.MatchTargetAt(ctx, coords, time.Now().UTC())
}

// MatchTargetAt executes deterministic local matching against stored intelligence using a specified reference time.
func (m *Matcher) MatchTargetAt(ctx context.Context, coords TargetCoordinates, now time.Time) (*MatchSummary, error) {
	now = now.UTC()
	summary := &MatchSummary{
		Target:  coords.NormalizedURL,
		Matches: []Match{},
		Ran:     true,
	}

	if m.repo == nil {
		summary.DatabaseUnavailable = true
		summary.Detail = "Local threat intelligence repository is not connected"
		return summary, nil
	}

	// Retrieve stats
	stats, err := m.repo.GetIntelStats(ctx)
	if err != nil {
		summary.DatabaseUnavailable = true
		summary.Detail = fmt.Sprintf("Failed to query intelligence repository: %v", err)
		return summary, nil
	}

	summary.ConfiguredSources = stats.TotalSources
	summary.EnabledSources = stats.EnabledSources
	summary.LastSyncTime = stats.LastSyncTime
	summary.IndicatorsConsidered = stats.TotalIndicators

	// Check staleness (if no sync within 7 days, or database empty with enabled sources)
	if stats.LastSyncTime == nil || time.Since(*stats.LastSyncTime) > 7*24*time.Hour {
		summary.DatabaseStale = true
	}

	// Build query list
	var queries []storage.IndicatorQuery

	if coords.NormalizedURL != "" {
		queries = append(queries, storage.IndicatorQuery{
			Type:  string(TypeURL),
			Value: coords.NormalizedURL,
		})
	}

	if coords.Hostname != "" {
		queries = append(queries, storage.IndicatorQuery{
			Type:  string(TypeDomain),
			Value: coords.Hostname,
		})
	}

	if coords.RegistrableDomain != "" && coords.RegistrableDomain != coords.Hostname {
		queries = append(queries, storage.IndicatorQuery{
			Type:  string(TypeDomain),
			Value: coords.RegistrableDomain,
		})
	}

	for _, ip := range coords.IPs {
		cleanIP := strings.TrimSpace(ip)
		if cleanIP == "" {
			continue
		}
		if strings.Contains(cleanIP, ":") {
			queries = append(queries, storage.IndicatorQuery{
				Type:  string(TypeIPv6),
				Value: cleanIP,
			})
		} else {
			queries = append(queries, storage.IndicatorQuery{
				Type:  string(TypeIPv4),
				Value: cleanIP,
			})
		}
	}

	if len(queries) == 0 {
		return summary, nil
	}

	storedHits, err := m.repo.LookupIndicatorsAt(ctx, queries, now)
	if err != nil {
		summary.DatabaseUnavailable = true
		summary.Detail = fmt.Sprintf("Lookup query failed: %v", err)
		return summary, nil
	}

	for _, hit := range storedHits {
		// Convert to intel.Indicator
		ind := convertStoredIndicator(hit)
		if ind.IsExpired(now) {
			continue // Exclude expired indicators
		}

		matchType := determineMatchType(coords, ind)
		freshness := calculateFreshness(ind, now)
		explanation := generateExplanation(coords, ind, matchType, freshness)

		summary.Matches = append(summary.Matches, Match{
			Indicator:   ind,
			MatchType:   matchType,
			Freshness:   freshness,
			Explanation: explanation,
		})
	}

	return summary, nil
}

func determineMatchType(coords TargetCoordinates, ind Indicator) MatchType {
	switch ind.Type {
	case TypeURL:
		return MatchExactURL
	case TypeDomain:
		if strings.EqualFold(ind.Value, coords.Hostname) {
			return MatchExactDomain
		}
		if strings.EqualFold(ind.Value, coords.RegistrableDomain) {
			return MatchRegistrableDomain
		}
		return MatchExactDomain
	case TypeIPv4, TypeIPv6:
		return MatchExactIP
	default:
		return MatchExactDomain
	}
}

// CalculateFreshness determines whether an indicator is "fresh" or "stale" relative to reference time.
// Policy:
// - Fresh: last_seen >= reference_time - 90 days
// - Stale: last_seen < reference_time - 90 days
func CalculateFreshness(ind Indicator, now time.Time) string {
	return calculateFreshness(ind, now)
}

func calculateFreshness(ind Indicator, now time.Time) string {
	refTime := ind.IngestedAt
	if ind.LastSeen != nil {
		refTime = *ind.LastSeen
	}

	threshold := now.Add(-90 * 24 * time.Hour)
	if refTime.Before(threshold) {
		return "stale"
	}
	return "fresh"
}

func generateExplanation(coords TargetCoordinates, ind Indicator, matchType MatchType, freshness string) string {
	var targetDesc string
	switch matchType {
	case MatchExactURL:
		targetDesc = fmt.Sprintf("URL %q matches", coords.NormalizedURL)
	case MatchExactDomain:
		targetDesc = fmt.Sprintf("Hostname %q matches", coords.Hostname)
	case MatchRegistrableDomain:
		targetDesc = fmt.Sprintf("Registrable domain %q matches", coords.RegistrableDomain)
	case MatchExactIP:
		targetDesc = fmt.Sprintf("Target IP %q matches", ind.Value)
	}

	staleNote := ""
	if freshness == "stale" {
		staleNote = " (historical/stale indicator)"
	}

	return fmt.Sprintf("%s %s indicator from source %s (%s, confidence %d%%)%s",
		targetDesc, ind.Category, ind.SourceName, ind.Severity, ind.Confidence, staleNote)
}

func convertStoredIndicator(hit storage.IntelIndicator) Indicator {
	sev := risk.Severity(hit.Severity)
	switch sev {
	case risk.SeverityInformational, risk.SeverityLow, risk.SeverityMedium, risk.SeverityHigh, risk.SeverityCritical:
	default:
		sev = risk.SeverityHigh
	}

	return Indicator{
		ID:          hit.ID,
		Type:        IndicatorType(hit.Type),
		Value:       hit.Value,
		SourceID:    hit.SourceID,
		SourceName:  hit.SourceName,
		Category:    hit.Category,
		Confidence:  hit.Confidence,
		Severity:    sev,
		FirstSeen:   hit.FirstSeen,
		LastSeen:    hit.LastSeen,
		ExpiresAt:   hit.ExpiresAt,
		IngestedAt:  hit.IngestedAt,
		SourceRef:   hit.SourceRef,
		Description: hit.Description,
		Metadata:    hit.Metadata,
	}
}
