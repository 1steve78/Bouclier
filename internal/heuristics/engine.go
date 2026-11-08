package heuristics

import (
	"fmt"
	"sort"
	"strings"
)

// AnalysisResult is a complete offline URL analysis. URL fields in the result
// are sanitized: userinfo, query values, and fragments are omitted.
type AnalysisResult struct {
	OriginalURL    string
	NormalizedURL  *NormalizedURL
	Classification *Classification
	Findings       []Finding
}

// AnalyzeURL validates, classifies, and analyzes rawURL without DNS or HTTP
// access. Findings are sorted by stable code for deterministic reporting.
func AnalyzeURL(rawURL string) (*AnalysisResult, error) {
	normalized, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("analyze URL normalization: %w", err)
	}
	classification, err := ClassifyURL(normalized)
	if err != nil {
		return nil, fmt.Errorf("analyze URL classification: %w", err)
	}
	findings, err := AnalyzePatterns(normalized, classification)
	if err != nil {
		return nil, fmt.Errorf("analyze URL detectors: %w", err)
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Code < findings[j].Code
	})

	safeURL := sanitizedURL(normalized)
	return &AnalysisResult{
		OriginalURL:    safeURL,
		NormalizedURL:  sanitizedNormalizedURL(normalized, safeURL),
		Classification: classification,
		Findings:       findings,
	}, nil
}

func sanitizedURL(u *NormalizedURL) string {
	return u.Scheme + "://" + u.Host + u.Path
}

func sanitizedNormalizedURL(u *NormalizedURL, safeURL string) *NormalizedURL {
	copy := *u
	copy.Original = safeURL
	copy.Normalized = safeURL
	copy.OriginalHostname = strings.TrimSuffix(u.OriginalHostname, ".")
	copy.Query = ""
	copy.Fragment = ""
	return &copy
}
