// Package domain orchestrates domain-only analysis without CLI, TUI, or
// network dependencies.
package domain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/registration"
)

// AnalysisResult contains hostname-derived findings and optional registration
// age analysis. Raw registration records and personal information are omitted.
type AnalysisResult struct {
	DomainInfo      *heuristics.DomainInfo
	Findings        []heuristics.Finding
	RegistrationAge *registration.AgeAnalysis
}

// AnalyzeDomain validates and analyzes an extracted domain model. It does not
// perform registration lookups or any network operations.
func AnalyzeDomain(info *heuristics.DomainInfo) (*AnalysisResult, error) {
	if info == nil {
		return nil, fmt.Errorf("analyze domain: domain info is nil")
	}
	structureFindings, err := heuristics.AnalyzeDomainStructure(info)
	if err != nil {
		return nil, fmt.Errorf("analyze domain structure: %w", err)
	}
	brandFindings, err := heuristics.AnalyzeDomainBrandRelationships(info)
	if err != nil {
		return nil, fmt.Errorf("analyze domain brand relationships: %w", err)
	}
	findings := mergeFindings(structureFindings, brandFindings)
	return &AnalysisResult{
		DomainInfo: info,
		Findings:   findings,
	}, nil
}

// AnalyzeDomainWithRegistration adds age analysis for explicitly supplied
// registration data. A nil record omits registration analysis; no provider is
// selected or queried. No registration record or personal information is
// copied into the result.
func AnalyzeDomainWithRegistration(info *heuristics.DomainInfo, registrationInfo *registration.RegistrationInfo, now time.Time) (*AnalysisResult, error) {
	result, err := AnalyzeDomain(info)
	if err != nil {
		return nil, err
	}
	if registrationInfo == nil {
		return result, nil
	}
	age, err := registration.AnalyzeRegistrationAge(registrationInfo, now)
	if err != nil {
		return nil, fmt.Errorf("analyze domain registration age: %w", err)
	}
	result.RegistrationAge = age
	return result, nil
}

// mergeFindings preserves the first finding for each stable code and evidence
// string, then sorts by code. Structure findings take precedence because they
// are supplied first; equal evidence under another code is also retained once.
func mergeFindings(groups ...[]heuristics.Finding) []heuristics.Finding {
	merged := make([]heuristics.Finding, 0)
	seenCodes := make(map[string]struct{})
	seenEvidence := make(map[string]struct{})
	for _, group := range groups {
		for _, finding := range group {
			evidence := strings.TrimSpace(finding.Evidence)
			if _, found := seenCodes[finding.Code]; found {
				continue
			}
			if _, found := seenEvidence[evidence]; found {
				continue
			}
			seenCodes[finding.Code] = struct{}{}
			seenEvidence[evidence] = struct{}{}
			merged = append(merged, finding)
		}
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Code < merged[j].Code })
	return merged
}
