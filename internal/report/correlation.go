package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"bouclier/internal/risk"
)

type CorrelationEntry struct {
	ID         string
	StartedAt  time.Time
	Assessment *risk.RiskAssessment
}

type CorrelatedFinding struct {
	Fingerprint string `json:"fingerprint"`
	Code        string `json:"code"`
	Title       string `json:"title"`
}

type CorrelatedScan struct {
	ID               string              `json:"scan_id"`
	StartedAt        time.Time           `json:"started_at"`
	Score            int                 `json:"score"`
	Classification   risk.RiskClass      `json:"classification"`
	FindingCount     int                 `json:"finding_count"`
	NewFindings      []CorrelatedFinding `json:"new_findings"`
	ResolvedFindings []CorrelatedFinding `json:"resolved_findings"`
}

type Correlation struct {
	Target string           `json:"target"`
	Scans  []CorrelatedScan `json:"scans"`
}

func Correlate(target string, entries []CorrelationEntry) (Correlation, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return Correlation{}, fmt.Errorf("correlate reports: target is required")
	}

	entries = append([]CorrelationEntry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].StartedAt.Equal(entries[j].StartedAt) {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].StartedAt.Before(entries[j].StartedAt)
	})

	result := Correlation{Target: target, Scans: make([]CorrelatedScan, 0, len(entries))}
	var previous map[string]CorrelatedFinding
	for _, entry := range entries {
		if entry.Assessment == nil {
			continue
		}
		current := make(map[string]CorrelatedFinding, len(entry.Assessment.Findings))
		for _, finding := range entry.Assessment.Findings {
			fingerprint := findingFingerprint(finding)
			current[fingerprint] = CorrelatedFinding{
				Fingerprint: fingerprint,
				Code:        finding.Code,
				Title:       finding.Title,
			}
		}

		scan := CorrelatedScan{
			ID:               entry.ID,
			StartedAt:        entry.StartedAt,
			Score:            entry.Assessment.OverallScore,
			Classification:   entry.Assessment.Classification,
			FindingCount:     len(current),
			NewFindings:      []CorrelatedFinding{},
			ResolvedFindings: []CorrelatedFinding{},
		}
		if previous != nil {
			for key, finding := range current {
				if _, exists := previous[key]; !exists {
					scan.NewFindings = append(scan.NewFindings, finding)
				}
			}
			for key, finding := range previous {
				if _, exists := current[key]; !exists {
					scan.ResolvedFindings = append(scan.ResolvedFindings, finding)
				}
			}
			sort.Slice(scan.NewFindings, func(i, j int) bool {
				return scan.NewFindings[i].Fingerprint < scan.NewFindings[j].Fingerprint
			})
			sort.Slice(scan.ResolvedFindings, func(i, j int) bool {
				return scan.ResolvedFindings[i].Fingerprint < scan.ResolvedFindings[j].Fingerprint
			})
		}
		result.Scans = append(result.Scans, scan)
		previous = current
	}
	return result, nil
}

func findingFingerprint(finding risk.NormalizedFinding) string {
	parts := []string{
		normalizeFingerprintPart(finding.Code),
		normalizeFingerprintPart(finding.Category),
		normalizeFingerprintPart(finding.Title),
		normalizeFingerprintPart(finding.Evidence),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func normalizeFingerprintPart(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
