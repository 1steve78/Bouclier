// Package risk classifies and scores findings from the independent analysis layers.
package risk

import (
	"fmt"
	"time"

	"bouclier/internal/registration"
)

type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type ClassificationStatus string

const (
	FindingClassified   ClassificationStatus = "classified"
	FindingUnclassified ClassificationStatus = "unclassified"
)

type RiskClass string

const (
	RiskLow      RiskClass = "low"
	RiskGuarded  RiskClass = "guarded"
	RiskElevated RiskClass = "elevated"
	RiskHigh     RiskClass = "high"
	RiskCritical RiskClass = "critical"
)

type ComponentState string

const (
	ComponentCompleted ComponentState = "completed"
	ComponentPartial   ComponentState = "partial"
	ComponentFailed    ComponentState = "failed"
	ComponentSkipped   ComponentState = "skipped"
	ComponentNoResults ComponentState = "no_results"
)

// Observation adapts a source finding without altering its package contract.
type Observation struct {
	Code        string
	Title       string
	Description string
	Category    string
	Evidence    string
	Source      string
}

// NormalizedFinding retains source content while attaching policy metadata.
type NormalizedFinding struct {
	Code             string               `json:"code"`
	Title            string               `json:"title"`
	Description      string               `json:"description"`
	Category         string               `json:"category,omitempty"`
	ScoringCategory  string               `json:"scoring_category,omitempty"`
	Evidence         string               `json:"evidence,omitempty"`
	Severity         Severity             `json:"severity,omitempty"`
	Confidence       Confidence           `json:"confidence,omitempty"`
	ScoreImpact      int                  `json:"score_impact"`
	Source           string               `json:"source,omitempty"`
	Sources          []string             `json:"sources,omitempty"`
	DeduplicationKey string               `json:"deduplication_key"`
	Classification   ClassificationStatus `json:"classification_status"`
	Remediation      string               `json:"remediation,omitempty"`
	ScoreEligible    bool                 `json:"score_eligible"`
}

func (f NormalizedFinding) Validate() error {
	if f.Code == "" {
		return fmt.Errorf("finding code is required")
	}
	if f.Classification == FindingUnclassified {
		if f.ScoreEligible || f.ScoreImpact != 0 {
			return fmt.Errorf("unclassified findings cannot affect score")
		}
		return nil
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("finding severity %q is invalid", f.Severity)
	}
	if !validConfidence(f.Confidence) {
		return fmt.Errorf("finding confidence %q is invalid", f.Confidence)
	}
	if f.ScoreImpact < 0 || f.ScoreImpact > 100 {
		return fmt.Errorf("finding score impact must be between 0 and 100")
	}
	return nil
}

type SeverityCount struct {
	Severity Severity `json:"severity"`
	Count    int      `json:"count"`
}

type CategoryContribution struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Cap      int    `json:"cap"`
}

type RiskFactor struct {
	Finding      NormalizedFinding `json:"finding"`
	Contribution int               `json:"contribution"`
}

type ComponentCoverage struct {
	Component string         `json:"component"`
	State     ComponentState `json:"state"`
	Detail    string         `json:"detail,omitempty"`
}

// RiskAssessment is an explainable, deterministic assessment, never a
// probability that a site is malicious.
type RiskAssessment struct {
	SchemaVersion         string                    `json:"schema_version"`
	Target                string                    `json:"target"`
	AnalyzedAt            time.Time                 `json:"analyzed_at"`
	OverallScore          int                       `json:"overall_score"`
	Classification        RiskClass                 `json:"classification"`
	PolicyID              string                    `json:"policy_id"`
	PolicyVersion         string                    `json:"policy_version"`
	Findings              []NormalizedFinding       `json:"findings"`
	SeverityCounts        []SeverityCount           `json:"severity_counts"`
	CategoryContributions []CategoryContribution    `json:"category_contributions"`
	TopRiskFactors        []RiskFactor              `json:"top_risk_factors"`
	ExcludedFindings      []NormalizedFinding       `json:"excluded_findings"`
	UnclassifiedCount     int                       `json:"unclassified_count"`
	AnalysisCoverage      []ComponentCoverage       `json:"analysis_coverage"`
	RegistrationAge       *registration.AgeAnalysis `json:"registration_age,omitempty"`
	Limitations           []string                  `json:"limitations"`
	ScoringMethod         string                    `json:"scoring_method"`
}

func validSeverity(value Severity) bool {
	switch value {
	case SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func validConfidence(value Confidence) bool {
	switch value {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	}
	return false
}
