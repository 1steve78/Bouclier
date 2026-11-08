package registration

import (
	"fmt"
	"time"
)

const (
	veryNewRegistrationAge = 7 * 24 * time.Hour
	newRegistrationAge     = 30 * 24 * time.Hour
)

const (
	AgeStatusUnavailable = "unavailable"
	AgeStatusRedacted    = "redacted"
	AgeStatusVeryNew     = "very_new"
	AgeStatusNew         = "new"
	AgeStatusEstablished = "established"
)

// AgeAnalysis summarizes registration age without assigning risk. The seven
// and thirty day cutoffs are contextual heuristics, not proof of abuse.
type AgeAnalysis struct {
	Age            *time.Duration
	IsNewlyCreated bool
	IsVeryNew      bool
	Status         string
	Explanation    string
}

// AnalyzeRegistrationAge evaluates creation time relative to the caller's
// clock. Missing or zero dates remain unavailable; future dates are rejected.
func AnalyzeRegistrationAge(info *RegistrationInfo, now time.Time) (*AgeAnalysis, error) {
	if info == nil {
		return nil, fmt.Errorf("analyze registration age: registration info is nil")
	}
	if info.CreatedAt == nil || info.CreatedAt.IsZero() {
		status := AgeStatusUnavailable
		explanation := "Creation date is unavailable; no age conclusion can be drawn."
		if info.IsRedacted {
			status = AgeStatusRedacted
			explanation = "Creation date is redacted; no age conclusion can be drawn."
		}
		return &AgeAnalysis{Status: status, Explanation: explanation}, nil
	}

	createdAt := info.CreatedAt.UTC()
	now = now.UTC()
	if createdAt.After(now) {
		return nil, fmt.Errorf("analyze registration age: creation date is in the future")
	}
	age := now.Sub(createdAt)
	result := &AgeAnalysis{Age: &age}
	switch {
	case age < veryNewRegistrationAge:
		result.IsNewlyCreated = true
		result.IsVeryNew = true
		result.Status = AgeStatusVeryNew
		result.Explanation = "The domain was registered less than 7 days ago. Recent registration is a contextual signal, not proof of malicious activity."
	case age < newRegistrationAge:
		result.IsNewlyCreated = true
		result.Status = AgeStatusNew
		result.Explanation = "The domain was registered at least 7 but less than 30 days ago. Recent registration is a contextual signal, not proof of malicious activity."
	default:
		result.Status = AgeStatusEstablished
		result.Explanation = "The domain was registered at least 30 days ago; age alone does not establish trustworthiness."
	}
	return result, nil
}
