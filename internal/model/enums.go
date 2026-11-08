package model

// RiskLevel describes the overall risk classification of the report.
type RiskLevel string

const (
	RiskLevelLowRisk            RiskLevel = "low_risk"
	RiskLevelSuspicious         RiskLevel = "suspicious"
	RiskLevelHighRisk           RiskLevel = "high_risk"
	RiskLevelConfirmedMalicious RiskLevel = "confirmed_malicious"
)

func (r RiskLevel) Valid() bool {
	switch r {
	case RiskLevelLowRisk, RiskLevelSuspicious, RiskLevelHighRisk, RiskLevelConfirmedMalicious:
		return true
	default:
		return false
	}
}

// Severity is the severity of a single finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// Confidence is the confidence attached to a finding.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

// Module identifies the subsystem that generated an item.
type Module string

const (
	ModuleURL         Module = "url"
	ModuleDomain      Module = "domain"
	ModuleTLS         Module = "tls"
	ModuleWeb         Module = "web"
	ModuleIntel       Module = "intel"
	ModuleMessage     Module = "message"
	ModuleCorrelation Module = "correlation"
)

func (m Module) Valid() bool {
	switch m {
	case ModuleURL, ModuleDomain, ModuleTLS, ModuleWeb, ModuleIntel, ModuleMessage, ModuleCorrelation:
		return true
	default:
		return false
	}
}

// FindingSource is the source of a finding.
type FindingSource string

const (
	FindingSourceRule  FindingSource = "rule"
	FindingSourceFeed  FindingSource = "feed"
	FindingSourceProbe FindingSource = "probe"
)

func (s FindingSource) Valid() bool {
	switch s {
	case FindingSourceRule, FindingSourceFeed, FindingSourceProbe:
		return true
	default:
		return false
	}
}

// CheckStatus indicates whether a check completed, was skipped, or failed.
type CheckStatus string

const (
	CheckStatusCompleted CheckStatus = "completed"
	CheckStatusSkipped   CheckStatus = "skipped"
	CheckStatusFailed    CheckStatus = "failed"
)

func (s CheckStatus) Valid() bool {
	switch s {
	case CheckStatusCompleted, CheckStatusSkipped, CheckStatusFailed:
		return true
	default:
		return false
	}
}

// IndicatorType is the type of indicator carried in a report.
type IndicatorType string

const (
	IndicatorTypeURL             IndicatorType = "url"
	IndicatorTypeDomain          IndicatorType = "domain"
	IndicatorTypeIP              IndicatorType = "ip"
	IndicatorTypeEmail           IndicatorType = "email"
	IndicatorTypePhone           IndicatorType = "phone"
	IndicatorTypeCertFingerprint IndicatorType = "cert_fingerprint"
	IndicatorTypePaymentHandle   IndicatorType = "payment_handle"
)

func (t IndicatorType) Valid() bool {
	switch t {
	case IndicatorTypeURL, IndicatorTypeDomain, IndicatorTypeIP, IndicatorTypeEmail, IndicatorTypePhone,
		IndicatorTypeCertFingerprint, IndicatorTypePaymentHandle:
		return true
	default:
		return false
	}
}

// ReportKind identifies the kind of report produced.
type ReportKind string

const (
	ReportKindURL     ReportKind = "url"
	ReportKindMessage ReportKind = "message"
)

func (k ReportKind) Valid() bool {
	switch k {
	case ReportKindURL, ReportKindMessage:
		return true
	default:
		return false
	}
}

// ChainStatus tracks blockchain verification state.
type ChainStatus string

const (
	ChainStatusPending   ChainStatus = "pending"
	ChainStatusConfirmed ChainStatus = "confirmed"
	ChainStatusFailed    ChainStatus = "failed"
)

func (s ChainStatus) Valid() bool {
	switch s {
	case ChainStatusPending, ChainStatusConfirmed, ChainStatusFailed:
		return true
	default:
		return false
	}
}
