package storage

import (
	"time"

	"bouclier/internal/risk"
)

// ScanStatus represents the final state of an executed scan.
type ScanStatus string

const (
	StatusCompleted ScanStatus = "completed"
	StatusPartial   ScanStatus = "partial"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// ScanRecord represents stored scan-level metadata.
type ScanRecord struct {
	ID             string         `json:"id"`
	Target         string         `json:"target"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at"`
	DurationMs     int64          `json:"duration_ms"`
	OverallScore   int            `json:"overall_score"`
	Classification risk.RiskClass `json:"classification"`
	PolicyID       string         `json:"policy_id"`
	PolicyVersion  string         `json:"policy_version"`
	Status         ScanStatus     `json:"status"`
	SchemaVersion  string         `json:"schema_version"`
	CreatedAt      time.Time      `json:"created_at"`
}

// ShortID returns a truncated identifier suitable for compact CLI and TUI display.
func (r ScanRecord) ShortID() string {
	if len(r.ID) > 8 {
		return r.ID[:8]
	}
	return r.ID
}

// ScanReport represents the detailed serialized assessment JSON stored for a scan.
type ScanReport struct {
	ScanID     string               `json:"scan_id"`
	ReportJSON string               `json:"report_json"`
	ReportHash string               `json:"report_hash,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
	Assessment *risk.RiskAssessment `json:"assessment,omitempty"`
}

type ReportAnchor struct {
	ScanID          string    `json:"scan_id"`
	ChainID         string    `json:"chain_id"`
	ContractAddress string    `json:"contract_address"`
	TransactionHash string    `json:"transaction_hash,omitempty"`
	ReportHash      string    `json:"report_hash"`
	RiskLevel       int       `json:"risk_level"`
	AnchoredAt      time.Time `json:"anchored_at"`
}

// ScanEntry pairs metadata with its full RiskAssessment.
type ScanEntry struct {
	Record     ScanRecord
	Assessment *risk.RiskAssessment
}

// ListFilter specifies filtering, pagination, and sorting parameters for querying scans.
type ListFilter struct {
	Target         string     `json:"target,omitempty"`
	Classification string     `json:"classification,omitempty"`
	MinScore       *int       `json:"min_score,omitempty"`
	MaxScore       *int       `json:"max_score,omitempty"`
	Status         ScanStatus `json:"status,omitempty"`
	Limit          int        `json:"limit,omitempty"`
	Offset         int        `json:"offset,omitempty"`
	SortBy         string     `json:"sort_by,omitempty"`    // "started_at" or "overall_score"
	SortOrder      string     `json:"sort_order,omitempty"` // "asc" or "desc"
}
