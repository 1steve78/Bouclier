package storage

import (
	"time"
)

// IntelSource represents a configured threat intelligence feed in the database.
type IntelSource struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	ProviderType   string        `json:"provider_type"` // "local_file", "https_feed"
	Endpoint       string        `json:"endpoint"`      // local file path or HTTPS URL
	Enabled        bool          `json:"enabled"`
	UpdateInterval time.Duration `json:"update_interval"`
	AuthHeaderEnv  string        `json:"auth_header_env,omitempty"` // environment variable name only, never the secret value
	Attribution    string        `json:"attribution"`
	License        string        `json:"license,omitempty"`
	Format         string        `json:"format"` // "json", "csv"
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// IntelSyncRun records the outcome of synchronizing a threat intelligence feed.
type IntelSyncRun struct {
	ID            string        `json:"id"`
	SourceID      string        `json:"source_id"`
	StartedAt     time.Time     `json:"started_at"`
	CompletedAt   time.Time     `json:"completed_at"`
	Duration      time.Duration `json:"duration"`
	Status        string        `json:"status"` // "success", "partial", "failed"
	ImportedCount int           `json:"imported_count"`
	UpdatedCount  int           `json:"updated_count"`
	SkippedCount  int           `json:"skipped_count"`
	RejectedCount int           `json:"rejected_count"`
	ErrorMessage  string        `json:"error_message,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

// IntelIndicator represents a stored threat intelligence indicator in SQLite.
type IntelIndicator struct {
	ID          string            `json:"id"`
	SourceID    string            `json:"source_id"`
	SourceName  string            `json:"source_name"`
	Type        string            `json:"type"` // "domain", "url", "ipv4", "ipv6"
	Value       string            `json:"value"`
	Category    string            `json:"category"`
	Confidence  int               `json:"confidence"`
	Severity    string            `json:"severity"`
	FirstSeen   *time.Time        `json:"first_seen,omitempty"`
	LastSeen    *time.Time        `json:"last_seen,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	IngestedAt  time.Time         `json:"ingested_at"`
	SourceRef   string            `json:"source_ref,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// IndicatorQuery specifies an exact (type, value) pair to query from local storage.
type IndicatorQuery struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// IntelStats contains high-level metrics about the local intelligence database.
type IntelStats struct {
	TotalIndicators  int        `json:"total_indicators"`
	TotalSources     int        `json:"total_sources"`
	EnabledSources   int        `json:"enabled_sources"`
	LastSyncTime     *time.Time `json:"last_sync_time,omitempty"`
	LastSyncStatus   string     `json:"last_sync_status,omitempty"`
	HasSyncFailures  bool       `json:"has_sync_failures"`
	LastErrorMessage string     `json:"last_error_message,omitempty"`
}
