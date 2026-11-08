package storage

import (
	"context"
	"time"

	"bouclier/internal/risk"
)

// Repository defines the persistent scan history operations required by Bouclier.
type Repository interface {
	// SaveScan persists a scan metadata record and its complete sanitized assessment in a single transaction.
	SaveScan(ctx context.Context, record ScanRecord, assessment *risk.RiskAssessment) error

	// GetScan retrieves a single scan record by full ID or unique short prefix.
	GetScan(ctx context.Context, idOrPrefix string) (*ScanRecord, error)

	// GetScanReport retrieves the serialized assessment JSON and unmarshaled RiskAssessment by scan ID or prefix.
	GetScanReport(ctx context.Context, idOrPrefix string) (*ScanReport, error)

	// GetScanEntry retrieves both metadata and unmarshaled assessment in a single call.
	GetScanEntry(ctx context.Context, idOrPrefix string) (*ScanEntry, error)

	// ListScans queries scan records matching the given filter criteria, ordered and paginated.
	ListScans(ctx context.Context, filter ListFilter) ([]ScanRecord, error)

	// CountScans returns the total count of scan records matching the filter criteria (ignoring limit and offset).
	CountScans(ctx context.Context, filter ListFilter) (int, error)

	// DeleteScan deletes a scan record and its associated report cascade-deleted by foreign key.
	DeleteScan(ctx context.Context, idOrPrefix string) error

	// RegisterSource creates or updates a configured threat intelligence source.
	RegisterSource(ctx context.Context, src IntelSource) error

	// UpdateSource modifies an existing source.
	UpdateSource(ctx context.Context, src IntelSource) error

	// GetSource retrieves a single source by ID.
	GetSource(ctx context.Context, id string) (*IntelSource, error)

	// ListSources returns all configured threat intelligence sources.
	ListSources(ctx context.Context) ([]IntelSource, error)

	// SetSourceEnabled toggles the enabled flag for a source.
	SetSourceEnabled(ctx context.Context, id string, enabled bool) error

	// DeleteSource deletes a source, its indicators, and its sync history cascade-deleted by foreign key.
	DeleteSource(ctx context.Context, id string) error

	// SaveIndicatorBatch atomically upserts a slice of indicators for a source, returning counts of imported and updated records.
	SaveIndicatorBatch(ctx context.Context, sourceID string, indicators []IntelIndicator) (imported int, updated int, err error)

	// LookupIndicators retrieves unexpired indicators matching any of the given (type, value) queries at current time.
	LookupIndicators(ctx context.Context, queries []IndicatorQuery) ([]IntelIndicator, error)

	// LookupIndicatorsAt retrieves unexpired indicators matching criteria at the specified reference time.
	LookupIndicatorsAt(ctx context.Context, queries []IndicatorQuery, at time.Time) ([]IntelIndicator, error)

	// SearchIndicators searches unexpired indicators by value substring or category, returning results and total matching count.
	SearchIndicators(ctx context.Context, query string, limit int, offset int) ([]IntelIndicator, int, error)

	// PruneExpiredIndicators deletes indicators whose expires_at is before the given timestamp (or returns count if dryRun is true).
	PruneExpiredIndicators(ctx context.Context, before time.Time, dryRun bool) (int, error)

	// RecordSyncRun persists the result of a feed synchronization.
	RecordSyncRun(ctx context.Context, run IntelSyncRun) error

	// GetLatestSyncRun returns the most recent sync run for a source, or nil if none.
	GetLatestSyncRun(ctx context.Context, sourceID string) (*IntelSyncRun, error)

	// GetIntelStats returns high-level metrics on the local intelligence database.
	GetIntelStats(ctx context.Context) (*IntelStats, error)

	// Close terminates all active database connections.
	Close() error
}
