package intel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrSourceDisabled    = errors.New("threat intelligence source is disabled")
	ErrUnsupportedFormat = errors.New("unsupported feed format")
	ErrProviderNotFound  = errors.New("provider not found for source type")
	ErrSSRFBlocked       = errors.New("destination address is restricted or private")
)

// SourceConfig configures a single threat intelligence feed or file source.
type SourceConfig struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	ProviderType   string        `json:"provider_type"` // "local_file", "https_feed"
	Endpoint       string        `json:"endpoint"`      // local file path or HTTPS URL
	Enabled        bool          `json:"enabled"`
	UpdateInterval time.Duration `json:"update_interval"`
	Timeout        time.Duration `json:"timeout"`
	AuthHeaderEnv  string        `json:"auth_header_env,omitempty"` // environment variable name only
	AuthHeader     string        `json:"-"`                         // in-memory resolved secret; never persisted or logged
	Attribution    string        `json:"attribution"`
	License        string        `json:"license,omitempty"`
	Format         string        `json:"format"` // "json", "csv"
	Version        string        `json:"version,omitempty"`
}

// Validate checks the source configuration for safety and completeness.
func (cfg *SourceConfig) Validate() error {
	if strings.TrimSpace(cfg.ID) == "" {
		return fmt.Errorf("source id is required")
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return fmt.Errorf("source name is required")
	}
	if strings.TrimSpace(cfg.ProviderType) == "" {
		return fmt.Errorf("provider_type is required")
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return fmt.Errorf("endpoint is required")
	}
	if cfg.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}
	if cfg.UpdateInterval < 0 {
		return fmt.Errorf("update_interval cannot be negative")
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format != "" && format != "json" && format != "csv" {
		return fmt.Errorf("%w: %q", ErrUnsupportedFormat, cfg.Format)
	}
	return nil
}

// RecordError captures a non-fatal parsing/validation error for an individual indicator record.
type RecordError struct {
	Index   int    `json:"index"`
	Raw     string `json:"raw,omitempty"`
	Message string `json:"message"`
}

// IngestionResult contains the summary metrics of an ingestion run.
type IngestionResult struct {
	SourceID   string        `json:"source_id"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration"`
	TotalRead  int           `json:"total_read"`
	ValidCount int           `json:"valid_count"`
	Errors     []RecordError `json:"errors,omitempty"`
	Indicators []Indicator   `json:"indicators,omitempty"`
}

// Provider defines the interface for fetching threat intelligence records from a source.
type Provider interface {
	FetchIndicators(ctx context.Context, config SourceConfig) (*IngestionResult, error)
}

// ProviderRegistry manages the set of available threat intelligence providers.
type ProviderRegistry struct {
	providers map[string]Provider
}

// NewProviderRegistry creates an initialized registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]Provider),
	}
}

// Register adds or replaces a provider for a provider type.
func (r *ProviderRegistry) Register(providerType string, p Provider) {
	r.providers[strings.ToLower(strings.TrimSpace(providerType))] = p
}

// Get retrieves a provider by type.
func (r *ProviderRegistry) Get(providerType string) (Provider, bool) {
	p, ok := r.providers[strings.ToLower(strings.TrimSpace(providerType))]
	return p, ok
}
