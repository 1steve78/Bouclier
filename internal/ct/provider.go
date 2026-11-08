package ct

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnsupportedQuery    = errors.New("unsupported CT query")
	ErrNoResults           = errors.New("no CT results")
	ErrProviderUnavailable = errors.New("CT provider unavailable")
	ErrRateLimited         = errors.New("CT provider rate limited")
	ErrInvalidResponse     = errors.New("invalid CT provider response")
	ErrAuthentication      = errors.New("CT provider authentication failed")
	ErrResultsTruncated    = errors.New("CT results are incomplete due to a retrieval limit or history window")
)

// Provider searches a CT source. Implementations should honor context
// cancellation and return summaries that NormalizeEntries can validate.
type Provider interface {
	Search(ctx context.Context, query Query) ([]CTEntry, error)
}

// QueryEntries validates a query, calls the supplied provider, then validates,
// scopes, deduplicates, sorts, and limits its results. It does not implement a
// provider or perform network access itself.
func QueryEntries(ctx context.Context, provider Provider, query Query) ([]CTEntry, error) {
	if ctx == nil {
		return nil, fmt.Errorf("query CT entries: %w: context is nil", ErrUnsupportedQuery)
	}
	if provider == nil {
		return nil, fmt.Errorf("query CT entries: %w", ErrProviderUnavailable)
	}
	normalized, err := NormalizeQuery(query)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("query CT entries: %w", err)
	}
	entries, err := provider.Search(ctx, normalized)
	if err != nil {
		if errors.Is(err, ErrResultsTruncated) {
			if len(entries) == 0 {
				return nil, fmt.Errorf("search CT provider: %w", err)
			}
			normalizedEntries, normalizeErr := NormalizeEntries(entries, normalized)
			if normalizeErr != nil && !errors.Is(normalizeErr, ErrNoResults) {
				return nil, normalizeErr
			}
			return normalizedEntries, fmt.Errorf("search CT provider: %w", err)
		}
		return nil, fmt.Errorf("search CT provider: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("query CT entries: %w", err)
	}
	return NormalizeEntries(entries, normalized)
}
