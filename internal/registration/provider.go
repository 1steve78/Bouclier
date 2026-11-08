package registration

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidDomain           = errors.New("invalid registration domain")
	ErrDomainNotFound          = errors.New("registration domain not found")
	ErrUnsupportedDomain       = errors.New("unsupported registration domain")
	ErrProviderUnavailable     = errors.New("registration provider unavailable")
	ErrRateLimited             = errors.New("registration provider rate limited")
	ErrInvalidProviderResponse = errors.New("invalid registration provider response")
)

// Provider supplies registration data for a normalized registrable domain.
// Implementations should honor context cancellation and return the sentinel
// errors defined in this package when their outcomes match those conditions.
type Provider interface {
	Lookup(ctx context.Context, domain string) (*RegistrationInfo, error)
}

// Lookup validates the requested domain and provider response around the
// provider boundary. It does not perform network access itself.
func Lookup(ctx context.Context, provider Provider, domain string) (*RegistrationInfo, error) {
	if ctx == nil {
		return nil, fmt.Errorf("lookup registration: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("lookup registration: %w", err)
	}
	if provider == nil {
		return nil, fmt.Errorf("lookup registration: provider is nil")
	}
	normalizedDomain, err := NormalizeDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup registration: normalize domain: %w", err)
	}

	info, err := provider.Lookup(ctx, normalizedDomain)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("lookup registration: %w", ctxErr)
		}
		return nil, fmt.Errorf("lookup registration provider: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("lookup registration: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("lookup registration: %w: provider returned no record", ErrInvalidProviderResponse)
	}
	info = cloneRegistrationInfo(info)
	if err := info.NormalizeAndValidate(); err != nil {
		return nil, fmt.Errorf("lookup registration: %w: %w", ErrInvalidProviderResponse, err)
	}
	if info.Domain != normalizedDomain {
		return nil, fmt.Errorf("lookup registration: %w: returned domain does not match request", ErrInvalidProviderResponse)
	}
	return info, nil
}

func cloneRegistrationInfo(info *RegistrationInfo) *RegistrationInfo {
	copy := *info
	copy.CreatedAt = cloneTime(info.CreatedAt)
	copy.UpdatedAt = cloneTime(info.UpdatedAt)
	copy.ExpiresAt = cloneTime(info.ExpiresAt)
	copy.Status = append([]string(nil), info.Status...)
	copy.NameServers = append([]string(nil), info.NameServers...)
	return &copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
