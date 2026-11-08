package registration

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockProvider struct {
	lookup func(context.Context, string) (*RegistrationInfo, error)
}

func (m mockProvider) Lookup(ctx context.Context, domain string) (*RegistrationInfo, error) {
	return m.lookup(ctx, domain)
}

func TestLookupSuccessNormalizesProviderResponse(t *testing.T) {
	provider := mockProvider{lookup: func(_ context.Context, domain string) (*RegistrationInfo, error) {
		if domain != "example.com" {
			t.Fatalf("provider domain = %q", domain)
		}
		info := validRegistrationInfo()
		info.Domain = "WWW.EXAMPLE.COM."
		return info, nil
	}}
	got, err := Lookup(context.Background(), provider, "WWW.EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.com" || got.RetrievedAt.Location() != time.UTC {
		t.Fatalf("lookup result was not normalized: %+v", got)
	}
}

func TestLookupProviderErrors(t *testing.T) {
	for _, providerErr := range []error{ErrDomainNotFound, ErrUnsupportedDomain, ErrProviderUnavailable, ErrRateLimited} {
		t.Run(providerErr.Error(), func(t *testing.T) {
			provider := mockProvider{lookup: func(context.Context, string) (*RegistrationInfo, error) {
				return nil, providerErr
			}}
			if _, err := Lookup(context.Background(), provider, "example.com"); !errors.Is(err, providerErr) {
				t.Fatalf("Lookup() error = %v, want errors.Is(..., %v)", err, providerErr)
			}
		})
	}
}

func TestLookupContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	provider := mockProvider{lookup: func(context.Context, string) (*RegistrationInfo, error) {
		called = true
		return nil, errors.New("should not be called")
	}}
	if _, err := Lookup(ctx, provider, "example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup() error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("provider was called with an already-cancelled context")
	}
}

func TestLookupPropagatesLiveContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	finished := make(chan error, 1)
	provider := mockProvider{lookup: func(ctx context.Context, _ string) (*RegistrationInfo, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	go func() {
		_, err := Lookup(ctx, provider, "example.com")
		finished <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Lookup() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Lookup did not return after provider observed context cancellation")
	}
}

func TestLookupContextDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := Lookup(ctx, mockProvider{}, "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lookup() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestLookupInvalidProviderResponses(t *testing.T) {
	for _, response := range []*RegistrationInfo{
		nil,
		{Domain: "attacker.example", RetrievedAt: time.Now(), DataSource: "mock"},
		{Domain: "bad..example", RetrievedAt: time.Now(), DataSource: "mock"},
		{Domain: "example.com", RetrievedAt: time.Time{}, DataSource: "mock"},
	} {
		provider := mockProvider{lookup: func(context.Context, string) (*RegistrationInfo, error) { return response, nil }}
		if _, err := Lookup(context.Background(), provider, "example.com"); !errors.Is(err, ErrInvalidProviderResponse) {
			t.Errorf("Lookup() error = %v, want ErrInvalidProviderResponse", err)
		}
	}
}

func TestLookupRejectsInvalidRequest(t *testing.T) {
	provider := mockProvider{lookup: func(context.Context, string) (*RegistrationInfo, error) {
		t.Fatal("provider should not be called for an invalid request")
		return nil, nil
	}}
	if _, err := Lookup(context.Background(), provider, "com"); !errors.Is(err, ErrUnsupportedDomain) {
		t.Fatalf("Lookup() error = %v, want ErrUnsupportedDomain", err)
	}
	if _, err := Lookup(context.Background(), nil, "example.com"); err == nil {
		t.Fatal("nil provider must fail")
	}
}
