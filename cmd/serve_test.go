package cmd

import (
	"context"
	"errors"
	"testing"

	"bouclier/internal/api"
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/webcheck"
	"bouclier/internal/webintel"
)

func TestPipelineScanServiceRejectsUnsafeTargetsBeforeScanning(t *testing.T) {
	service := pipelineScanService{}
	for _, target := range []string{
		"http://127.0.0.1",
		"http://10.0.0.1",
		"http://[::1]",
		"http://[::8.8.8.8]",
	} {
		t.Run(target, func(t *testing.T) {
			_, err := service.Scan(context.Background(), target)
			if !errors.Is(err, api.ErrDestinationNotAllowed) {
				t.Fatalf("Scan() error = %v, want destination-not-allowed", err)
			}
		})
	}
	_, err := service.Scan(context.Background(), "http://[::ffff:127.0.0.1]")
	if !errors.Is(err, api.ErrInvalidTarget) {
		t.Fatalf("Scan() error for IPv4-mapped IPv6 target = %v, want invalid-target (rejected before scanning)", err)
	}
}

func TestPipelineScanServiceMapsBlockedRedirectToAPIError(t *testing.T) {
	restore := cli.SetWebsiteAnalyzerForTesting(func(context.Context, *heuristics.NormalizedURL, webintel.Options) (*webintel.AnalysisResult, error) {
		return &webintel.AnalysisResult{
			HTTPStatus: webintel.ComponentStatus{
				State: webintel.StateFailed,
				Error: "inspect website: destination is not permitted: loopback redirect",
				Err:   webcheck.ErrUnsafeTarget,
			},
		}, nil
	})
	defer restore()

	service := pipelineScanService{config: config.Default()}
	_, err := service.Scan(context.Background(), "http://example.com/")
	if !errors.Is(err, api.ErrDestinationNotAllowed) {
		t.Fatalf("Scan() error = %v, want destination-not-allowed", err)
	}
}
