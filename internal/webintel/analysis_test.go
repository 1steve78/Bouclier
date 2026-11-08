package webintel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"bouclier/internal/heuristics"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webcheck"
)

func webInput(t *testing.T, raw string) *heuristics.NormalizedURL {
	t.Helper()
	input, err := heuristics.NormalizeURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func successfulTLS(_ context.Context, input *heuristics.NormalizedURL, _ tlsintel.Options) (*tlsintel.AnalysisResult, error) {
	return &tlsintel.AnalysisResult{TargetHostname: input.Hostname, TLSStatus: tlsintel.ComponentStatus{State: tlsintel.StateCompleted}}, nil
}

func successfulHTTP(_ context.Context, input *heuristics.NormalizedURL) (*webcheck.HTTPInspectionResult, error) {
	return &webcheck.HTTPInspectionResult{
		RequestedURL: "https://example.com", FinalURL: "https://example.com", StatusCode: http.StatusOK,
		Headers:     http.Header{"X-Powered-By": {"test-stack"}, "Content-Type": {"text/html"}},
		ContentType: "text/html", IsHTML: true, FinalHTTPS: true, UsedHTTPS: input.IsHTTPS,
		HTML: []byte(`<html><script src="http://assets.example.net/a.js"></script></html>`),
	}, nil
}

func TestAnalyzeWebsiteSuccessfulPipelineAndDeterminism(t *testing.T) {
	input := webInput(t, "https://example.com?secret=do-not-report")
	options := Options{CurrentTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
	first, err := analyzeWebsite(context.Background(), input, options, successfulTLS, successfulHTTP)
	if err != nil {
		t.Fatal(err)
	}
	second, err := analyzeWebsite(context.Background(), input, options, successfulTLS, successfulHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if first.TLSStatus.State != StateCompleted || first.HTTPStatus.State != StateCompleted || !first.Complete || first.TLS == nil || first.HTTP == nil {
		t.Fatalf("incomplete result: %+v", first)
	}
	if len(first.Findings) == 0 || len(first.Findings) != len(second.Findings) {
		t.Fatalf("findings missing or unstable: %v / %v", first.Findings, second.Findings)
	}
	for i := range first.Findings {
		if first.Findings[i] != second.Findings[i] {
			t.Fatalf("finding order changed: %v / %v", first.Findings, second.Findings)
		}
	}
	if strings.Contains(first.RequestedURL, "secret") {
		t.Fatal("query value leaked")
	}
}

func TestAnalyzeWebsiteComponentFailuresPreserveResults(t *testing.T) {
	input := webInput(t, "https://example.com")
	tlsErr := errors.New("TLS unavailable")
	tlsPartial := func(context.Context, *heuristics.NormalizedURL, tlsintel.Options) (*tlsintel.AnalysisResult, error) {
		return &tlsintel.AnalysisResult{TargetHostname: "example.com", TLSStatus: tlsintel.ComponentStatus{State: tlsintel.StateFailed, Err: tlsErr}}, tlsErr
	}
	result, err := analyzeWebsite(context.Background(), input, Options{}, tlsPartial, successfulHTTP)
	if err != nil || result.TLS == nil || result.HTTP == nil || result.HTTPStatus.State != StateCompleted || result.TLSStatus.State != StateFailed {
		t.Fatalf("TLS failure lost HTTP result: result=%+v err=%v", result, err)
	}

	httpErr := errors.New("HTTP failed")
	failingHTTP := func(context.Context, *heuristics.NormalizedURL) (*webcheck.HTTPInspectionResult, error) {
		return nil, httpErr
	}
	result, err = analyzeWebsite(context.Background(), input, Options{}, successfulTLS, failingHTTP)
	if err != nil || result.TLS == nil || result.TLSStatus.State != StateCompleted || result.HTTPStatus.State != StateFailed {
		t.Fatalf("HTTP failure lost TLS result: result=%+v err=%v", result, err)
	}
}

func TestAnalyzeWebsiteHTTPOnlyNonHTMLAndTruncated(t *testing.T) {
	input := webInput(t, "http://example.com")
	result, err := analyzeWebsite(context.Background(), input, Options{}, func(context.Context, *heuristics.NormalizedURL, tlsintel.Options) (*tlsintel.AnalysisResult, error) {
		t.Fatal("TLS should be skipped for HTTP")
		return nil, nil
	}, func(_ context.Context, input *heuristics.NormalizedURL) (*webcheck.HTTPInspectionResult, error) {
		return &webcheck.HTTPInspectionResult{RequestedURL: "http://example.com", FinalURL: "https://example.com", StatusCode: 200, Headers: make(http.Header), ContentType: "application/json", FinalHTTPS: true}, nil
	})
	if err != nil || result.TLSStatus.State != StateSkipped || result.HTMLStatus.State != StateSkipped || result.FinalURL != "https://example.com" {
		t.Fatalf("HTTP-only result=%+v err=%v", result, err)
	}

	input = webInput(t, "https://example.com")
	truncatedHTTP := func(context.Context, *heuristics.NormalizedURL) (*webcheck.HTTPInspectionResult, error) {
		r, _ := successfulHTTP(context.Background(), input)
		r.BodyTruncated = true
		return r, nil
	}
	truncated, err := analyzeWebsite(context.Background(), input, Options{}, successfulTLS, truncatedHTTP)
	if err != nil || truncated.Complete || !truncated.BodyTruncated || truncated.HTMLStatus.State != StatePartial {
		t.Fatalf("truncated report=%+v err=%v", truncated, err)
	}
}

func TestAnalyzeWebsiteCancellationAndValidation(t *testing.T) {
	input := webInput(t, "https://example.com")
	ctx, cancel := context.WithCancel(context.Background())
	httpCalled := false
	cancelingTLS := func(context.Context, *heuristics.NormalizedURL, tlsintel.Options) (*tlsintel.AnalysisResult, error) {
		cancel()
		return &tlsintel.AnalysisResult{TargetHostname: "example.com"}, nil
	}
	result, err := analyzeWebsite(ctx, input, Options{}, cancelingTLS, func(context.Context, *heuristics.NormalizedURL) (*webcheck.HTTPInspectionResult, error) {
		httpCalled = true
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) || result == nil || httpCalled {
		t.Fatalf("cancellation result=%+v err=%v HTTP called=%v", result, err, httpCalled)
	}
	if _, err := analyzeWebsite(context.Background(), nil, Options{}, successfulTLS, successfulHTTP); err == nil {
		t.Fatal("nil input accepted")
	}
	bad := &heuristics.NormalizedURL{Normalized: "https://not a hostname", Hostname: "not a hostname", Scheme: "https"}
	if _, err := analyzeWebsite(context.Background(), bad, Options{}, successfulTLS, successfulHTTP); err == nil {
		t.Fatal("invalid normalized input accepted")
	}
	if _, err := analyzeWebsite(context.Background(), webInput(t, "https://example.com:8443"), Options{}, successfulTLS, successfulHTTP); err == nil {
		t.Fatal("nonstandard web port accepted")
	}
}
