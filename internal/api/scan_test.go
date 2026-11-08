package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"bouclier/internal/api/middleware"
	"bouclier/internal/config"
	"bouclier/internal/report"
	"bouclier/internal/risk"
)

type scanServiceFunc func(context.Context, string) (*risk.RiskAssessment, error)

func (f scanServiceFunc) Scan(ctx context.Context, target string) (*risk.RiskAssessment, error) {
	return f(ctx, target)
}

func newTestScanHandler(t *testing.T, service ScanService, timeout time.Duration, concurrency int) http.Handler {
	t.Helper()
	handler, err := NewScanHandler(service, timeout, concurrency, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return middleware.RequestID(nil)(handler)
}

func scanRequest(handler http.Handler, method, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, "/api/v1/scans", strings.NewReader(body)))
	return recorder
}

func testAssessment() *risk.RiskAssessment {
	return &risk.RiskAssessment{
		SchemaVersion:         "bouclier-risk/v1",
		Target:                "https://example.com",
		AnalyzedAt:            time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
		OverallScore:          12,
		Classification:        risk.RiskLow,
		PolicyID:              "bouclier-default",
		PolicyVersion:         "1",
		Findings:              []risk.NormalizedFinding{},
		SeverityCounts:        []risk.SeverityCount{},
		CategoryContributions: []risk.CategoryContribution{},
		TopRiskFactors:        []risk.RiskFactor{},
		ExcludedFindings:      []risk.NormalizedFinding{},
		AnalysisCoverage:      []risk.ComponentCoverage{},
		Limitations:           []string{},
		ScoringMethod:         "test",
	}
}

func TestScanHandlerReturnsCanonicalReport(t *testing.T) {
	assessment := testAssessment()
	assessment.OverallScore = 90
	assessment.Classification = risk.RiskCritical
	assessment.Findings = []risk.NormalizedFinding{{
		Code: "WEB_HTML_INSECURE_PASSWORD_FORM", Title: "Password form without HTTPS",
		Description: "A password form is available over an insecure transport.",
		Severity:    risk.SeverityCritical, Confidence: risk.ConfidenceHigh,
		Classification: risk.FindingClassified, ScoreImpact: 35,
		DeduplicationKey: "test-password-form", ScoreEligible: true,
	}}
	var gotTarget string
	service := scanServiceFunc(func(_ context.Context, target string) (*risk.RiskAssessment, error) {
		gotTarget = target
		return assessment, nil
	})
	server, err := NewServerWithScanService(config.Default().HTTPServer, nil, service, 1)
	if err != nil {
		t.Fatal(err)
	}

	response := scanRequest(server.Handler, http.MethodPost, `{"target_url":" https://example.com "}`)
	if response.Code != http.StatusOK {
		t.Fatalf("high-risk assessment status = %d, want 200: %s", response.Code, response.Body)
	}
	if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
	if gotTarget != "https://example.com/" {
		t.Fatalf("service target = %q", gotTarget)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if _, wrapped := payload["data"]; wrapped {
		t.Fatal("canonical risk report was unexpectedly wrapped")
	}
	if string(payload["schema_version"]) != `"bouclier-risk/v1"` {
		t.Fatalf("schema_version = %s", payload["schema_version"])
	}
	if _, hasScore := payload["overall_score"]; !hasScore {
		t.Fatal("canonical report is missing overall_score")
	}
	want, err := report.RenderJSON(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Body.Bytes(), want) {
		t.Fatal("HTTP response differs from the canonical report serialization")
	}
}

func TestScanHandlerReleasesCapacityAfterPanic(t *testing.T) {
	calls := 0
	base := newTestScanHandler(t, scanServiceFunc(func(context.Context, string) (*risk.RiskAssessment, error) {
		calls++
		if calls == 1 {
			panic("test panic")
		}
		return testAssessment(), nil
	}), time.Second, 1)
	handler := middleware.Recovery(slog.New(slog.NewTextHandler(io.Discard, nil)))(base)

	panicked := scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
	if panicked.Code != http.StatusInternalServerError || !strings.Contains(panicked.Body.String(), `"code":"internal_error"`) {
		t.Fatalf("panic response = %d %s", panicked.Code, panicked.Body)
	}
	recovered := scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
	if recovered.Code != http.StatusOK {
		t.Fatalf("second scan status = %d, want 200 after panic recovery: %s", recovered.Code, recovered.Body)
	}
}

func TestScanHandlerRejectsInvalidRequests(t *testing.T) {
	var calls int
	handler := newTestScanHandler(t, scanServiceFunc(func(context.Context, string) (*risk.RiskAssessment, error) {
		calls++
		return testAssessment(), nil
	}), time.Second, 1)
	tests := []struct {
		name      string
		method    string
		body      string
		status    int
		errorCode string
	}{
		{"empty target", http.MethodPost, `{"target_url":" "}`, http.StatusBadRequest, "invalid_request"},
		{"malformed JSON", http.MethodPost, `{"target_url":`, http.StatusBadRequest, "invalid_request"},
		{"unknown field", http.MethodPost, `{"target_url":"https://example.com","other":true}`, http.StatusBadRequest, "invalid_request"},
		{"empty body", http.MethodPost, "", http.StatusBadRequest, "invalid_request"},
		{"oversized body", http.MethodPost, `{"target_url":"https://example.com","padding":"` + strings.Repeat("x", 1<<20) + `"}`, http.StatusRequestEntityTooLarge, "request_too_large"},
		{"trailing JSON value", http.MethodPost, `{"target_url":"https://example.com"} {}`, http.StatusBadRequest, "invalid_request"},
		{"invalid URL", http.MethodPost, `{"target_url":"not a url"}`, http.StatusBadRequest, "invalid_target"},
		{"unsupported scheme", http.MethodPost, `{"target_url":"ftp://example.com"}`, http.StatusBadRequest, "invalid_target"},
		{"embedded credentials", http.MethodPost, `{"target_url":"https://` + "user" + ":pass@" + `example.com"}`, http.StatusBadRequest, "invalid_target"},
		{"wrong method", http.MethodGet, `{"target_url":"https://example.com"}`, http.StatusMethodNotAllowed, "method_not_allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := scanRequest(handler, tt.method, tt.body)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tt.status, response.Body)
			}
			var payload struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("error response is not JSON: %v", err)
			}
			if payload.Error.Code != tt.errorCode {
				t.Errorf("error code = %q, want %q", payload.Error.Code, tt.errorCode)
			}
			if payload.Error.RequestID == "" || payload.Error.RequestID != response.Header().Get(middleware.RequestIDHeader) {
				t.Errorf("request ID was not propagated: body=%q header=%q", payload.Error.RequestID, response.Header().Get(middleware.RequestIDHeader))
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid requests invoked service %d times", calls)
	}
}

func TestScanHandlerMapsServiceErrorsSafely(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"blocked destination", ErrDestinationNotAllowed, http.StatusBadRequest, "destination_not_allowed"},
		{"invalid target", ErrInvalidTarget, http.StatusBadRequest, "invalid_target"},
		{"timeout", context.DeadlineExceeded, http.StatusGatewayTimeout, "scan_timeout"},
		{"canceled", context.Canceled, http.StatusRequestTimeout, "scan_canceled"},
		{"internal", errors.New("sensitive internal implementation detail"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestScanHandler(t, scanServiceFunc(func(context.Context, string) (*risk.RiskAssessment, error) {
				return nil, tt.err
			}), time.Second, 1)
			response := scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
			if response.Code != tt.status || !strings.Contains(response.Body.String(), `"code":"`+tt.code+`"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body)
			}
			if strings.Contains(response.Body.String(), "sensitive internal implementation detail") {
				t.Fatal("internal error details leaked to client")
			}
		})
	}
}

func TestScanHandlerAppliesTimeout(t *testing.T) {
	handler := newTestScanHandler(t, scanServiceFunc(func(ctx context.Context, _ string) (*risk.RiskAssessment, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}), 20*time.Millisecond, 1)
	response := scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
	if response.Code != http.StatusGatewayTimeout || !strings.Contains(response.Body.String(), `"code":"scan_timeout"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body)
	}
}

func TestScanHandlerDoesNotReturnSuccessAfterTimeout(t *testing.T) {
	handler := newTestScanHandler(t, scanServiceFunc(func(context.Context, string) (*risk.RiskAssessment, error) {
		time.Sleep(40 * time.Millisecond)
		return testAssessment(), nil
	}), 20*time.Millisecond, 1)
	response := scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
	if response.Code != http.StatusGatewayTimeout || !strings.Contains(response.Body.String(), `"code":"scan_timeout"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body)
	}
}

func TestScanHandlerPropagatesClientCancellation(t *testing.T) {
	started := make(chan struct{})
	handler := newTestScanHandler(t, scanServiceFunc(func(ctx context.Context, _ string) (*risk.RiskAssessment, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}), time.Second, 1)
	ctx, cancel := context.WithCancel(context.Background())
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target_url":"https://example.com"}`)).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(done)
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after client cancellation")
	}
	if recorder.Code != http.StatusRequestTimeout || !strings.Contains(recorder.Body.String(), `"code":"scan_canceled"`) {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body)
	}
}

func TestScanHandlerRejectsWhenCapacityIsExhausted(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	handler := newTestScanHandler(t, scanServiceFunc(func(_ context.Context, _ string) (*risk.RiskAssessment, error) {
		once.Do(func() { close(started) })
		<-release
		return testAssessment(), nil
	}), time.Second, 1)

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
	}()
	<-started
	response := scanRequest(handler, http.MethodPost, `{"target_url":"https://example.com"}`)
	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), `"code":"scan_capacity_exhausted"`) {
		close(release)
		t.Fatalf("capacity response = %d %s", response.Code, response.Body)
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first scan did not complete")
	}
}

func TestNewScanHandlerRejectsInvalidConfiguration(t *testing.T) {
	service := scanServiceFunc(func(context.Context, string) (*risk.RiskAssessment, error) { return testAssessment(), nil })
	for _, tc := range []struct {
		timeout     time.Duration
		concurrency int
	}{
		{0, 1},
		{time.Second, 0},
	} {
		if _, err := NewScanHandler(service, tc.timeout, tc.concurrency, nil); err == nil {
			t.Errorf("NewScanHandler accepted timeout=%s concurrency=%d", tc.timeout, tc.concurrency)
		}
	}
	if _, err := NewScanHandler(nil, time.Second, 1, nil); err == nil {
		t.Error("NewScanHandler accepted nil service")
	}
}

func TestScanHandlerOriginAndContentTypeSecurity(t *testing.T) {
	service := scanServiceFunc(func(context.Context, string) (*risk.RiskAssessment, error) {
		return testAssessment(), nil
	})
	handler := newTestScanHandler(t, service, 5*time.Second, 2)

	// 1. External Origin rejected
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target_url":"https://example.com"}`))
	req.Header.Set("Origin", "https://malicious.evil.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for external origin, got %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "forbidden_origin") {
		t.Errorf("expected forbidden_origin error code, got: %s", w.Body)
	}

	// 2. Loopback Origin accepted
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target_url":"https://example.com"}`))
	req.Header.Set("Origin", "http://localhost:3000")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for localhost origin, got %d: %s", w.Code, w.Body)
	}

	// 3. Non-JSON Content-Type rejected
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target_url":"https://example.com"}`))
	req.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 Unsupported Media Type for text/plain, got %d: %s", w.Code, w.Body)
	}

	// 4. JSON Content-Type accepted
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"target_url":"https://example.com"}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for application/json Content-Type, got %d: %s", w.Code, w.Body)
	}
}
