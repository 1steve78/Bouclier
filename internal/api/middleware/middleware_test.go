package middleware

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDGeneratedAndPropagated(t *testing.T) {
	var contextID string
	handler := RequestID(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok {
			t.Error("request ID missing from context")
		}
		contextID = id
		if got := r.Header.Get(RequestIDHeader); got != "untrusted-client-value" {
			t.Errorf("client header was unexpectedly modified in request: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(RequestIDHeader, "untrusted-client-value")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	id := recorder.Header().Get(RequestIDHeader)
	if len(id) != 32 || id == "untrusted-client-value" {
		t.Fatalf("response request ID = %q, want server-generated 32-char hex", id)
	}
	if contextID != id {
		t.Errorf("context request ID = %q, response header = %q", contextID, id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("request ID is not hexadecimal: %v", err)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("sensitive response"))
	}))
	request := httptest.NewRequest(http.MethodPost, "/health?token=do-not-log", strings.NewReader("sensitive request body"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	output := logs.String()
	for _, expected := range []string{`"method":"POST"`, `"path":"/health"`, `"status":201`} {
		if !strings.Contains(output, expected) {
			t.Errorf("log missing %s: %s", expected, output)
		}
	}
	for _, sensitive := range []string{"do-not-log", "sensitive request body", "sensitive response"} {
		if strings.Contains(output, sensitive) {
			t.Errorf("log contains sensitive content %q: %s", sensitive, output)
		}
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Recovery(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("private panic detail")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "private panic detail") ||
		strings.Contains(recorder.Body.String(), "goroutine") {
		t.Fatalf("response leaked panic details: %s", recorder.Body.String())
	}
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload.Error.Code != "internal_error" || payload.Error.Message != "An internal server error occurred." {
		t.Errorf("unexpected error payload: %+v", payload.Error)
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("recovered panic response is missing security headers")
	}
	if strings.Contains(logs.String(), "goroutine") {
		t.Errorf("panic recovery emitted a stack trace: %s", logs.String())
	}
}

func TestWriteJSONErrorIncludesRequestID(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set(RequestIDHeader, "server-generated-id")
	WriteJSONError(recorder, http.StatusBadRequest, "invalid_request", "The request is invalid.")

	var response struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("error response is not JSON: %v", err)
	}
	if response.Error.Code != "invalid_request" ||
		response.Error.Message != "The request is invalid." ||
		response.Error.RequestID != "server-generated-id" {
		t.Errorf("unexpected error response: %+v", response.Error)
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	for header, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":           "no-store",
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}
