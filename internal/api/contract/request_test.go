package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"bouclier/internal/report"
	"bouclier/internal/risk"
)

func TestDecodeScanURLRequest(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantTarget string
		wantStatus int
		wantCode   string
	}{
		{"valid", `{"target_url":"https://example.com"}`, "https://example.com", 0, ""},
		{"invalid JSON", `{"target_url":`, "", http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"unknown field", `{"target_url":"https://example.com","extra":true}`, "", http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"empty body", "", "", http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"missing target", `{}`, "", http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"trailing JSON value", `{"target_url":"https://example.com"} {}`, "", http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"trailing garbage", `{"target_url":"https://example.com"} x`, "", http.StatusBadRequest, ErrorCodeInvalidRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := DecodeScanURLRequest(httpRequest(tt.body))
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("DecodeScanURLRequest() error = %v", err)
				}
				if request.TargetURL != tt.wantTarget {
					t.Errorf("TargetURL = %q, want %q", request.TargetURL, tt.wantTarget)
				}
				return
			}
			var decodeErr *RequestDecodeError
			if !errors.As(err, &decodeErr) {
				t.Fatalf("DecodeScanURLRequest() error = %v, want *RequestDecodeError", err)
			}
			if decodeErr.StatusCode != tt.wantStatus || decodeErr.Code != tt.wantCode {
				t.Errorf("decode error = %+v, want status %d code %q", decodeErr, tt.wantStatus, tt.wantCode)
			}
		})
	}
}

func TestDecodeScanURLRequestRejectsOversizedBody(t *testing.T) {
	body := `{"target_url":"` + strings.Repeat("a", MaxRequestBodyBytes) + `"}`
	_, err := DecodeScanURLRequest(httpRequest(body))
	var decodeErr *RequestDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("DecodeScanURLRequest() error = %v, want *RequestDecodeError", err)
	}
	if decodeErr.StatusCode != http.StatusRequestEntityTooLarge || decodeErr.Code != ErrorCodeRequestTooLarge {
		t.Fatalf("decode error = %+v, want request-too-large classification", decodeErr)
	}
}

func TestMarshalSuccess(t *testing.T) {
	body, err := MarshalSuccess(map[string]string{"status": "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), `{"data":{"status":"ok"}}`; got != want {
		t.Errorf("MarshalSuccess() = %s, want %s", got, want)
	}
}

func TestReportJSONRemainsCanonical(t *testing.T) {
	assessment, err := risk.CalculateRisk(nil, risk.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	body, err := report.RenderJSON(assessment)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(assessment)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	var canonicalFields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &canonicalFields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(jsonFieldNames(decoded), jsonFieldNames(canonicalFields)) {
		t.Errorf("report renderer changed canonical fields: got %v, want %v", jsonFieldNames(decoded), jsonFieldNames(canonicalFields))
	}
	if got := strings.TrimSpace(string(decoded["schema_version"])); got != `"bouclier-risk/v1"` {
		t.Errorf("schema_version = %s, want %q", got, "bouclier-risk/v1")
	}
	if bytes.HasPrefix(body, []byte(`{"data":`)) {
		t.Fatal("canonical risk report was wrapped in the API success envelope")
	}
}

func jsonFieldNames(fields map[string]json.RawMessage) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func httpRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(body))
}
