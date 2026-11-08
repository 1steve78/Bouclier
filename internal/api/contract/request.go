package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const MaxRequestBodyBytes = 1 << 20

// ScanURLRequest is the request contract reserved for a future URL scan operation.
type ScanURLRequest struct {
	TargetURL string `json:"target_url"`
}

// RequestDecodeError contains a safe client-facing classification for a decode failure.
type RequestDecodeError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *RequestDecodeError) Error() string {
	return e.Message
}

// DecodeScanURLRequest strictly decodes a bounded JSON request. It performs no
// URL resolution, network access, or scanning.
func DecodeScanURLRequest(r *http.Request) (ScanURLRequest, error) {
	var request ScanURLRequest
	if r == nil || r.Body == nil {
		return request, invalidRequest("A JSON request body is required.")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodyBytes+1))
	if err != nil {
		return request, invalidRequest("The request body could not be read.")
	}
	if len(body) > MaxRequestBodyBytes {
		return request, &RequestDecodeError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Code:       ErrorCodeRequestTooLarge,
			Message:    "The request body exceeds the allowed size.",
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		if errors.Is(err, io.EOF) {
			return ScanURLRequest{}, invalidRequest("A JSON request body is required.")
		}
		var typeError *json.UnmarshalTypeError
		if errors.As(err, &typeError) {
			return ScanURLRequest{}, invalidRequest("The request body has an invalid JSON shape.")
		}
		return ScanURLRequest{}, invalidRequest("The request body must be valid JSON with only documented fields.")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ScanURLRequest{}, invalidRequest("The request body must contain exactly one JSON value.")
	}
	if strings.TrimSpace(request.TargetURL) == "" {
		return ScanURLRequest{}, invalidRequest("The target_url field is required.")
	}
	request.TargetURL = strings.TrimSpace(request.TargetURL)
	return request, nil
}

func invalidRequest(message string) *RequestDecodeError {
	return &RequestDecodeError{
		StatusCode: http.StatusBadRequest,
		Code:       ErrorCodeInvalidRequest,
		Message:    message,
	}
}

// MarshalSuccess serializes a successful response using the standard envelope.
func MarshalSuccess[T any](data T) ([]byte, error) {
	body, err := json.Marshal(SuccessResponse[T]{Data: data})
	if err != nil {
		return nil, fmt.Errorf("marshal API success response: %w", err)
	}
	return body, nil
}
