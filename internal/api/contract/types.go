package contract

// SuccessResponse is the standard envelope for successful operation responses.
type SuccessResponse[T any] struct {
	Data T `json:"data"`
}

// ErrorResponse is the standard public API error envelope.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

const (
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeRequestTooLarge    = "request_too_large"
	ErrorCodeNotFound           = "not_found"
	ErrorCodeMethodNotAllowed   = "method_not_allowed"
	ErrorCodeConflict           = "conflict"
	ErrorCodeInvalidTarget      = "invalid_target"
	ErrorCodeDestinationBlocked = "destination_not_allowed"
	ErrorCodeScanTimeout        = "scan_timeout"
	ErrorCodeScanCanceled       = "scan_canceled"
	ErrorCodeScanCapacity       = "scan_capacity_exhausted"
	ErrorCodeServiceUnavailable = "scan_service_unavailable"
	ErrorCodeInternal           = "internal_error"
)

// HealthResponse reports process liveness.
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// ReadinessResponse reports API initialization readiness.
type ReadinessResponse struct {
	Status string `json:"status"`
}

// MetadataResponse describes the public API version.
type MetadataResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
