package middleware

import (
	"encoding/json"
	"net/http"

	"bouclier/internal/api/contract"
)

// WriteJSONError writes a public-safe, consistent JSON error response.
func WriteJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(contract.ErrorResponse{
		Error: contract.ErrorDetail{
			Code:      code,
			Message:   message,
			RequestID: w.Header().Get(RequestIDHeader),
		},
	})
}
