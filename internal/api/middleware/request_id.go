package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"

	"bouclier/internal/api/contract"
)

const RequestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

// RequestIDFromContext returns the server-generated request ID, when present.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(string)
	return id, ok
}

// RequestID replaces any client-supplied ID with a fresh server-generated ID.
func RequestID(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var idBytes [16]byte
			if _, err := rand.Read(idBytes[:]); err != nil {
				logger.ErrorContext(r.Context(), "generate request ID", "error", err)
				WriteJSONError(w, http.StatusInternalServerError, contract.ErrorCodeInternal, "An internal server error occurred.")
				return
			}
			id := hex.EncodeToString(idBytes[:])
			w.Header().Set(RequestIDHeader, id)
			ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
