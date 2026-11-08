package middleware

import (
	"log/slog"
	"net/http"

	"bouclier/internal/api/contract"
)

// Recovery converts handler panics into a generic JSON error response.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recover() == nil {
					return
				}
				setSecurityHeaders(w)
				logger.ErrorContext(r.Context(), "recovered HTTP handler panic",
					"request_id", requestIDForLog(r),
					"method", r.Method,
					"path", r.URL.Path,
				)
				WriteJSONError(w, http.StatusInternalServerError, contract.ErrorCodeInternal, "An internal server error occurred.")
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func requestIDForLog(r *http.Request) string {
	id, _ := RequestIDFromContext(r.Context())
	return id
}
