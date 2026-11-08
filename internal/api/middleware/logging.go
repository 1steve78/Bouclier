package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Logging logs request metadata and outcomes without recording bodies or query values.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			recorder := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(recorder, r)
			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			requestID, _ := RequestIDFromContext(r.Context())
			args := []any{
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
				"duration", time.Since(start),
			}
			if status >= http.StatusInternalServerError {
				logger.ErrorContext(r.Context(), "HTTP request", args...)
				return
			}
			logger.InfoContext(r.Context(), "HTTP request", args...)
		})
	}
}
