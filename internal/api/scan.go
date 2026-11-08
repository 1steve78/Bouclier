package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bouclier/internal/api/contract"
	"bouclier/internal/api/middleware"
	"bouclier/internal/heuristics"
	"bouclier/internal/report"
	"bouclier/internal/risk"
)

var ErrDestinationNotAllowed = errors.New("scan destination is not allowed")
var ErrInvalidTarget = errors.New("scan target is invalid")

// ScanService is the application boundary used by the HTTP API.
type ScanService interface {
	Scan(ctx context.Context, target string) (*risk.RiskAssessment, error)
}

// NewScanHandler creates a bounded synchronous scan handler.
func NewScanHandler(service ScanService, maxDuration time.Duration, maxConcurrent int, logger *slog.Logger) (http.Handler, error) {
	if service == nil {
		return nil, errors.New("scan service is required")
	}
	if maxDuration <= 0 {
		return nil, errors.New("maximum scan duration must be positive")
	}
	if maxConcurrent <= 0 {
		return nil, errors.New("maximum concurrent scans must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &scanHandler{
		service: service,
		timeout: maxDuration,
		slots:   make(chan struct{}, maxConcurrent),
		logger:  logger,
	}, nil
}

type scanHandler struct {
	service ScanService
	timeout time.Duration
	slots   chan struct{}
	logger  *slog.Logger
}

func (h *scanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		middleware.WriteJSONError(w, http.StatusMethodNotAllowed, contract.ErrorCodeMethodNotAllowed, "The requested method is not allowed.")
		return
	}

	// Reject cross-origin requests from external web origins (protects loopback API against CSRF/drive-by scanning)
	if origin := r.Header.Get("Origin"); origin != "" {
		if !isAllowedOrigin(origin) {
			middleware.WriteJSONError(w, http.StatusForbidden, "forbidden_origin", "Cross-origin requests from external web origins are not permitted.")
			return
		}
	}

	// Validate Content-Type if specified
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
		if mediaType != "application/json" {
			middleware.WriteJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
			return
		}
	}

	request, err := contract.DecodeScanURLRequest(r)
	if err != nil {
		var decodeErr *contract.RequestDecodeError
		if !errors.As(err, &decodeErr) {
			h.writeInternalError(w, r, "decode scan request", err)
			return
		}
		middleware.WriteJSONError(w, decodeErr.StatusCode, decodeErr.Code, decodeErr.Message)
		return
	}
	target, err := heuristics.NormalizeURL(request.TargetURL)
	if err != nil || target.HasUserInfo {
		middleware.WriteJSONError(w, http.StatusBadRequest, contract.ErrorCodeInvalidTarget, "The target_url must be an absolute HTTP or HTTPS URL without embedded credentials.")
		return
	}

	select {
	case <-r.Context().Done():
		middleware.WriteJSONError(w, http.StatusRequestTimeout, contract.ErrorCodeScanCanceled, "The scan request was canceled.")
		return
	case h.slots <- struct{}{}:
	default:
		middleware.WriteJSONError(w, http.StatusTooManyRequests, contract.ErrorCodeScanCapacity, "Scan capacity is currently exhausted.")
		return
	}
	defer func() { <-h.slots }()

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	assessment, err := h.service.Scan(ctx, target.Normalized)
	if ctx.Err() != nil {
		h.writeScanError(w, r, ctx.Err())
		return
	}
	if err != nil {
		h.writeScanError(w, r, err)
		return
	}
	if assessment == nil {
		h.writeInternalError(w, r, "scan service returned no assessment", errors.New("nil assessment"))
		return
	}

	body, err := report.RenderJSON(assessment)
	if err != nil {
		h.writeInternalError(w, r, "serialize scan report", err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		h.logger.ErrorContext(r.Context(), "write scan report",
			"request_id", requestID(r),
			"error", err,
		)
	}
}

func (h *scanHandler) writeScanError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalidTarget):
		middleware.WriteJSONError(w, http.StatusBadRequest, contract.ErrorCodeInvalidTarget, "The target_url is not supported.")
	case errors.Is(err, ErrDestinationNotAllowed):
		middleware.WriteJSONError(w, http.StatusBadRequest, contract.ErrorCodeDestinationBlocked, "The target resolves to a destination that is not allowed.")
	case errors.Is(err, context.DeadlineExceeded):
		middleware.WriteJSONError(w, http.StatusGatewayTimeout, contract.ErrorCodeScanTimeout, "The scan exceeded its maximum duration.")
	case errors.Is(err, context.Canceled):
		middleware.WriteJSONError(w, http.StatusRequestTimeout, contract.ErrorCodeScanCanceled, "The scan request was canceled.")
	default:
		h.writeInternalError(w, r, "scan failed", err)
	}
}

func (h *scanHandler) writeInternalError(w http.ResponseWriter, r *http.Request, message string, err error) {
	h.logger.ErrorContext(r.Context(), message,
		"request_id", requestID(r),
		"error", err,
	)
	middleware.WriteJSONError(w, http.StatusInternalServerError, contract.ErrorCodeInternal, "An internal server error occurred.")
}

func requestID(r *http.Request) string {
	id, _ := middleware.RequestIDFromContext(r.Context())
	return id
}

func isAllowedOrigin(originStr string) bool {
	u, err := url.Parse(originStr)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

var _ http.Handler = (*scanHandler)(nil)
