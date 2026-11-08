package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"bouclier/internal/api/middleware"
	"bouclier/internal/config"
)

const shutdownTimeout = 10 * time.Second

// NewServer constructs the HTTP server and registers the initial API routes.
func NewServer(cfg config.HTTPServerConfig, logger *slog.Logger) (*http.Server, error) {
	return newServer(cfg, logger, nil, 0)
}

// NewServerWithScanService constructs the HTTP server with a bounded scan endpoint.
func NewServerWithScanService(cfg config.HTTPServerConfig, logger *slog.Logger, service ScanService, maxConcurrentScans int) (*http.Server, error) {
	return newServer(cfg, logger, service, maxConcurrentScans)
}

func newServer(cfg config.HTTPServerConfig, logger *slog.Logger, service ScanService, maxConcurrentScans int) (*http.Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HTTP server configuration: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()
	var scanHandler http.Handler
	if service != nil {
		var err error
		scanHandler, err = NewScanHandler(service, cfg.MaxScanDuration, maxConcurrentScans, logger)
		if err != nil {
			return nil, fmt.Errorf("configure scan endpoint: %w", err)
		}
	}
	registerRoutes(mux, scanHandler)
	handler := middleware.Recovery(logger)(
		middleware.SecurityHeaders()(
			middleware.Logging(logger)(
				middleware.RequestID(logger)(mux),
			),
		),
	)

	return &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}, nil
}

// Serve starts an already-constructed server on an injected listener and shuts
// it down gracefully when ctx is canceled.
func Serve(ctx context.Context, server *http.Server, listener net.Listener, logger *slog.Logger) error {
	if server == nil {
		return errors.New("HTTP server cannot be nil")
	}
	if listener == nil {
		return errors.New("HTTP server listener cannot be nil")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return errors.New("HTTP server listener must be bound to a loopback TCP address")
	}
	if logger == nil {
		logger = slog.Default()
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()
	logger.InfoContext(ctx, "HTTP server started", "address", listener.Addr().String())

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("gracefully shut down HTTP server: %w", err)
		}
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP during shutdown: %w", err)
		}
		logger.Info("HTTP server stopped")
		return nil
	}
}
