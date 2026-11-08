package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"bouclier/internal/config"
)

type loggerContextKey struct{}

// New creates a logger configured with the requested level and output format.
func New(cfg config.LoggingConfig, writer io.Writer) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("unsupported log level %q: expected debug, info, warn, or error", cfg.Level)
	}
	if writer == nil {
		writer = os.Stderr
	}

	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Structured {
		handler = slog.NewJSONHandler(writer, options)
	} else {
		handler = slog.NewTextHandler(writer, options)
	}
	return slog.New(handler).With("app", "bouclier"), nil
}

// WithContext stores the application logger in a command context.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, logger)
}

// FromContext returns the logger installed by WithContext, if any.
func FromContext(ctx context.Context) (*slog.Logger, bool) {
	logger, ok := ctx.Value(loggerContextKey{}).(*slog.Logger)
	return logger, ok
}
