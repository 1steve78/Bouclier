package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"bouclier/internal/config"
)

var (
	sensitiveKeyPattern = regexp.MustCompile(`(?i)\b(password|token|secret|api[_-]?key|access[_-]?key|auth(?:orization)?|cookie)\b`)
	logSecretPattern    = regexp.MustCompile(`(?i)\b(session(?:id)?|sid|auth(?:orization)?|jwt|token|password|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*([^&;\s,]+)`)
	logBearerPattern    = regexp.MustCompile(`(?i)(bearer\s+)[a-zA-Z0-9_\-\.]+`)
	logURLPattern       = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
)

func redactLogAttr(groups []string, a slog.Attr) slog.Attr {
	if sensitiveKeyPattern.MatchString(a.Key) {
		return slog.String(a.Key, "[redacted]")
	}
	if a.Value.Kind() == slog.KindString {
		val := a.Value.String()
		val = logBearerPattern.ReplaceAllString(val, "$1[redacted]")
		val = logSecretPattern.ReplaceAllString(val, "$1=[redacted]")
		val = logURLPattern.ReplaceAllStringFunc(val, func(raw string) string {
			if at := strings.LastIndex(raw, "@"); at >= 0 {
				if scheme := strings.Index(raw, "://"); scheme >= 0 && at > scheme+2 {
					raw = raw[:scheme+3] + raw[at+1:]
				}
			}
			return raw
		})
		return slog.String(a.Key, val)
	}
	return a
}

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

	options := &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactLogAttr,
	}
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
