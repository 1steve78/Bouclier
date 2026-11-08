package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"bouclier/internal/config"
)

func TestJSONLogger(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(config.LoggingConfig{Level: "info", Structured: true}, &output)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("ready", "component", "startup")

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("logger output is not valid JSON: %v; output=%q", err, output.String())
	}
	if record["msg"] != "ready" || record["app"] != "bouclier" || record["component"] != "startup" {
		t.Fatalf("unexpected structured log record: %#v", record)
	}
}

func TestTextLogger(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(config.LoggingConfig{Level: "info"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("ready", "component", "startup")
	for _, want := range []string{"level=INFO", "msg=ready", "app=bouclier", "component=startup"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("text output %q does not contain %q", output.String(), want)
		}
	}
}

type testLogger interface {
	Debug(string, ...any)
	Info(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		log      func(testLogger)
		want     []string
		unwanted []string
	}{
		{"debug enables debug", "debug", func(l testLogger) { l.Debug("debug message") }, []string{"debug message"}, nil},
		{"info filters debug", "info", func(l testLogger) { l.Debug("debug message"); l.Info("info message") }, []string{"info message"}, []string{"debug message"}},
		{"warn level", "warn", func(l testLogger) { l.Info("info message"); l.Warn("warn message"); l.Error("error message") }, []string{"warn message", "error message"}, []string{"info message"}},
		{"error level", "error", func(l testLogger) { l.Warn("warn message"); l.Error("error message") }, []string{"error message"}, []string{"warn message"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger, err := New(config.LoggingConfig{Level: tt.level}, &output)
			if err != nil {
				t.Fatal(err)
			}
			tt.log(logger)
			for _, want := range tt.want {
				if !strings.Contains(output.String(), want) {
					t.Errorf("output %q does not contain %q", output.String(), want)
				}
			}
			for _, unwanted := range tt.unwanted {
				if strings.Contains(output.String(), unwanted) {
					t.Errorf("output %q unexpectedly contains %q", output.String(), unwanted)
				}
			}
		})
	}
}

func TestInvalidLogLevel(t *testing.T) {
	if _, err := New(config.LoggingConfig{Level: "trace"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unsupported log level") {
		t.Fatalf("New() error = %v, want descriptive unsupported-level error", err)
	}
}

func TestSensitiveDataRedactedInLogs(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(config.LoggingConfig{Level: "debug", Structured: true}, &output)
	if err != nil {
		t.Fatal(err)
	}

	secretToken := "secret-api-token-987654"
	passwordVal := "SuperSecretPassword123"

	logger.Debug("performing authentication",
		"auth_header", "Bearer "+secretToken,
		"password", passwordVal,
		"target_url", "https://admin:pass123@example.com/api?token="+secretToken,
	)

	out := output.String()
	if strings.Contains(out, secretToken) {
		t.Errorf("SECURITY LEAK: secret token leaked in log: %s", out)
	}
	if strings.Contains(out, passwordVal) {
		t.Errorf("SECURITY LEAK: password leaked in log: %s", out)
	}
	if strings.Contains(out, "admin:pass123@") {
		t.Errorf("SECURITY LEAK: embedded userinfo leaked in log: %s", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("expected [redacted] indicator in log: %s", out)
	}
}
