package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Application.Name != "Bouclier" || c.Application.Version != "0.1.0-dev" || c.Application.Environment != "development" {
		t.Fatalf("unexpected application defaults: %+v", c.Application)
	}
	if c.Scanner.HTTPTimeout != 8*time.Second || c.Scanner.TLSHandshakeTimeout != 5*time.Second || c.Scanner.MaxRedirects != 5 || c.Scanner.MaxConcurrentScans != 10 || c.Scanner.UserAgent != "Bouclier/0.1.0-dev" {
		t.Fatalf("unexpected scanner defaults: %+v", c.Scanner)
	}
	if c.Storage.DatabasePath == "" || c.Storage.CacheTTL != 24*time.Hour || c.ThreatIntel.FeedUpdateInterval != 24*time.Hour || c.Logging.Level != "info" {
		t.Fatalf("unexpected remaining defaults: %+v", c)
	}
}

func TestLoadFromReader(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{name: "valid JSON", data: `{"scanner":{"http_timeout":"9s"}}`},
		{name: "invalid JSON", data: `{`, wantErr: "decode configuration"},
		{name: "invalid duration", data: `{"scanner":{"http_timeout":"soon"}}`, wantErr: "http_timeout"},
		{name: "negative redirects", data: `{"scanner":{"max_redirects":-1}}`, wantErr: "max_redirects"},
		{name: "invalid concurrency", data: `{"scanner":{"max_concurrent_scans":0}}`, wantErr: "max_concurrent_scans"},
		{name: "empty user agent", data: `{"scanner":{"user_agent":" "}}`, wantErr: "user_agent"},
		{name: "invalid log level", data: `{"logging":{"level":"trace"}}`, wantErr: "logging.level"},
		{name: "unknown field", data: `{"scanner":{"mystery":true}}`, wantErr: "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadFromReader(strings.NewReader(tt.data))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadFromReader() error = %v, want text %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFromReader() error = %v", err)
			}
			if got.Scanner.HTTPTimeout != 9*time.Second {
				t.Fatalf("HTTPTimeout = %s, want 9s", got.Scanner.HTTPTimeout)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("missing-config-file.json"); err == nil || !strings.Contains(err.Error(), "open configuration") {
		t.Fatalf("Load() error = %v, want informative missing-file error", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"HTTP timeout", func(c *Config) { c.Scanner.HTTPTimeout = 0 }},
		{"TLS timeout", func(c *Config) { c.Scanner.TLSHandshakeTimeout = -1 }},
		{"redirect count", func(c *Config) { c.Scanner.MaxRedirects = -1 }},
		{"concurrency", func(c *Config) { c.Scanner.MaxConcurrentScans = 0 }},
		{"user agent", func(c *Config) { c.Scanner.UserAgent = "" }},
		{"database path", func(c *Config) { c.Storage.DatabasePath = " " }},
		{"log level", func(c *Config) { c.Logging.Level = "verbose" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatal("Validate() succeeded for invalid configuration")
			}
		})
	}
}

func TestDurationJSONSerialization(t *testing.T) {
	data, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"http_timeout":"8s"`) || !strings.Contains(string(data), `"cache_ttl":"24h0m0s"`) {
		t.Fatalf("duration values were not serialized as strings: %s", data)
	}
}
