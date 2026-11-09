package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Application.Name != "Bouclier" || c.Application.Version != "1.1.0-dev" || c.Application.Environment != "development" {
		t.Fatalf("unexpected application defaults: %+v", c.Application)
	}
	if c.Scanner.HTTPTimeout != 8*time.Second || c.Scanner.TLSHandshakeTimeout != 5*time.Second || c.Scanner.MaxRedirects != 5 || c.Scanner.MaxConcurrentScans != 10 || c.Scanner.UserAgent != "Bouclier/1.1.0-dev" {
		t.Fatalf("unexpected scanner defaults: %+v", c.Scanner)
	}
	if c.HTTPServer.Host != "127.0.0.1" || c.HTTPServer.Port != 8081 ||
		c.HTTPServer.ReadHeaderTimeout != 5*time.Second || c.HTTPServer.ReadTimeout != 15*time.Second ||
		c.HTTPServer.WriteTimeout != 30*time.Second || c.HTTPServer.IdleTimeout != 60*time.Second ||
		c.HTTPServer.MaxScanDuration != 20*time.Second {
		t.Fatalf("unexpected HTTP server defaults: %+v", c.HTTPServer)
	}
	if c.Storage.DatabasePath == "" || c.Storage.CacheTTL != 24*time.Hour || c.ThreatIntel.FeedUpdateInterval != 24*time.Hour || c.Logging.Level != "info" {
		t.Fatalf("unexpected remaining defaults: %+v", c)
	}
	if c.AI.Enabled || c.AI.Ollama.BaseURL != "http://127.0.0.1:11434" ||
		c.AI.Ollama.Model != "llama3.2" || c.AI.Timeout != 90*time.Second || c.AI.MaxTokens != 512 {
		t.Fatalf("unexpected AI defaults: %+v", c.AI)
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
		{name: "redirects above supported maximum", data: `{"scanner":{"max_redirects":21}}`, wantErr: "max_redirects"},
		{name: "invalid concurrency", data: `{"scanner":{"max_concurrent_scans":0}}`, wantErr: "max_concurrent_scans"},
		{name: "empty user agent", data: `{"scanner":{"user_agent":" "}}`, wantErr: "user_agent"},
		{name: "invalid log level", data: `{"logging":{"level":"trace"}}`, wantErr: "logging.level"},
		{name: "invalid HTTP host", data: `{"http_server":{"host":"0.0.0.0"}}`, wantErr: "unspecified address"},
		{name: "invalid HTTP port", data: `{"http_server":{"port":65536}}`, wantErr: "http_server.port"},
		{name: "invalid HTTP timeout", data: `{"http_server":{"read_timeout":"soon"}}`, wantErr: "read_timeout"},
		{name: "non-positive HTTP timeout", data: `{"http_server":{"idle_timeout":"0s"}}`, wantErr: "idle_timeout"},
		{name: "invalid scan duration", data: `{"http_server":{"max_scan_duration":"soon"}}`, wantErr: "max_scan_duration"},
		{name: "non-positive scan duration", data: `{"http_server":{"max_scan_duration":"0s"}}`, wantErr: "max_scan_duration"},
		{name: "invalid AI timeout", data: `{"ai":{"timeout":"soon"}}`, wantErr: "ai.timeout"},
		{name: "invalid AI token limit", data: `{"ai":{"max_tokens":9000}}`, wantErr: "ai.max_tokens"},
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
			if got.HTTPServer.Host != "127.0.0.1" || got.HTTPServer.Port != 8081 {
				t.Fatalf("missing HTTP settings did not use defaults: %+v", got.HTTPServer)
			}
		})
	}
}

func TestAIConfigRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.Ollama.Model = "qwen2.5:7b"
	cfg.AI.Timeout = 2 * time.Minute
	cfg.AI.MaxTokens = 768
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromReader(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.AI.Enabled || loaded.AI.Ollama.Model != "qwen2.5:7b" ||
		loaded.AI.Timeout != 2*time.Minute || loaded.AI.MaxTokens != 768 {
		t.Fatalf("AI config did not round-trip: %+v", loaded.AI)
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
		{"AI timeout", func(c *Config) { c.AI.Timeout = 0 }},
		{"AI token limit", func(c *Config) { c.AI.MaxTokens = 0 }},
		{"enabled AI model", func(c *Config) { c.AI.Enabled = true; c.AI.Ollama.Model = " " }},
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

func TestValidateMaxRedirectsBoundaries(t *testing.T) {
	for _, redirects := range []int{0, MaxRedirectsLimit} {
		cfg := Default()
		cfg.Scanner.MaxRedirects = redirects
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected max_redirects=%d: %v", redirects, err)
		}
	}

	for _, redirects := range []int{-1, MaxRedirectsLimit + 1} {
		cfg := Default()
		cfg.Scanner.MaxRedirects = redirects
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "scanner.max_redirects") {
			t.Errorf("Validate() error for max_redirects=%d = %v, want redirect-limit error", redirects, err)
		}
	}
}

func TestDurationJSONSerialization(t *testing.T) {
	data, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"http_timeout":"8s"`) ||
		!strings.Contains(string(data), `"cache_ttl":"24h0m0s"`) ||
		!strings.Contains(string(data), `"read_header_timeout":"5s"`) ||
		!strings.Contains(string(data), `"max_scan_duration":"20s"`) {
		t.Fatalf("duration values were not serialized as strings: %s", data)
	}
}

func TestHTTPServerConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HTTPServerConfig)
	}{
		{"empty host", func(c *HTTPServerConfig) { c.Host = " " }},
		{"wildcard IPv4", func(c *HTTPServerConfig) { c.Host = "0.0.0.0" }},
		{"wildcard IPv6", func(c *HTTPServerConfig) { c.Host = "::" }},
		{"non-loopback IPv4", func(c *HTTPServerConfig) { c.Host = "192.168.1.10" }},
		{"public IPv6", func(c *HTTPServerConfig) { c.Host = "2001:4860:4860::8888" }},
		{"hostname", func(c *HTTPServerConfig) { c.Host = "localhost" }},
		{"port too low", func(c *HTTPServerConfig) { c.Port = 0 }},
		{"port too high", func(c *HTTPServerConfig) { c.Port = 65536 }},
		{"read header timeout", func(c *HTTPServerConfig) { c.ReadHeaderTimeout = 0 }},
		{"read timeout", func(c *HTTPServerConfig) { c.ReadTimeout = 0 }},
		{"write timeout", func(c *HTTPServerConfig) { c.WriteTimeout = 0 }},
		{"idle timeout", func(c *HTTPServerConfig) { c.IdleTimeout = 0 }},
		{"maximum scan duration", func(c *HTTPServerConfig) { c.MaxScanDuration = 0 }},
		{"scan duration exceeds write timeout", func(c *HTTPServerConfig) { c.MaxScanDuration = c.WriteTimeout }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default().HTTPServer
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() succeeded for invalid HTTP server configuration")
			}
		})
	}
}

func TestHTTPServerConfigValidateAllowsLoopbackIPs(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
		t.Run(host, func(t *testing.T) {
			cfg := Default().HTTPServer
			cfg.Host = host
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() rejected loopback host %q: %v", host, err)
			}
		})
	}
}
