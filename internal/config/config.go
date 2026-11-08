package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const MaxRedirectsLimit = 20

// Config contains the settings used by the Bouclier application.
type Config struct {
	Application ApplicationConfig `json:"application"`
	HTTPServer  HTTPServerConfig  `json:"http_server"`
	Scanner     ScannerConfig     `json:"scanner"`
	AI          AIConfig          `json:"ai"`
	Storage     StorageConfig     `json:"storage"`
	ThreatIntel ThreatIntelConfig `json:"threat_intelligence"`
	Logging     LoggingConfig     `json:"logging"`
}

// HTTPServerConfig contains settings for the Bouclier HTTP API server.
type HTTPServerConfig struct {
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	ReadHeaderTimeout time.Duration `json:"read_header_timeout"`
	ReadTimeout       time.Duration `json:"read_timeout"`
	WriteTimeout      time.Duration `json:"write_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout"`
	MaxScanDuration   time.Duration `json:"max_scan_duration"`
}

type ApplicationConfig struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
}

type ScannerConfig struct {
	HTTPTimeout         time.Duration `json:"http_timeout"`
	TLSHandshakeTimeout time.Duration `json:"tls_handshake_timeout"`
	MaxRedirects        int           `json:"max_redirects"`
	MaxConcurrentScans  int           `json:"max_concurrent_scans"`
	UserAgent           string        `json:"user_agent"`
}

type AIConfig struct {
	Enabled   bool          `json:"enabled"`
	Ollama    OllamaConfig  `json:"ollama"`
	Timeout   time.Duration `json:"timeout"`
	MaxTokens int           `json:"max_tokens"`
}

type OllamaConfig struct {
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`
}

type StorageConfig struct {
	DatabasePath string        `json:"database_path"`
	CacheTTL     time.Duration `json:"cache_ttl"`
}

type ThreatIntelConfig struct {
	FeedUpdateInterval time.Duration `json:"feed_update_interval"`
	FeedURLs           []string      `json:"feed_urls"`
}

type LoggingConfig struct {
	Level      string `json:"level"`
	Structured bool   `json:"structured"`
}

type jsonConfig struct {
	Application ApplicationConfig `json:"application"`
	HTTPServer  struct {
		Host              string `json:"host"`
		Port              int    `json:"port"`
		ReadHeaderTimeout string `json:"read_header_timeout"`
		ReadTimeout       string `json:"read_timeout"`
		WriteTimeout      string `json:"write_timeout"`
		IdleTimeout       string `json:"idle_timeout"`
		MaxScanDuration   string `json:"max_scan_duration"`
	} `json:"http_server"`
	Scanner struct {
		HTTPTimeout         string `json:"http_timeout"`
		TLSHandshakeTimeout string `json:"tls_handshake_timeout"`
		MaxRedirects        int    `json:"max_redirects"`
		MaxConcurrentScans  int    `json:"max_concurrent_scans"`
		UserAgent           string `json:"user_agent"`
	} `json:"scanner"`
	AI struct {
		Enabled bool `json:"enabled"`
		Ollama  struct {
			BaseURL string `json:"base_url"`
			Model   string `json:"model"`
		} `json:"ollama"`
		Timeout   string `json:"timeout"`
		MaxTokens int    `json:"max_tokens"`
	} `json:"ai"`
	Storage struct {
		DatabasePath string `json:"database_path"`
		CacheTTL     string `json:"cache_ttl"`
	} `json:"storage"`
	ThreatIntel struct {
		FeedUpdateInterval string   `json:"feed_update_interval"`
		FeedURLs           []string `json:"feed_urls"`
	} `json:"threat_intelligence"`
	Logging LoggingConfig `json:"logging"`
}

func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Application ApplicationConfig `json:"application"`
		HTTPServer  struct {
			Host              string `json:"host"`
			Port              int    `json:"port"`
			ReadHeaderTimeout string `json:"read_header_timeout"`
			ReadTimeout       string `json:"read_timeout"`
			WriteTimeout      string `json:"write_timeout"`
			IdleTimeout       string `json:"idle_timeout"`
			MaxScanDuration   string `json:"max_scan_duration"`
		} `json:"http_server"`
		Scanner struct {
			HTTPTimeout         string `json:"http_timeout"`
			TLSHandshakeTimeout string `json:"tls_handshake_timeout"`
			MaxRedirects        int    `json:"max_redirects"`
			MaxConcurrentScans  int    `json:"max_concurrent_scans"`
			UserAgent           string `json:"user_agent"`
		} `json:"scanner"`
		AI struct {
			Enabled bool `json:"enabled"`
			Ollama  struct {
				BaseURL string `json:"base_url"`
				Model   string `json:"model"`
			} `json:"ollama"`
			Timeout   string `json:"timeout"`
			MaxTokens int    `json:"max_tokens"`
		} `json:"ai"`
		Storage struct {
			DatabasePath string `json:"database_path"`
			CacheTTL     string `json:"cache_ttl"`
		} `json:"storage"`
		ThreatIntel struct {
			FeedUpdateInterval string   `json:"feed_update_interval"`
			FeedURLs           []string `json:"feed_urls"`
		} `json:"threat_intelligence"`
		Logging LoggingConfig `json:"logging"`
	}{
		Application: c.Application,
		HTTPServer: struct {
			Host              string `json:"host"`
			Port              int    `json:"port"`
			ReadHeaderTimeout string `json:"read_header_timeout"`
			ReadTimeout       string `json:"read_timeout"`
			WriteTimeout      string `json:"write_timeout"`
			IdleTimeout       string `json:"idle_timeout"`
			MaxScanDuration   string `json:"max_scan_duration"`
		}{
			c.HTTPServer.Host, c.HTTPServer.Port,
			c.HTTPServer.ReadHeaderTimeout.String(), c.HTTPServer.ReadTimeout.String(),
			c.HTTPServer.WriteTimeout.String(), c.HTTPServer.IdleTimeout.String(),
			c.HTTPServer.MaxScanDuration.String(),
		},
		Scanner: struct {
			HTTPTimeout         string `json:"http_timeout"`
			TLSHandshakeTimeout string `json:"tls_handshake_timeout"`
			MaxRedirects        int    `json:"max_redirects"`
			MaxConcurrentScans  int    `json:"max_concurrent_scans"`
			UserAgent           string `json:"user_agent"`
		}{c.Scanner.HTTPTimeout.String(), c.Scanner.TLSHandshakeTimeout.String(), c.Scanner.MaxRedirects, c.Scanner.MaxConcurrentScans, c.Scanner.UserAgent},
		AI: struct {
			Enabled bool `json:"enabled"`
			Ollama  struct {
				BaseURL string `json:"base_url"`
				Model   string `json:"model"`
			} `json:"ollama"`
			Timeout   string `json:"timeout"`
			MaxTokens int    `json:"max_tokens"`
		}{
			Enabled: c.AI.Enabled,
			Ollama: struct {
				BaseURL string `json:"base_url"`
				Model   string `json:"model"`
			}{c.AI.Ollama.BaseURL, c.AI.Ollama.Model},
			Timeout: c.AI.Timeout.String(), MaxTokens: c.AI.MaxTokens,
		},
		Storage: struct {
			DatabasePath string `json:"database_path"`
			CacheTTL     string `json:"cache_ttl"`
		}{c.Storage.DatabasePath, c.Storage.CacheTTL.String()},
		ThreatIntel: struct {
			FeedUpdateInterval string   `json:"feed_update_interval"`
			FeedURLs           []string `json:"feed_urls"`
		}{c.ThreatIntel.FeedUpdateInterval.String(), c.ThreatIntel.FeedURLs},
		Logging: c.Logging,
	})
}

func (c *Config) UnmarshalJSON(data []byte) error {
	d := Default()
	w := jsonConfig{Application: d.Application, HTTPServer: struct {
		Host              string `json:"host"`
		Port              int    `json:"port"`
		ReadHeaderTimeout string `json:"read_header_timeout"`
		ReadTimeout       string `json:"read_timeout"`
		WriteTimeout      string `json:"write_timeout"`
		IdleTimeout       string `json:"idle_timeout"`
		MaxScanDuration   string `json:"max_scan_duration"`
	}{
		Host: d.HTTPServer.Host, Port: d.HTTPServer.Port,
		ReadHeaderTimeout: d.HTTPServer.ReadHeaderTimeout.String(),
		ReadTimeout:       d.HTTPServer.ReadTimeout.String(),
		WriteTimeout:      d.HTTPServer.WriteTimeout.String(),
		IdleTimeout:       d.HTTPServer.IdleTimeout.String(),
		MaxScanDuration:   d.HTTPServer.MaxScanDuration.String(),
	}, Logging: d.Logging}
	w.Scanner.HTTPTimeout = d.Scanner.HTTPTimeout.String()
	w.Scanner.TLSHandshakeTimeout = d.Scanner.TLSHandshakeTimeout.String()
	w.Scanner.MaxRedirects = d.Scanner.MaxRedirects
	w.Scanner.MaxConcurrentScans = d.Scanner.MaxConcurrentScans
	w.Scanner.UserAgent = d.Scanner.UserAgent
	w.AI.Enabled = d.AI.Enabled
	w.AI.Ollama.BaseURL = d.AI.Ollama.BaseURL
	w.AI.Ollama.Model = d.AI.Ollama.Model
	w.AI.Timeout = d.AI.Timeout.String()
	w.AI.MaxTokens = d.AI.MaxTokens
	w.Storage.DatabasePath = d.Storage.DatabasePath
	w.Storage.CacheTTL = d.Storage.CacheTTL.String()
	w.ThreatIntel.FeedUpdateInterval = d.ThreatIntel.FeedUpdateInterval.String()
	w.ThreatIntel.FeedURLs = d.ThreatIntel.FeedURLs

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&w); err != nil {
		return err
	}
	parsed, err := w.toConfig()
	if err != nil {
		return err
	}
	*c = *parsed
	return nil
}

func (w jsonConfig) toConfig() (*Config, error) {
	parse := func(field, value string) (time.Duration, error) {
		d, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", field, value, err)
		}
		return d, nil
	}
	httpTimeout, err := parse("scanner.http_timeout", w.Scanner.HTTPTimeout)
	if err != nil {
		return nil, err
	}
	tlsTimeout, err := parse("scanner.tls_handshake_timeout", w.Scanner.TLSHandshakeTimeout)
	if err != nil {
		return nil, err
	}
	cacheTTL, err := parse("storage.cache_ttl", w.Storage.CacheTTL)
	if err != nil {
		return nil, err
	}
	feedInterval, err := parse("threat_intelligence.feed_update_interval", w.ThreatIntel.FeedUpdateInterval)
	if err != nil {
		return nil, err
	}
	aiTimeout, err := parse("ai.timeout", w.AI.Timeout)
	if err != nil {
		return nil, err
	}
	readHeaderTimeout, err := parse("http_server.read_header_timeout", w.HTTPServer.ReadHeaderTimeout)
	if err != nil {
		return nil, err
	}
	readTimeout, err := parse("http_server.read_timeout", w.HTTPServer.ReadTimeout)
	if err != nil {
		return nil, err
	}
	writeTimeout, err := parse("http_server.write_timeout", w.HTTPServer.WriteTimeout)
	if err != nil {
		return nil, err
	}
	idleTimeout, err := parse("http_server.idle_timeout", w.HTTPServer.IdleTimeout)
	if err != nil {
		return nil, err
	}
	maxScanDuration, err := parse("http_server.max_scan_duration", w.HTTPServer.MaxScanDuration)
	if err != nil {
		return nil, err
	}
	return &Config{
		Application: w.Application,
		HTTPServer: HTTPServerConfig{
			Host: w.HTTPServer.Host, Port: w.HTTPServer.Port,
			ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout,
			WriteTimeout: writeTimeout, IdleTimeout: idleTimeout,
			MaxScanDuration: maxScanDuration,
		},
		Scanner: ScannerConfig{HTTPTimeout: httpTimeout, TLSHandshakeTimeout: tlsTimeout,
			MaxRedirects: w.Scanner.MaxRedirects, MaxConcurrentScans: w.Scanner.MaxConcurrentScans,
			UserAgent: w.Scanner.UserAgent},
		AI: AIConfig{
			Enabled: w.AI.Enabled,
			Ollama:  OllamaConfig{BaseURL: w.AI.Ollama.BaseURL, Model: w.AI.Ollama.Model},
			Timeout: aiTimeout, MaxTokens: w.AI.MaxTokens,
		},
		Storage:     StorageConfig{DatabasePath: w.Storage.DatabasePath, CacheTTL: cacheTTL},
		ThreatIntel: ThreatIntelConfig{FeedUpdateInterval: feedInterval, FeedURLs: w.ThreatIntel.FeedURLs},
		Logging:     w.Logging,
	}, nil
}

// Load reads and validates a JSON configuration file.
func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()
	config, err := LoadFromReader(file)
	if err != nil {
		return nil, fmt.Errorf("load configuration %q: %w", path, err)
	}
	return config, nil
}

// MaxConfigFileBytes is the maximum allowed size for a configuration file (1 MiB).
const MaxConfigFileBytes = 1 << 20

// LoadFromReader reads, parses, and validates a JSON configuration.
func LoadFromReader(reader io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	if len(data) > MaxConfigFileBytes {
		return nil, fmt.Errorf("configuration file exceeds maximum allowed size of %d bytes", MaxConfigFileBytes)
	}
	config := Default()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	return config, nil
}

// Validate checks values that affect safe application operation.
func (c *Config) Validate() error {
	if err := c.HTTPServer.Validate(); err != nil {
		return err
	}
	if c.Scanner.HTTPTimeout <= 0 {
		return fmt.Errorf("scanner.http_timeout must be positive")
	}
	if c.HTTPServer.MaxScanDuration <= 0 {
		return fmt.Errorf("http_server.max_scan_duration must be positive")
	}
	if c.Scanner.TLSHandshakeTimeout <= 0 {
		return fmt.Errorf("scanner.tls_handshake_timeout must be positive")
	}
	if c.Scanner.MaxRedirects < 0 || c.Scanner.MaxRedirects > MaxRedirectsLimit {
		return fmt.Errorf("scanner.max_redirects must be between 0 and %d", MaxRedirectsLimit)
	}
	if c.Scanner.MaxConcurrentScans <= 0 {
		return fmt.Errorf("scanner.max_concurrent_scans must be positive")
	}
	if c.AI.Timeout <= 0 {
		return fmt.Errorf("ai.timeout must be positive")
	}
	if c.AI.MaxTokens < 1 || c.AI.MaxTokens > 8192 {
		return fmt.Errorf("ai.max_tokens must be between 1 and 8192")
	}
	if c.AI.Enabled {
		if strings.TrimSpace(c.AI.Ollama.BaseURL) == "" {
			return fmt.Errorf("ai.ollama.base_url cannot be empty when AI is enabled")
		}
		if strings.TrimSpace(c.AI.Ollama.Model) == "" {
			return fmt.Errorf("ai.ollama.model cannot be empty when AI is enabled")
		}
	}
	if strings.TrimSpace(c.Scanner.UserAgent) == "" {
		return fmt.Errorf("scanner.user_agent cannot be empty")
	}
	if strings.TrimSpace(c.Storage.DatabasePath) == "" {
		return fmt.Errorf("storage.database_path cannot be empty")
	}
	if c.Storage.CacheTTL <= 0 {
		return fmt.Errorf("storage.cache_ttl must be positive")
	}
	if c.ThreatIntel.FeedUpdateInterval <= 0 {
		return fmt.Errorf("threat_intelligence.feed_update_interval must be positive")
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level must be one of debug, info, warn, error")
	}
	return nil
}

// Validate checks HTTP server settings, including restricting binds to loopback IPs.
func (c HTTPServerConfig) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("http_server.host cannot be empty")
	}
	ip := net.ParseIP(c.Host)
	if ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("http_server.host cannot be an unspecified address")
	}
	if strings.EqualFold(c.Host, "0.0.0.0") || strings.EqualFold(c.Host, "::") {
		return fmt.Errorf("http_server.host cannot be an unspecified address")
	}
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("http_server.host must be a loopback IP address")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("http_server.port must be between 1 and 65535")
	}
	if c.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("http_server.read_header_timeout must be positive")
	}
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("http_server.read_timeout must be positive")
	}
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("http_server.write_timeout must be positive")
	}
	if c.IdleTimeout <= 0 {
		return fmt.Errorf("http_server.idle_timeout must be positive")
	}
	if c.MaxScanDuration <= 0 {
		return fmt.Errorf("http_server.max_scan_duration must be positive")
	}
	if c.MaxScanDuration >= c.WriteTimeout {
		return fmt.Errorf("http_server.max_scan_duration must be less than write_timeout")
	}
	return nil
}
