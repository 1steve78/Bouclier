package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Config contains the settings used by the Bouclier application.
type Config struct {
	Application ApplicationConfig `json:"application"`
	Scanner     ScannerConfig     `json:"scanner"`
	Storage     StorageConfig     `json:"storage"`
	ThreatIntel ThreatIntelConfig `json:"threat_intelligence"`
	Logging     LoggingConfig     `json:"logging"`
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
	Scanner     struct {
		HTTPTimeout         string `json:"http_timeout"`
		TLSHandshakeTimeout string `json:"tls_handshake_timeout"`
		MaxRedirects        int    `json:"max_redirects"`
		MaxConcurrentScans  int    `json:"max_concurrent_scans"`
		UserAgent           string `json:"user_agent"`
	} `json:"scanner"`
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
		Scanner     struct {
			HTTPTimeout         string `json:"http_timeout"`
			TLSHandshakeTimeout string `json:"tls_handshake_timeout"`
			MaxRedirects        int    `json:"max_redirects"`
			MaxConcurrentScans  int    `json:"max_concurrent_scans"`
			UserAgent           string `json:"user_agent"`
		} `json:"scanner"`
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
		Scanner: struct {
			HTTPTimeout         string `json:"http_timeout"`
			TLSHandshakeTimeout string `json:"tls_handshake_timeout"`
			MaxRedirects        int    `json:"max_redirects"`
			MaxConcurrentScans  int    `json:"max_concurrent_scans"`
			UserAgent           string `json:"user_agent"`
		}{c.Scanner.HTTPTimeout.String(), c.Scanner.TLSHandshakeTimeout.String(), c.Scanner.MaxRedirects, c.Scanner.MaxConcurrentScans, c.Scanner.UserAgent},
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
	w := jsonConfig{Application: d.Application, Logging: d.Logging}
	w.Scanner.HTTPTimeout = d.Scanner.HTTPTimeout.String()
	w.Scanner.TLSHandshakeTimeout = d.Scanner.TLSHandshakeTimeout.String()
	w.Scanner.MaxRedirects = d.Scanner.MaxRedirects
	w.Scanner.MaxConcurrentScans = d.Scanner.MaxConcurrentScans
	w.Scanner.UserAgent = d.Scanner.UserAgent
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
	return &Config{
		Application: w.Application,
		Scanner: ScannerConfig{HTTPTimeout: httpTimeout, TLSHandshakeTimeout: tlsTimeout,
			MaxRedirects: w.Scanner.MaxRedirects, MaxConcurrentScans: w.Scanner.MaxConcurrentScans,
			UserAgent: w.Scanner.UserAgent},
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

// LoadFromReader reads, parses, and validates a JSON configuration.
func LoadFromReader(reader io.Reader) (*Config, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
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
	if c.Scanner.HTTPTimeout <= 0 {
		return fmt.Errorf("scanner.http_timeout must be positive")
	}
	if c.Scanner.TLSHandshakeTimeout <= 0 {
		return fmt.Errorf("scanner.tls_handshake_timeout must be positive")
	}
	if c.Scanner.MaxRedirects < 0 {
		return fmt.Errorf("scanner.max_redirects cannot be negative")
	}
	if c.Scanner.MaxConcurrentScans <= 0 {
		return fmt.Errorf("scanner.max_concurrent_scans must be positive")
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
