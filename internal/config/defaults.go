package config

import (
	"os"
	"path/filepath"
	"time"
)

// Default returns a configuration populated with the application defaults.
func Default() *Config {
	home, err := os.UserHomeDir()
	databasePath := "bouclier.db"
	if err == nil && home != "" {
		databasePath = filepath.Join(home, ".bouclier", "bouclier.db")
	}

	return &Config{
		Application: ApplicationConfig{Name: "Bouclier", Version: "0.1.0-dev", Environment: "development"},
		HTTPServer: HTTPServerConfig{
			Host: "127.0.0.1", Port: 8081,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			MaxScanDuration: 20 * time.Second,
		},
		Scanner: ScannerConfig{
			HTTPTimeout: 8 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
			MaxRedirects: 5, MaxConcurrentScans: 10, UserAgent: "Bouclier/0.1.0-dev",
		},
		AI: AIConfig{
			Enabled: false,
			Ollama:  OllamaConfig{BaseURL: "http://127.0.0.1:11434", Model: "llama3.2"},
			Timeout: 90 * time.Second, MaxTokens: 512,
		},
		Storage:     StorageConfig{DatabasePath: databasePath, CacheTTL: 24 * time.Hour},
		ThreatIntel: ThreatIntelConfig{FeedUpdateInterval: 24 * time.Hour, FeedURLs: []string{}},
		Logging:     LoggingConfig{Level: "info", Structured: false},
	}
}
