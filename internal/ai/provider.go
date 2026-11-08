package ai

import (
	"context"
	"time"
)

// Provider defines the minimal AI contract used by the application.
type Provider interface {
	ID() string
	Health(ctx context.Context) error
	Generate(ctx context.Context, req GenerateRequest) (GenerateResult, error)
}

// GenerateRequest contains the prompt and generation options.
type GenerateRequest struct {
	System    string `json:"system"`
	User      string `json:"user"`
	MaxTokens int    `json:"max_tokens"`
	JSON      bool   `json:"json"`
}

// GenerateResult is the text returned by an AI model.
type GenerateResult struct {
	Text  string `json:"text"`
	Model string `json:"model"`
}

// OllamaConfig configures a local Ollama-backed provider.
type OllamaConfig struct {
	BaseURL string        `json:"base_url"`
	Model   string        `json:"model"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// APIKeyConfig configures a provider that reads credentials from environment variables.
type APIKeyConfig struct {
	KeyEnvVar string `json:"key_env_var"`
	Model     string `json:"model"`
}
