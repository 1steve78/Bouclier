package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

const maxOllamaResponseBytes = 1 << 20

type OllamaProvider struct {
	baseURL string
	model   string
	client  *http.Client
}

func NewOllamaProvider(cfg OllamaConfig) (*OllamaProvider, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("configure Ollama: base URL is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("configure Ollama: base URL must use HTTP or HTTPS")
	}
	if !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("configure Ollama: base URL must point to a loopback host")
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, errors.New("configure Ollama: model is required")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 90 * time.Second
	}
	if timeout < 0 {
		return nil, errors.New("configure Ollama: timeout must be positive")
	}
	return &OllamaProvider{
		baseURL: baseURL,
		model:   model,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:       nil,
				DialContext: dialLoopback,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("Ollama redirects are not permitted")
			},
		},
	}, nil
}

func (p *OllamaProvider) ID() string {
	return "ollama:" + p.model
}

func (p *OllamaProvider) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("check Ollama health: create request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("check Ollama health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("check Ollama health: server returned %s", resp.Status)
	}
	return nil
}

func (p *OllamaProvider) Generate(ctx context.Context, req GenerateRequest) (GenerateResult, error) {
	if strings.TrimSpace(req.User) == "" {
		return GenerateResult{}, errors.New("generate with Ollama: user prompt is required")
	}
	messages := make([]ollamaMessage, 0, 2)
	if req.System != "" {
		messages = append(messages, ollamaMessage{Role: "system", Content: req.System})
	}
	messages = append(messages, ollamaMessage{Role: "user", Content: req.User})
	body := ollamaChatRequest{
		Model:    p.model,
		Messages: messages,
		Stream:   false,
		Options:  ollamaOptions{NumPredict: req.MaxTokens},
	}
	if req.JSON {
		body.Format = "json"
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("generate with Ollama: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/api/chat", bytes.NewReader(encoded))
	if err != nil {
		return GenerateResult{}, fmt.Errorf("generate with Ollama: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("generate with Ollama: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return GenerateResult{}, fmt.Errorf("generate with Ollama: server returned %s (read error: %w)", resp.Status, readErr)
		}
		message := truncateText(cleanGeneratedText(string(detail)), 300)
		if message == "" {
			return GenerateResult{}, fmt.Errorf("generate with Ollama: server returned %s", resp.Status)
		}
		return GenerateResult{}, fmt.Errorf("generate with Ollama: server returned %s: %s", resp.Status, message)
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxOllamaResponseBytes+1))
	if err != nil {
		return GenerateResult{}, fmt.Errorf("generate with Ollama: read response: %w", err)
	}
	if len(responseBody) > maxOllamaResponseBytes {
		return GenerateResult{}, errors.New("generate with Ollama: response exceeds size limit")
	}
	var result ollamaChatResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return GenerateResult{}, fmt.Errorf("generate with Ollama: decode response: %w", err)
	}
	if strings.TrimSpace(result.Message.Content) == "" {
		return GenerateResult{}, errors.New("generate with Ollama: model returned an empty response")
	}
	model := result.Model
	if model == "" {
		model = p.model
	}
	return GenerateResult{Text: strings.TrimSpace(result.Message.Content), Model: model}, nil
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	NumPredict int `json:"num_predict,omitempty"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   string          `json:"format,omitempty"`
	Options  ollamaOptions   `json:"options,omitempty"`
}

type ollamaChatResponse struct {
	Model   string `json:"model"`
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && address.IsLoopback()
}

func ListOllamaModels(ctx context.Context) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("list Ollama models: context is required")
	}
	output, err := exec.CommandContext(ctx, "ollama", "list").Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("list Ollama models: %w", ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			detail := strings.TrimSpace(string(exitErr.Stderr))
			if detail != "" {
				return nil, fmt.Errorf("run 'ollama list': %s", truncateText(cleanGeneratedText(detail), 300))
			}
		}
		return nil, fmt.Errorf("run 'ollama list' (ensure Ollama is installed and on PATH): %w", err)
	}
	return parseOllamaList(output)
}

func parseOllamaList(output []byte) ([]string, error) {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return nil, errors.New("parse 'ollama list': expected NAME column header")
	}
	lines := strings.Split(trimmed, "\n")
	header := strings.Fields(lines[0])
	if len(header) == 0 || !strings.EqualFold(header[0], "NAME") {
		return nil, errors.New("parse 'ollama list': expected NAME column header")
	}
	models := make([]string, 0, len(lines)-1)
	seen := make(map[string]struct{}, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		models = append(models, name)
	}
	return models, nil
}

func dialLoopback(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("connect to Ollama: invalid endpoint")
	}
	var addresses []netip.Addr
	if ip, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
		addresses = []netip.Addr{ip}
	} else if strings.EqualFold(host, "localhost") {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("connect to Ollama: resolve loopback host: %w", err)
		}
	} else {
		return nil, errors.New("connect to Ollama: target must be a loopback host")
	}
	if len(addresses) == 0 {
		return nil, errors.New("connect to Ollama: loopback host resolved to no addresses")
	}
	dialer := &net.Dialer{}
	var lastErr error
	for _, ip := range addresses {
		if !ip.IsLoopback() {
			return nil, errors.New("connect to Ollama: host resolved to a non-loopback address")
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("connect to Ollama: %w", lastErr)
}
