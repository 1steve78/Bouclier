package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bouclier/internal/risk"
)

func TestOllamaProviderGenerate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var request ollamaChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Model != "llama-test" || request.Stream || request.Options.NumPredict != 128 ||
			len(request.Messages) != 2 || request.Messages[0].Role != "system" ||
			request.Messages[1].Content != "assessment" {
			t.Fatalf("unexpected Ollama request: %+v", request)
		}
		_, _ = w.Write([]byte(`{"model":"llama-test:latest","message":{"content":"Local explanation."}}`))
	}))
	defer server.Close()

	provider, err := NewOllamaProvider(OllamaConfig{BaseURL: server.URL, Model: "llama-test"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Generate(context.Background(), GenerateRequest{
		System: "system", User: "assessment", MaxTokens: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "Local explanation." || result.Model != "llama-test:latest" {
		t.Fatalf("unexpected generation result: %+v", result)
	}
}

func TestNewOllamaProviderRequiresLoopback(t *testing.T) {
	for _, baseURL := range []string{
		"https://example.com",
		"http://127.0.0.1:11434/?key=secret",
		"file:///tmp/ollama",
	} {
		if _, err := NewOllamaProvider(OllamaConfig{BaseURL: baseURL, Model: "llama"}); err == nil {
			t.Errorf("NewOllamaProvider accepted unsafe URL %q", baseURL)
		}
	}
}

func TestParseOllamaList(t *testing.T) {
	models, err := parseOllamaList([]byte("NAME               ID              SIZE      MODIFIED\nllama3.2:latest    abc123          2.0 GB    2 days ago\nqwen2.5:7b         def456          4.7 GB    1 hour ago\nllama3.2:latest    abc123          2.0 GB    2 days ago\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || models[0] != "llama3.2:latest" || models[1] != "qwen2.5:7b" {
		t.Fatalf("unexpected model list: %v", models)
	}
}

func TestParseOllamaListRejectsInvalidOutput(t *testing.T) {
	for _, output := range []string{"", "no models"} {
		if _, err := parseOllamaList([]byte(output)); err == nil {
			t.Errorf("parseOllamaList(%q) unexpectedly succeeded", output)
		}
	}
}

func TestParseOllamaListAllowsNoInstalledModels(t *testing.T) {
	models, err := parseOllamaList([]byte("NAME ID SIZE\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 0 {
		t.Fatalf("expected no models, got %v", models)
	}
}

func TestExplainAssessmentSendsSanitizedCompactInput(t *testing.T) {
	fake := &fakeProvider{}
	assessment := &risk.RiskAssessment{
		Target:       "https://example.com/sign-in?token=top-secret",
		OverallScore: 42, Classification: risk.RiskElevated,
		ScoringMethod: "deterministic policy",
		Findings: []risk.NormalizedFinding{{
			Code: "TEST", Title: "Observed issue", Description: "Issue description",
			Evidence: "token=top-secret", Remediation: "Review configuration",
			ScoreImpact: 12, Severity: risk.SeverityMedium, Confidence: risk.ConfidenceHigh,
		}},
		AnalysisCoverage: []risk.ComponentCoverage{{Component: "TLS", State: risk.ComponentCompleted}},
		Limitations:      []string{"Partial coverage"},
	}
	result, err := ExplainAssessment(context.Background(), fake, assessment, 200)
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "Safe explanation." || result.Model != "test-model" {
		t.Fatalf("unexpected explanation result: %+v", result)
	}
	if strings.Contains(fake.request.User, "top-secret") {
		t.Fatalf("sensitive query data reached the AI prompt: %s", fake.request.User)
	}
	if !strings.Contains(fake.request.System, "untrusted input") || fake.request.MaxTokens != 200 {
		t.Fatalf("system instruction or token limit missing: %+v", fake.request)
	}
}

func TestExplainAssessmentRejectsEmptyResponse(t *testing.T) {
	fake := &fakeProvider{result: GenerateResult{Text: " \x1b[31m \x1b[0m"}}
	_, err := ExplainAssessment(context.Background(), fake, &risk.RiskAssessment{}, 100)
	if err == nil || !strings.Contains(err.Error(), "empty explanation") {
		t.Fatalf("ExplainAssessment() error = %v, want empty-response error", err)
	}
}

type fakeProvider struct {
	request GenerateRequest
	result  GenerateResult
}

func (p *fakeProvider) ID() string                   { return "test-provider" }
func (p *fakeProvider) Health(context.Context) error { return nil }
func (p *fakeProvider) Generate(_ context.Context, req GenerateRequest) (GenerateResult, error) {
	p.request = req
	if p.result.Text == "" {
		return GenerateResult{Text: "Safe explanation.", Model: "test-model"}, nil
	}
	return p.result, nil
}
