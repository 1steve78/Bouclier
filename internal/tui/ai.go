package tui

import (
	"context"
	"fmt"
	"time"

	"bouclier/internal/ai"
	"bouclier/internal/config"
	"bouclier/internal/risk"
	tea "github.com/charmbracelet/bubbletea"
)

type assessmentExplainer func(context.Context, *config.Config, *risk.RiskAssessment) (ai.GenerateResult, error)

var explainAssessmentRunner assessmentExplainer = runAssessmentExplanation
var ollamaModelLister = ai.ListOllamaModels

func SetAssessmentExplainerForTesting(fn func(context.Context, *config.Config, *risk.RiskAssessment) (ai.GenerateResult, error)) func() {
	previous := explainAssessmentRunner
	explainAssessmentRunner = fn
	return func() {
		explainAssessmentRunner = previous
	}
}

func SetOllamaModelListerForTesting(fn func(context.Context) ([]string, error)) func() {
	previous := ollamaModelLister
	ollamaModelLister = fn
	return func() {
		ollamaModelLister = previous
	}
}

func runAssessmentExplanation(ctx context.Context, cfg *config.Config, assessment *risk.RiskAssessment) (ai.GenerateResult, error) {
	provider, err := ai.NewOllamaProvider(ai.OllamaConfig{
		BaseURL: cfg.AI.Ollama.BaseURL,
		Model:   cfg.AI.Ollama.Model,
		Timeout: cfg.AI.Timeout,
	})
	if err != nil {
		return ai.GenerateResult{}, err
	}
	return ai.ExplainAssessment(ctx, provider, assessment, cfg.AI.MaxTokens)
}

func StartExplainAssessmentCmd(requestID uint64, cfg *config.Config, assessment *risk.RiskAssessment) (tea.Cmd, context.CancelFunc) {
	timeout := cfg.AI.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return func() tea.Msg {
		result, err := explainAssessmentRunner(ctx, cfg, assessment)
		if err != nil {
			return AIExplanationCompletedMsg{RequestID: requestID, Err: fmt.Errorf("explain assessment: %w", err)}
		}
		return AIExplanationCompletedMsg{
			RequestID: requestID, Text: result.Text, Model: result.Model,
		}
	}, cancel
}

func ListOllamaModelsCmd(requestID uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		models, err := ollamaModelLister(ctx)
		return AIModelsLoadedMsg{RequestID: requestID, Models: models, Err: err}
	}
}
