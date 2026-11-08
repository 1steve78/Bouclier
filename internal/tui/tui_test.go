package tui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"bouclier/internal/ai"
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
	tea "github.com/charmbracelet/bubbletea"
)

func sampleTestAssessment() *risk.RiskAssessment {
	findings, _ := risk.NormalizeFindings([]risk.Observation{
		{
			Code:        "URL_IP_LITERAL",
			Title:       "IP address used as destination",
			Description: "This URL names an IP literal instead of a DNS hostname.",
			Category:    "destination",
			Evidence:    "destination is an IP literal",
			Source:      risk.SourceURL,
		},
		{
			Code:        "WEB_CSP_UNSAFE_EVAL",
			Title:       "CSP permits eval-like execution",
			Description: "unsafe-eval weakens restrictions for script execution.",
			Category:    "web-content-policy",
			Evidence:    "unsafe-eval found in script-src",
			Source:      risk.SourceWeb,
		},
		{
			Code:        "WEB_HSTS_MISSING",
			Title:       "Missing Strict-Transport-Security",
			Description: "HSTS header is absent from HTTP response.",
			Category:    "http-security-headers",
			Evidence:    "Strict-Transport-Security absent",
			Source:      risk.SourceWeb,
		},
	}, "https://example.com")

	return &risk.RiskAssessment{
		SchemaVersion:  "bouclier-risk/v1",
		Target:         "https://example.com",
		AnalyzedAt:     time.Now().UTC(),
		OverallScore:   21,
		Classification: risk.RiskElevated,
		PolicyID:       "bouclier-default",
		PolicyVersion:  "1.0",
		Findings:       findings,
		SeverityCounts: []risk.SeverityCount{
			{Severity: risk.SeverityMedium, Count: 1},
			{Severity: risk.SeverityLow, Count: 2},
		},
		TopRiskFactors: []risk.RiskFactor{
			{Finding: findings[1], Contribution: 15},
			{Finding: findings[0], Contribution: 6},
		},
		AnalysisCoverage: []risk.ComponentCoverage{
			{Component: "url_analysis", State: risk.ComponentCompleted},
			{Component: "domain_structure", State: risk.ComponentCompleted},
			{Component: "tls_connection", State: risk.ComponentCompleted},
			{Component: "web_http_inspection", State: risk.ComponentCompleted},
			{Component: "ct_lookup", State: risk.ComponentSkipped, Detail: "no CT logs found"},
		},
		Limitations: []string{
			"ct_lookup coverage is skipped; absence of findings is not a clean result",
		},
	}
}

func TestModelInitialState(t *testing.T) {
	m := NewModel(config.Default(), false)
	if m.CurrentScreen != ScreenDashboard {
		t.Fatalf("expected initial screen Dashboard, got %v", m.CurrentScreen)
	}
	if m.ActiveFilter != FilterAll {
		t.Fatalf("expected active filter All, got %v", m.ActiveFilter)
	}
	if len(m.StageOrder) != 7 {
		t.Fatalf("expected 7 scan stages, got %d", len(m.StageOrder))
	}
	for _, s := range m.StageOrder {
		if m.Stages[s] != cli.StageStatePending {
			t.Errorf("expected stage %s to be pending, got %v", s, m.Stages[s])
		}
	}
}

func TestWindowSizeResize(t *testing.T) {
	m := NewModel(config.Default(), false)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model := updated.(Model)
	if model.Width != 120 || model.Height != 40 {
		t.Fatalf("window size not updated: got %dx%d, want 120x40", model.Width, model.Height)
	}
}

func TestNavigationToURLInput(t *testing.T) {
	m := NewModel(config.Default(), false)
	// Press Enter on Dashboard -> goes to URL input
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(Model)
	if model.CurrentScreen != ScreenURLInput {
		t.Fatalf("expected ScreenURLInput after enter, got %v", model.CurrentScreen)
	}

	// Press Esc -> returns to Dashboard
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)
	if model.CurrentScreen != ScreenDashboard {
		t.Fatalf("expected ScreenDashboard after esc, got %v", model.CurrentScreen)
	}
}

func TestURLValidation(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenURLInput

	// Empty input -> validation error
	m.URLInput.SetValue("")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model := updated.(Model)
	if model.CurrentScreen != ScreenURLInput {
		t.Fatalf("expected to remain on URL input on empty value, got %v", model.CurrentScreen)
	}
	if model.URLValidationErr == "" {
		t.Fatal("expected URLValidationErr for empty input")
	}

	// Valid target -> transitions to ScreenScanning and starts scan
	model.URLInput.SetValue("example.com")
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.CurrentScreen != ScreenScanning {
		t.Fatalf("expected ScreenScanning for valid input, got %v", model.CurrentScreen)
	}
	if cmd == nil {
		t.Fatal("expected non-nil tea.Cmd to initiate background scan")
	}
	if model.ScanTarget != "https://example.com" && model.ScanTarget != "https://example.com/" {
		t.Fatalf("expected normalized target https://example.com/, got %q", model.ScanTarget)
	}
	if model.ScanCancel == nil {
		t.Fatal("expected ScanCancel func to be set")
	}
}

func TestScanningProgressAndCompletion(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenScanning
	m.ScanID = 1
	m.ScanTarget = "https://example.com"

	// 1. Stage progress message
	progMsg := ScanProgressMsg{
		ScanID:  1,
		Stage:   cli.StageURLAnalysis,
		State:   cli.StageStateRunning,
		Message: "Analyzing URL structure...",
	}
	updated, _ := m.Update(progMsg)
	m = updated.(Model)
	if m.Stages[cli.StageURLAnalysis] != cli.StageStateRunning {
		t.Fatalf("expected StageURLAnalysis running, got %v", m.Stages[cli.StageURLAnalysis])
	}
	if m.StageMessages[cli.StageURLAnalysis] != "Analyzing URL structure..." {
		t.Fatalf("unexpected stage message: %s", m.StageMessages[cli.StageURLAnalysis])
	}

	// 2. Ignore stale progress message from old ScanID
	staleMsg := ScanProgressMsg{
		ScanID: 0,
		Stage:  cli.StageDomainIntelligence,
		State:  cli.StageStateRunning,
	}
	updated, _ = m.Update(staleMsg)
	m = updated.(Model)
	if m.Stages[cli.StageDomainIntelligence] != cli.StageStatePending {
		t.Fatalf("expected StageDomainIntelligence to remain pending, got %v", m.Stages[cli.StageDomainIntelligence])
	}

	// 3. Scan completed message
	assessment := sampleTestAssessment()
	compMsg := ScanCompletedMsg{
		ScanID:     1,
		Assessment: assessment,
	}
	updated, _ = m.Update(compMsg)
	m = updated.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected transition to ScreenOverview, got %v", m.CurrentScreen)
	}
	if m.Assessment == nil || m.Assessment.OverallScore != 21 {
		t.Fatalf("assessment not stored in model properly: %+v", m.Assessment)
	}
	if len(m.FilteredFindings) != len(assessment.Findings) {
		t.Fatalf("expected %d filtered findings, got %d", len(assessment.Findings), len(m.FilteredFindings))
	}
}

func TestAIExplanationOverviewAction(t *testing.T) {
	restoreModels := SetOllamaModelListerForTesting(func(context.Context) ([]string, error) {
		return []string{"llama3.2:latest", "qwen2.5:7b"}, nil
	})
	defer restoreModels()
	restore := SetAssessmentExplainerForTesting(func(_ context.Context, cfg *config.Config, assessment *risk.RiskAssessment) (ai.GenerateResult, error) {
		if assessment.OverallScore != 21 {
			t.Fatalf("explanation received changed assessment score: %d", assessment.OverallScore)
		}
		if cfg.AI.Ollama.Model != "qwen2.5:7b" {
			t.Fatalf("selected Ollama model not used: %q", cfg.AI.Ollama.Model)
		}
		return ai.GenerateResult{Text: "This explains the existing findings.", Model: "local-test"}, nil
	})
	defer restore()

	cfg := config.Default()
	cfg.AI.Enabled = true
	m := NewModel(cfg, true)
	m.CurrentScreen = ScreenOverview
	m.Assessment = sampleTestAssessment()

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = updated.(Model)
	if m.CurrentScreen != ScreenAIModelSelect || !m.AIModelLoading || cmd == nil {
		t.Fatal("pressing a did not start the installed-model picker")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if len(m.AIModels) != 2 || m.AIModelSelectedIdx != 0 {
		t.Fatalf("ollama list results were not loaded: %+v", m.AIModels)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.CurrentScreen != ScreenOverview || !m.AIExplaining || cmd == nil {
		t.Fatal("selecting a model did not start its explanation")
	}
	if m.Config.AI.Ollama.Model != "qwen2.5:7b" {
		t.Fatalf("selected model was not applied: %q", m.Config.AI.Ollama.Model)
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if m.AIExplaining || m.AIExplanationText != "This explains the existing findings." || m.AIExplanationModel != "local-test" {
		t.Fatalf("explanation result was not stored: %+v", m)
	}
	if m.Assessment.OverallScore != 21 {
		t.Fatalf("AI explanation changed the deterministic score: %d", m.Assessment.OverallScore)
	}
	view := m.View()
	if !strings.Contains(view, "AI-generated explanation") || !strings.Contains(view, "This explains the existing findings.") {
		t.Fatalf("overview omitted AI explanation:\n%s", view)
	}
}

func TestAIModelPickerHandlesListFailureAndRetry(t *testing.T) {
	var calls int
	restore := SetOllamaModelListerForTesting(func(context.Context) ([]string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("ollama is not available")
		}
		return []string{"llama3.2"}, nil
	})
	defer restore()

	cfg := config.Default()
	cfg.AI.Enabled = true
	m := NewModel(cfg, true)
	m.CurrentScreen = ScreenOverview
	m.Assessment = sampleTestAssessment()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = updated.(Model)
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if m.AIModelListErr == nil || !strings.Contains(m.View(), "ollama is not available") {
		t.Fatal("model listing failure was not displayed")
	}
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	if !m.AIModelLoading || cmd == nil {
		t.Fatal("R did not retry ollama list")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if m.AIModelListErr != nil || len(m.AIModels) != 1 {
		t.Fatalf("retry did not populate model list: models=%v err=%v", m.AIModels, m.AIModelListErr)
	}
}

func TestAIModelPickerHandlesEmptyList(t *testing.T) {
	restore := SetOllamaModelListerForTesting(func(context.Context) ([]string, error) {
		return []string{}, nil
	})
	defer restore()

	cfg := config.Default()
	cfg.AI.Enabled = true
	m := NewModel(cfg, true)
	m.CurrentScreen = ScreenOverview
	m.Assessment = sampleTestAssessment()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = updated.(Model)
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if !strings.Contains(m.View(), "ollama pull <model>") {
		t.Fatal("empty model list did not show how to install an Ollama model")
	}
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.CurrentScreen != ScreenAIModelSelect || cmd != nil || m.AIExplaining {
		t.Fatal("empty model list should not start an explanation")
	}
}

func TestAIExplanationIgnoresStaleResults(t *testing.T) {
	m := NewModel(config.Default(), true)
	m.AIExplainRequestID = 5
	m.AIExplanationText = "current"
	updated, _ := m.Update(AIExplanationCompletedMsg{RequestID: 4, Text: "stale"})
	m = updated.(Model)
	if m.AIExplanationText != "current" {
		t.Fatalf("stale explanation overwrote current result: %q", m.AIExplanationText)
	}
}

func TestScanCancellation(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenScanning
	m.ScanID = 42
	cancelled := false
	m.ScanCancel = func() {
		cancelled = true
	}

	// Press 'c' to cancel
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = updated.(Model)
	if !cancelled {
		t.Fatal("expected ScanCancel() to have been called")
	}
	if m.ScanErr == nil {
		t.Fatal("expected ScanErr to be set on cancellation")
	}
	if !strings.Contains(m.ScanErr.Error(), "cancelled") {
		t.Fatalf("expected cancellation error message, got %v", m.ScanErr)
	}
}

func TestScanFailureAndRetry(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenScanning
	m.ScanID = 10
	m.ScanTarget = "https://example.com"

	// Receive scan error
	updated, _ := m.Update(ScanCompletedMsg{
		ScanID: 10,
		Err:    errors.New("connection reset by peer"),
	})
	m = updated.(Model)
	if m.ScanErr == nil {
		t.Fatal("expected ScanErr to be set")
	}
	if m.CurrentScreen != ScreenScanning {
		t.Fatalf("expected to stay on ScreenScanning displaying error, got %v", m.CurrentScreen)
	}

	// Press Enter to retry
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("expected non-nil tea.Cmd on retry")
	}
	if m.ScanErr != nil {
		t.Fatal("expected ScanErr to be reset on retry")
	}
	if m.ScanID != 11 {
		t.Fatalf("expected ScanID incremented to 11, got %d", m.ScanID)
	}
}

func TestFindingsExplorationAndFiltering(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.Assessment = sampleTestAssessment()
	m.FilteredFindings = m.Assessment.Findings
	m.CurrentScreen = ScreenFindings

	if len(m.FilteredFindings) != 3 {
		t.Fatalf("expected 3 findings initially, got %d", len(m.FilteredFindings))
	}

	// Filter by Medium (key '4')
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	m = updated.(Model)
	if m.ActiveFilter != FilterMedium {
		t.Fatalf("expected FilterMedium, got %v", m.ActiveFilter)
	}
	if len(m.FilteredFindings) != 1 {
		t.Fatalf("expected 1 medium finding, got %d", len(m.FilteredFindings))
	}
	if m.FilteredFindings[0].Code != "WEB_CSP_UNSAFE_EVAL" {
		t.Fatalf("unexpected finding code: %s", m.FilteredFindings[0].Code)
	}

	// Filter by Critical (key '2') -> 0 findings
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = updated.(Model)
	if len(m.FilteredFindings) != 0 {
		t.Fatalf("expected 0 critical findings, got %d", len(m.FilteredFindings))
	}

	// Filter back to All (key '1')
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m = updated.(Model)
	if len(m.FilteredFindings) != 3 {
		t.Fatalf("expected 3 findings for All, got %d", len(m.FilteredFindings))
	}

	// Navigate cursor down
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	if m.SelectedFindingIdx != 1 {
		t.Fatalf("expected SelectedFindingIdx 1, got %d", m.SelectedFindingIdx)
	}

	// Press Enter to inspect details
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.CurrentScreen != ScreenFindingDetail {
		t.Fatalf("expected ScreenFindingDetail, got %v", m.CurrentScreen)
	}

	// Esc returns to ScreenFindings
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.CurrentScreen != ScreenFindings {
		t.Fatalf("expected back to ScreenFindings, got %v", m.CurrentScreen)
	}

	// Esc again returns to ScreenOverview
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected back to ScreenOverview, got %v", m.CurrentScreen)
	}
}

func TestCoverageAndHelpNavigation(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.Assessment = sampleTestAssessment()
	m.CurrentScreen = ScreenOverview

	// Press 'c' for Coverage
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = updated.(Model)
	if m.CurrentScreen != ScreenCoverage {
		t.Fatalf("expected ScreenCoverage, got %v", m.CurrentScreen)
	}

	// Esc returns to Overview
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected ScreenOverview, got %v", m.CurrentScreen)
	}

	// Press '?' for Help
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = updated.(Model)
	if m.CurrentScreen != ScreenHelp {
		t.Fatalf("expected ScreenHelp, got %v", m.CurrentScreen)
	}

	// Press '?' again to toggle back
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = updated.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected return to ScreenOverview from help, got %v", m.CurrentScreen)
	}
}

func TestReportExport(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewModel(config.Default(), false)
	m.Assessment = sampleTestAssessment()
	m.CurrentScreen = ScreenOverview

	// Press 'e' to open Export
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = updated.(Model)
	if m.CurrentScreen != ScreenExport {
		t.Fatalf("expected ScreenExport, got %v", m.CurrentScreen)
	}

	// 1. Export JSON
	jsonPath := filepath.Join(tmpDir, "export-test.json")
	m.ExportPathInput.SetValue(jsonPath)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("expected export cmd")
	}
	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)
	if !m.ExportSuccess {
		t.Fatalf("expected export success, got err: %v", m.ExportErr)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"schema_version": "bouclier-risk/v1"`) {
		t.Fatalf("exported file missing schema_version:\n%s", string(data))
	}

	// Check file permissions 0600 (on POSIX systems)
	info, err := os.Stat(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("expected file permission 0600, got %o", info.Mode().Perm())
	}

	// 2. Toggle to Markdown (Tab) and export
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = updated.(Model)
	if m.ExportFormat != "markdown" {
		t.Fatalf("expected format markdown after tab, got %s", m.ExportFormat)
	}

	mdPath := filepath.Join(tmpDir, "export-test.md")
	m.ExportPathInput.SetValue(mdPath)
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	msg = cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)
	if !m.ExportSuccess {
		t.Fatalf("expected markdown export success, got err: %v", m.ExportErr)
	}
	mdData, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mdData), "# Bouclier Website Risk Assessment") {
		t.Fatalf("exported markdown missing title:\n%s", string(mdData))
	}
}

func TestViewRenderingNoPanics(t *testing.T) {
	for _, noColor := range []bool{false, true} {
		m := NewModel(config.Default(), noColor)
		m.Width = 80
		m.Height = 24
		m.Assessment = sampleTestAssessment()
		m.FilteredFindings = m.Assessment.Findings

		screens := []Screen{
			ScreenDashboard,
			ScreenURLInput,
			ScreenScanning,
			ScreenOverview,
			ScreenFindings,
			ScreenFindingDetail,
			ScreenCoverage,
			ScreenExport,
			ScreenHelp,
		}

		for _, screen := range screens {
			m.CurrentScreen = screen
			view := m.View()
			if len(view) == 0 {
				t.Fatalf("screen %v produced empty view (noColor=%v)", screen, noColor)
			}
			if noColor && strings.Contains(view, "\033[") {
				t.Errorf("screen %v contained ANSI escape code in no-color mode", screen)
			}
		}
	}
}

func TestEndToEndMockScan(t *testing.T) {
	restore := SetScanRunnerForTesting(func(ctx context.Context, cfg *config.Config, opts cli.ScanOptions, onProgress cli.ScanProgressFunc) (*cli.ScanPipelineResult, error) {
		if onProgress != nil {
			onProgress(cli.StageURLAnalysis, cli.StageStateRunning, "checking URL")
			onProgress(cli.StageURLAnalysis, cli.StageStateCompleted, "done")
			onProgress(cli.StageTLSAndCertificates, cli.StageStateRunning, "checking TLS")
			onProgress(cli.StageTLSAndCertificates, cli.StageStateCompleted, "done")
		}
		norm, _ := heuristics.NormalizeURL(opts.Target)
		return &cli.ScanPipelineResult{
			Assessment:    sampleTestAssessment(),
			NormalizedURL: norm,
		}, nil
	})
	defer restore()

	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenURLInput
	m.URLInput.SetValue("https://test.example")

	// Trigger scan
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.CurrentScreen != ScreenScanning {
		t.Fatalf("expected ScreenScanning, got %v", m.CurrentScreen)
	}

	// Consume progress and completion messages
	var executeCmd func(c tea.Cmd)
	executeCmd = func(c tea.Cmd) {
		if c == nil {
			return
		}
		raw := c()
		if raw == nil {
			return
		}
		if batch, ok := raw.(tea.BatchMsg); ok {
			for _, sub := range batch {
				executeCmd(sub)
			}
			return
		}
		if _, isTick := raw.(TickMsg); isTick {
			return
		}
		var nextCmd tea.Cmd
		updated, nextCmd = m.Update(raw)
		m = updated.(Model)
		if nextCmd != nil && m.CurrentScreen != ScreenOverview {
			executeCmd(nextCmd)
		}
	}
	executeCmd(cmd)

	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected transition to ScreenOverview, got %v", m.CurrentScreen)
	}
	if m.Assessment == nil {
		t.Fatal("expected non-nil Assessment after mock scan")
	}
}

func TestScanCancellationEscAndReturnToDashboard(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenScanning
	m.ScanID = 100
	cancelled := false
	m.ScanCancel = func() {
		cancelled = true
	}

	// 1. Press Esc to cancel active scan
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if !cancelled {
		t.Fatal("expected ScanCancel() to be invoked on Esc")
	}
	if m.ScanErr == nil || !strings.Contains(m.ScanErr.Error(), "cancelled") {
		t.Fatalf("expected scan cancelled error, got %v", m.ScanErr)
	}
	if m.CurrentScreen != ScreenScanning {
		t.Fatalf("expected to remain on ScreenScanning in cancelled state, got %v", m.CurrentScreen)
	}

	// 2. Press Esc again to return to Dashboard
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.CurrentScreen != ScreenDashboard {
		t.Fatalf("expected ScreenDashboard after second Esc, got %v", m.CurrentScreen)
	}

	// 3. From dashboard, initiate a subsequent scan successfully
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.CurrentScreen != ScreenURLInput {
		t.Fatalf("expected ScreenURLInput, got %v", m.CurrentScreen)
	}
}

func TestCancellationIgnoresStaleScanCompletedMsg(t *testing.T) {
	m := NewModel(config.Default(), false)
	m.CurrentScreen = ScreenScanning
	m.ScanID = 77
	m.ScanCancel = func() {}

	// User cancels scan
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = updated.(Model)
	if m.ScanErr == nil {
		t.Fatal("expected ScanErr to be set")
	}

	// Delayed successful ScanCompletedMsg arrives for scanID 77
	assessment := sampleTestAssessment()
	updated, _ = m.Update(ScanCompletedMsg{
		ScanID:     77,
		Assessment: assessment,
	})
	m = updated.(Model)

	// Verify stale result did NOT transition to ScreenOverview or overwrite ScanErr
	if m.CurrentScreen != ScreenScanning {
		t.Fatalf("expected ScreenScanning (retaining cancelled error state), got %v", m.CurrentScreen)
	}
	if m.Assessment != nil {
		t.Fatalf("expected Assessment to remain nil after cancelled scan, got %+v", m.Assessment)
	}
	if m.ScanErr == nil || !strings.Contains(m.ScanErr.Error(), "cancelled") {
		t.Fatalf("expected cancelled ScanErr to be preserved, got %v", m.ScanErr)
	}
}

func TestNarrowTerminalWidth(t *testing.T) {
	for _, width := range []int{40, 35} {
		m := NewModel(config.Default(), false)
		m.Width = width
		m.Height = 24
		m.Assessment = sampleTestAssessment()
		m.FilteredFindings = m.Assessment.Findings

		screens := []Screen{
			ScreenDashboard,
			ScreenURLInput,
			ScreenScanning,
			ScreenOverview,
			ScreenFindings,
			ScreenFindingDetail,
			ScreenCoverage,
			ScreenExport,
			ScreenHelp,
		}

		for _, screen := range screens {
			m.CurrentScreen = screen
			view := m.View()
			if len(view) == 0 {
				t.Fatalf("screen %v rendered empty view at width %d", screen, width)
			}
		}
	}
}

func TestNoColorEnvironmentVariable(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	m := NewModel(config.Default(), false)
	if !m.Styles.NoColor {
		t.Fatal("expected styles.NoColor=true when NO_COLOR env var is set")
	}

	m.Width = 80
	m.Height = 24
	m.Assessment = sampleTestAssessment()
	m.FilteredFindings = m.Assessment.Findings

	for _, screen := range []Screen{ScreenDashboard, ScreenOverview, ScreenFindings} {
		m.CurrentScreen = screen
		view := m.View()
		if strings.Contains(view, "\033[") {
			t.Errorf("screen %v contained ANSI color code despite NO_COLOR=1", screen)
		}
	}
}

func TestTUIDashboardRecentScans(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://alpha-portal.com"
	_, err = cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-10*time.Minute), time.Now().Add(-9*time.Minute), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatalf("PersistScanAssessment failed: %v", err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)
	if len(m.RecentScans) != 1 {
		t.Fatalf("expected 1 recent scan, got %d", len(m.RecentScans))
	}

	view := m.View()
	if !strings.Contains(view, "Recent Scans") {
		t.Fatal("expected view to contain 'Recent Scans'")
	}
	if !strings.Contains(view, "alpha-portal.com") {
		t.Fatal("expected view to contain 'alpha-portal.com'")
	}
	if !strings.Contains(view, "[ H ]") {
		t.Fatal("expected view to contain history shortcut '[ H ]'")
	}
}

func TestTUIHistoryNavigationAndSelection(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	// Persist 15 scans to test pagination
	for i := 1; i <= 15; i++ {
		ass := sampleTestAssessment()
		ass.Target = "https://domain" + string(rune('a'+i-1)) + ".org"
		_, err = cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(time.Duration(-i)*time.Minute), time.Now(), time.Minute, storage.StatusCompleted)
		if err != nil {
			t.Fatalf("PersistScanAssessment %d failed: %v", i, err)
		}
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Press 'h' from dashboard to enter history
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	m = model.(Model)

	if m.CurrentScreen != ScreenHistory {
		t.Fatalf("expected ScreenHistory, got %v", m.CurrentScreen)
	}
	if m.HistoryTotal != 15 {
		t.Fatalf("expected HistoryTotal=15, got %d", m.HistoryTotal)
	}
	if len(m.HistoryRecords) != 10 {
		t.Fatalf("expected 10 records on page 0, got %d", len(m.HistoryRecords))
	}
	if m.HistorySelectedIdx != 0 {
		t.Fatalf("expected HistorySelectedIdx=0, got %d", m.HistorySelectedIdx)
	}

	// Move cursor down
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = model.(Model)
	if m.HistorySelectedIdx != 1 {
		t.Fatalf("expected HistorySelectedIdx=1, got %d", m.HistorySelectedIdx)
	}

	// Page forward using ']'
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{']'}})
	m = model.(Model)
	if m.HistoryPage != 1 {
		t.Fatalf("expected HistoryPage=1, got %d", m.HistoryPage)
	}
	if len(m.HistoryRecords) != 5 {
		t.Fatalf("expected 5 records on page 1, got %d", len(m.HistoryRecords))
	}

	// Page back using '['
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'['}})
	m = model.(Model)
	if m.HistoryPage != 0 {
		t.Fatalf("expected HistoryPage=0, got %d", m.HistoryPage)
	}
	if len(m.HistoryRecords) != 10 {
		t.Fatalf("expected 10 records on page 0, got %d", len(m.HistoryRecords))
	}
}

func TestTUIHistoryOpenAssessment(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://historical-target.org"
	ass.OverallScore = 77
	_, err = cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-5*time.Minute), time.Now(), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatalf("PersistScanAssessment failed: %v", err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Enter history screen
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	m = model.(Model)

	// Press Enter to open the report
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = model.(Model)

	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected ScreenOverview, got %v", m.CurrentScreen)
	}
	if m.Assessment == nil {
		t.Fatal("expected Assessment to be non-nil after opening from history")
	}
	if m.Assessment.Target != "https://historical-target.org" {
		t.Fatalf("expected target 'https://historical-target.org', got %s", m.Assessment.Target)
	}
	if m.Assessment.OverallScore != 77 {
		t.Fatalf("expected overall score 77, got %d", m.Assessment.OverallScore)
	}
	if m.PreviousScreen != ScreenHistory {
		t.Fatalf("expected PreviousScreen=ScreenHistory, got %v", m.PreviousScreen)
	}

	// Press Esc to return to history screen
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(Model)
	if m.CurrentScreen != ScreenHistory {
		t.Fatalf("expected return to ScreenHistory, got %v", m.CurrentScreen)
	}
}

func TestTUIHistoryDeleteConfirmation(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://delete-me.org"
	rec, err := cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-5*time.Minute), time.Now(), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatalf("PersistScanAssessment failed: %v", err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Enter history screen
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	m = model.(Model)

	// Press 'd' to initiate delete confirmation
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m = model.(Model)

	if !m.HistoryDeleteConfirm {
		t.Fatal("expected HistoryDeleteConfirm to be true")
	}
	if m.HistoryDeleteID != rec.ShortID() {
		t.Fatalf("expected HistoryDeleteID=%s, got %s", rec.ShortID(), m.HistoryDeleteID)
	}

	// Verify confirmation card appears in view
	view := m.View()
	if !strings.Contains(view, "Confirm Deletion") {
		t.Fatal("expected view to contain 'Confirm Deletion'")
	}

	// Press 'n' to cancel deletion
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m = model.(Model)

	if m.HistoryDeleteConfirm {
		t.Fatal("expected HistoryDeleteConfirm to be false after cancellation")
	}
	if m.HistoryTotal != 1 {
		t.Fatalf("expected HistoryTotal to remain 1, got %d", m.HistoryTotal)
	}

	// Press 'd' again and confirm with 'y'
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m = model.(Model)
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m = model.(Model)

	if m.HistoryDeleteConfirm {
		t.Fatal("expected HistoryDeleteConfirm to be false after completion")
	}
	if m.HistoryTotal != 0 {
		t.Fatalf("expected HistoryTotal to be 0 after delete, got %d", m.HistoryTotal)
	}
	if !strings.Contains(m.HistoryStatusMsg, "deleted") {
		t.Fatalf("expected status message to contain 'deleted', got %s", m.HistoryStatusMsg)
	}
}

func TestTUIScanAutoPersistence(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer repo.Close()

	// Mock scan runner to return assessment
	restore := SetScanRunnerForTesting(func(ctx context.Context, cfg *config.Config, opts cli.ScanOptions, onProgress cli.ScanProgressFunc) (*cli.ScanPipelineResult, error) {
		ass := sampleTestAssessment()
		ass.Target = opts.Target
		// Use ExecuteScanPipeline's persistence logic directly or persist via options
		rec, _ := cli.PersistScanAssessment(ctx, opts.Storage, ass, opts.Target, time.Now().Add(-2*time.Second), time.Now(), 2*time.Second, storage.StatusCompleted)
		return &cli.ScanPipelineResult{
			Assessment:    ass,
			ScanRecord:    rec,
			NormalizedURL: &heuristics.NormalizedURL{Normalized: opts.Target},
		}, nil
	})
	defer restore()

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)
	m.ScanTarget = "https://auto-persist.org"
	m.ScanChan = make(chan tea.Msg, 10)

	// Trigger scan execution via StartScanCmd
	cmd := StartScanCmd(m.ScanID, context.Background(), cfg, repo, m.ScanTarget, m.ScanChan)
	msg := cmd() // waits and returns message from channel

	// Pass completed message to model Update
	model, _ := m.Update(msg)
	m = model.(Model)

	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected ScreenOverview, got %v", m.CurrentScreen)
	}

	// Verify exactly 1 scan in database
	ctx := context.Background()
	count, err := repo.CountScans(ctx, storage.ListFilter{})
	if err != nil {
		t.Fatalf("CountScans failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 scan in database, got %d", count)
	}

	// Verify RecentScans in model was reloaded
	if len(m.RecentScans) != 1 {
		t.Fatalf("expected 1 recent scan in model, got %d", len(m.RecentScans))
	}
	if m.RecentScans[0].Target != "https://auto-persist.org" {
		t.Fatalf("expected recent scan target 'https://auto-persist.org', got %s", m.RecentScans[0].Target)
	}
}

func TestTUICompletionMessageRedeliveryDoesNotDuplicateRecord(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://redelivery-test.org"
	rec, err := cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-5*time.Second), time.Now(), 5*time.Second, storage.StatusCompleted)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)
	m.ScanID = 42

	completedMsg := ScanCompletedMsg{
		ScanID:     42,
		Assessment: ass,
		ScanRecord: rec,
	}

	// First delivery
	model, _ := m.Update(completedMsg)
	m = model.(Model)

	// Second delivery of identical message
	model, _ = m.Update(completedMsg)
	m = model.(Model)

	// Third delivery
	model, _ = m.Update(completedMsg)
	m = model.(Model)

	// Count must remain exactly 1
	count, err := repo.CountScans(ctx, storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 scan despite redeliveries, got %d", count)
	}
}

func TestTUIReturningToScreensDoesNotDuplicateRecord(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://nav-test.org"
	rec, err := cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-5*time.Second), time.Now(), 5*time.Second, storage.StatusCompleted)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)
	m.ScanID = 10
	model, _ := m.Update(ScanCompletedMsg{ScanID: 10, Assessment: ass, ScanRecord: rec})
	m = model.(Model)

	// Navigate to Findings
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	m = model.(Model)
	if m.CurrentScreen != ScreenFindings {
		t.Fatalf("expected ScreenFindings, got %v", m.CurrentScreen)
	}

	// Navigate back to Overview
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected ScreenOverview, got %v", m.CurrentScreen)
	}

	// Navigate to Dashboard
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(Model)
	if m.CurrentScreen != ScreenDashboard {
		t.Fatalf("expected ScreenDashboard, got %v", m.CurrentScreen)
	}

	// Return to active assessment using 'r'
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = model.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected ScreenOverview on return, got %v", m.CurrentScreen)
	}

	// Verify scan count remains 1
	count, err := repo.CountScans(ctx, storage.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 record after navigation, got %d", count)
	}
}

func TestTUIHistoricalExportJSONAndMarkdown(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://export-history.org"
	_, err = cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-10*time.Minute), time.Now(), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// 1. Enter History screen
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	m = model.(Model)
	if m.CurrentScreen != ScreenHistory {
		t.Fatalf("expected ScreenHistory, got %v", m.CurrentScreen)
	}

	// 2. Open report into Overview
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = model.(Model)
	if m.CurrentScreen != ScreenOverview {
		t.Fatalf("expected ScreenOverview, got %v", m.CurrentScreen)
	}

	// 3. Navigate to Export screen using 'e'
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = model.(Model)
	if m.CurrentScreen != ScreenExport {
		t.Fatalf("expected ScreenExport, got %v", m.CurrentScreen)
	}

	// 4. Export as JSON
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "historical-report.json")
	m.ExportPathInput.SetValue(jsonPath)
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = model.(Model)
	if cmd != nil {
		expMsg := cmd()
		model, _ = m.Update(expMsg)
		m = model.(Model)
	}

	if !m.ExportSuccess {
		t.Fatalf("expected export success, err: %v", m.ExportErr)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read exported JSON failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("invalid exported JSON: %v", err)
	}
	if parsed["schema_version"] != "bouclier-risk/v1" {
		t.Fatalf("unexpected schema_version: %v", parsed["schema_version"])
	}

	// Check file permissions (on Unix-like platforms where 0600 applies)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(jsonPath)
		if err == nil && info.Mode().Perm() != 0600 {
			t.Errorf("expected 0600 file permissions, got %o", info.Mode().Perm())
		}
	}

	// 5. Return to Overview and export as Markdown
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(Model)
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = model.(Model)

	// Toggle to Markdown with Tab
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = model.(Model)
	if m.ExportFormat != "markdown" {
		t.Fatalf("expected markdown format after Tab, got %s", m.ExportFormat)
	}

	mdPath := filepath.Join(tmpDir, "historical-report.md")
	m.ExportPathInput.SetValue(mdPath)
	model, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = model.(Model)
	if cmd != nil {
		expMsg := cmd()
		model, _ = m.Update(expMsg)
		m = model.(Model)
	}

	if !m.ExportSuccess {
		t.Fatalf("expected markdown export success, err: %v", m.ExportErr)
	}
	mdData, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read exported MD failed: %v", err)
	}
	if !strings.Contains(string(mdData), "# Bouclier Website Risk Assessment") {
		t.Fatalf("markdown report missing expected header:\n%s", string(mdData))
	}
}

func TestTUIHistoricalDirectExport(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	ass := sampleTestAssessment()
	ass.Target = "https://direct-export.org"
	_, err = cli.PersistScanAssessment(ctx, repo, ass, ass.Target, time.Now().Add(-5*time.Minute), time.Now(), time.Minute, storage.StatusCompleted)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Enter history
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	m = model.(Model)

	// Press 'e' directly from history
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = model.(Model)

	if m.CurrentScreen != ScreenExport {
		t.Fatalf("expected ScreenExport, got %v", m.CurrentScreen)
	}
	if m.Assessment == nil || m.Assessment.Target != "https://direct-export.org" {
		t.Fatalf("unexpected assessment loaded for direct export: %v", m.Assessment)
	}

	// Press Esc to return directly to ScreenHistory
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(Model)
	if m.CurrentScreen != ScreenHistory {
		t.Fatalf("expected return to ScreenHistory, got %v", m.CurrentScreen)
	}
}

func TestTUIIntelNavigationAndTabs(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	_ = repo.RegisterSource(ctx, storage.IntelSource{
		ID:           "test-source",
		Name:         "Source A",
		ProviderType: "local_file",
		Endpoint:     "/feed.json",
		Enabled:      true,
	})

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Navigate to Intel via 'i'
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m = model.(Model)

	if m.CurrentScreen != ScreenIntel {
		t.Fatalf("expected ScreenIntel, got %v", m.CurrentScreen)
	}
	if m.IntelActiveTab != 0 {
		t.Fatalf("expected initial tab 0, got %d", m.IntelActiveTab)
	}

	// Switch tabs via '2'
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = model.(Model)
	if m.IntelActiveTab != 1 {
		t.Fatalf("expected tab 1, got %d", m.IntelActiveTab)
	}

	// Switch tabs via Tab key
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = model.(Model)
	if m.IntelActiveTab != 2 {
		t.Fatalf("expected tab 2 after Tab, got %d", m.IntelActiveTab)
	}

	// View rendering should not panic
	view := m.View()
	if !strings.Contains(view, "Threat Intelligence & IOCs") {
		t.Errorf("expected view to contain title, got: %s", view)
	}

	// Esc returns to Dashboard
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(Model)
	if m.CurrentScreen != ScreenDashboard {
		t.Fatalf("expected return to ScreenDashboard, got %v", m.CurrentScreen)
	}
}

func TestTUIIntelSearchAndSync(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	_ = repo.RegisterSource(ctx, storage.IntelSource{
		ID:           "test-source",
		Name:         "Source A",
		ProviderType: "local_file",
		Endpoint:     "/feed.json",
		Enabled:      true,
	})
	now := time.Now().UTC()
	fut := now.Add(24 * time.Hour)
	_, _, _ = repo.SaveIndicatorBatch(ctx, "test-source", []storage.IntelIndicator{
		{
			Type:       "domain",
			Value:      "searched-evil.com",
			Category:   "phishing",
			Confidence: 92,
			Severity:   "high",
			ExpiresAt:  &fut,
		},
	})

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Jump to Intel and tab 3 (Search)
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m = model.(Model)
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	m = model.(Model)

	// Deliver search completion message
	model, _ = m.Update(IntelSearchCompletedMsg{
		Query: "searched",
		Results: []storage.IntelIndicator{
			{Type: "domain", Value: "searched-evil.com", Category: "phishing", Confidence: 92, Severity: "high"},
		},
		Total: 1,
	})
	m = model.(Model)

	if len(m.IntelSearchResults) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(m.IntelSearchResults))
	}
	if !strings.Contains(m.View(), "searched-evil.com") {
		t.Errorf("expected search result to appear in view")
	}

	// Test update feed triggering
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'u'}})
	m = model.(Model)
	if !m.IntelUpdating {
		t.Errorf("expected IntelUpdating to be true")
	}
	if cmd == nil {
		t.Errorf("expected non-nil async command")
	}

	// Deliver update completed message with matching SyncID
	model, _ = m.Update(IntelUpdateCompletedMsg{SyncID: m.IntelSyncID, Message: "Synchronization complete."})
	m = model.(Model)
	if m.IntelUpdating {
		t.Errorf("expected IntelUpdating to be false after completion")
	}
	if m.IntelUpdateMsg != "Synchronization complete." {
		t.Errorf("unexpected update message: %s", m.IntelUpdateMsg)
	}
}

func TestTUISyncReliability(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	_ = repo.RegisterSource(ctx, storage.IntelSource{
		ID:           "test-source",
		Name:         "Existing Community Feed",
		ProviderType: "local_file",
		Endpoint:     "/feed.json",
		Enabled:      true,
	})
	fut := time.Now().UTC().Add(48 * time.Hour)
	_, _, _ = repo.SaveIndicatorBatch(ctx, "test-source", []storage.IntelIndicator{
		{
			Type:       "domain",
			Value:      "existing-malware.com",
			Category:   "malware",
			Confidence: 90,
			Severity:   "high",
			ExpiresAt:  &fut,
		},
	})

	cfg := config.Default()
	m := NewModelWithStorage(cfg, false, repo)

	// Navigate to Intel screen
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m = model.(Model)

	// 1. Non-blocking sync command execution
	model, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'u'}})
	m = model.(Model)
	if !m.IntelUpdating {
		t.Fatalf("expected IntelUpdating=true after pressing U")
	}
	if cmd == nil {
		t.Fatalf("expected non-nil tea.Cmd for async sync execution")
	}
	initialSyncID := m.IntelSyncID
	if initialSyncID == 0 {
		t.Fatalf("expected non-zero IntelSyncID")
	}

	// 2. Cancellation handling via 'c' key
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m = model.(Model)
	if m.IntelUpdating {
		t.Fatalf("expected IntelUpdating=false after pressing C (cancellation)")
	}
	if !strings.Contains(m.IntelUpdateMsg, "cancelled") {
		t.Errorf("expected cancellation message, got: %s", m.IntelUpdateMsg)
	}

	// 3. Stale message protection: message from cancelled sync arrives
	model, _ = m.Update(IntelUpdateCompletedMsg{
		SyncID:  initialSyncID, // Stale!
		Message: "Stale message that should be ignored",
		Err:     nil,
	})
	m = model.(Model)
	// Stale message must not overwrite current message
	if m.IntelUpdateMsg == "Stale message that should be ignored" {
		t.Fatalf("PROTECTION FAILURE: stale sync message overwrote current state!")
	}

	// 4. Trigger second sync and test error state display
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'u'}})
	m = model.(Model)
	secondSyncID := m.IntelSyncID
	if secondSyncID <= initialSyncID {
		t.Fatalf("expected incremented sync ID, got %d <= %d", secondSyncID, initialSyncID)
	}

	// Deliver failure for second sync
	syncErr := errors.New("upstream feed timed out (connection reset by peer)")
	model, _ = m.Update(IntelUpdateCompletedMsg{
		SyncID: secondSyncID,
		Err:    syncErr,
	})
	m = model.(Model)
	if m.IntelUpdating {
		t.Errorf("expected IntelUpdating=false after error")
	}
	if m.IntelErr != syncErr {
		t.Errorf("expected IntelErr to hold sync error, got %v", m.IntelErr)
	}

	// Verify error state is rendered in view
	view := m.View()
	if !strings.Contains(view, "upstream feed timed out") {
		t.Errorf("expected error message in TUI view, got:\n%s", view)
	}

	// 5. Existing intelligence remains searchable even after sync failure
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}}) // Tab 3: Search
	m = model.(Model)
	model, _ = m.Update(IntelSearchCompletedMsg{
		Query: "existing",
		Results: []storage.IntelIndicator{
			{Type: "domain", Value: "existing-malware.com", Category: "malware", Confidence: 90, Severity: "high"},
		},
		Total: 1,
	})
	m = model.(Model)
	if len(m.IntelSearchResults) != 1 {
		t.Errorf("expected existing intelligence to be searchable after failure, got %d results", len(m.IntelSearchResults))
	}
	if !strings.Contains(m.View(), "existing-malware.com") {
		t.Errorf("expected search result in view after sync failure")
	}
}
