package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/risk"
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
	if len(m.StageOrder) != 6 {
		t.Fatalf("expected 6 scan stages, got %d", len(m.StageOrder))
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
