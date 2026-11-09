package tui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"bouclier/internal/api"
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/report"
	"bouclier/internal/storage"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Update handles incoming events and state transitions.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		return m, nil

	case ScanProgressMsg:
		if msg.ScanID != m.ScanID {
			// Discard stale progress updates from earlier canceled scans
			return m, nil
		}
		m.Stages[msg.Stage] = msg.State
		if msg.Message != "" {
			m.StageMessages[msg.Stage] = msg.Message
		}
		return m, WaitForScanMsg(m.ScanChan)

	case ScanCompletedMsg:
		if msg.ScanID != m.ScanID {
			return m, nil
		}
		if m.ScanCancel != nil {
			m.ScanCancel = nil
		}
		m.cancelAIExplanation()
		m.AIExplanationText = ""
		m.AIExplanationModel = ""
		m.AIExplanationErr = nil
		m.AIExplaining = false
		if m.ScanErr != nil {
			// Scan was cancelled or already failed; do not overwrite with stale results
			return m, nil
		}
		if msg.Err != nil {
			m.ScanErr = msg.Err
			return m, nil
		}
		m.Assessment = msg.Assessment
		m.IsSSRFBlocked = msg.IsSSRFBlocked
		m.ActiveFilter = FilterAll
		m.FilteredFindings = m.Assessment.Findings
		m.SelectedFindingIdx = 0
		m.CurrentScreen = ScreenOverview

		// Scan was persisted by the scan pipeline orchestrator.
		// Reload recent scans so dashboard reflects the newly saved record.
		m.reloadRecentScans()
		return m, nil

	case AIExplanationCompletedMsg:
		if msg.RequestID != m.AIExplainRequestID {
			return m, nil
		}
		if m.AIExplainCancel != nil {
			m.AIExplainCancel()
			m.AIExplainCancel = nil
		}
		m.AIExplaining = false
		if msg.Err != nil {
			m.AIExplanationErr = msg.Err
		} else {
			m.AIExplanationText = msg.Text
			m.AIExplanationModel = msg.Model
			m.AIExplanationErr = nil
		}
		return m, nil

	case AIModelsLoadedMsg:
		if msg.RequestID != m.AIModelListRequest {
			return m, nil
		}
		m.AIModelLoading = false
		m.AIModelListErr = msg.Err
		if msg.Err == nil {
			m.AIModels = msg.Models
			m.AIModelSelectedIdx = 0
			if m.Config != nil {
				for i, model := range m.AIModels {
					if model == m.Config.AI.Ollama.Model {
						m.AIModelSelectedIdx = i
						break
					}
				}
			}
		} else {
			m.AIModels = nil
			m.AIModelSelectedIdx = 0
		}
		return m, nil

	case TickMsg:
		if m.CurrentScreen == ScreenScanning && m.ScanErr == nil {
			m.ScanElapsed = time.Since(m.ScanStartTime)
			return m, TickCmd()
		}
		return m, nil

	case ExportCompletedMsg:
		m.ExportSuccess = (msg.Err == nil)
		m.ExportErr = msg.Err
		if msg.Err == nil {
			m.ExportMessage = fmt.Sprintf("Report saved to %s", msg.Path)
		}
		return m, nil

	case IntelStatsLoadedMsg:
		if msg.Err == nil {
			m.IntelStats = msg.Stats
			m.IntelSources = msg.Sources
		}
		return m, nil

	case IntelSearchCompletedMsg:
		if msg.Err == nil {
			m.IntelSearchResults = msg.Results
		} else {
			m.IntelErr = msg.Err
		}
		return m, nil

	case IntelUpdateCompletedMsg:
		if !m.IntelUpdating || msg.SyncID != m.IntelSyncID {
			// Discard stale message from superseded or cancelled sync
			return m, nil
		}
		m.IntelUpdating = false
		m.IntelCancel = nil
		if msg.Err != nil && !errors.Is(msg.Err, context.Canceled) {
			m.IntelErr = msg.Err
			m.IntelUpdateMsg = ""
		} else if errors.Is(msg.Err, context.Canceled) {
			m.IntelErr = nil
			m.IntelUpdateMsg = "Synchronization cancelled."
		} else {
			m.IntelErr = nil
			m.IntelUpdateMsg = msg.Message
			m.reloadIntelStats()
		}
		return m, nil

	case tea.KeyMsg:
		// Force quit from anywhere
		if key.Matches(msg, m.Keys.ForceQuit) {
			if m.ScanCancel != nil {
				m.ScanCancel()
			}
			m.stopAPIServer()
			m.cancelAIExplanation()
			m.Quitting = true
			return m, tea.Quit
		}

		// Command palette shortcut from anywhere: ctrl+k
		if msg.String() == "ctrl+k" {
			if m.CurrentScreen == ScreenCommandPalette {
				m.CurrentScreen = m.PalettePreviousScreen
				return m, nil
			}
			m.openCommandPalette()
			return m, textinput.Blink
		}

		// When not in text input mode, "/" opens command palette
		if msg.String() == "/" && !m.isTextInputActive() {
			m.openCommandPalette()
			return m, textinput.Blink
		}

		// Global module jumps (1-7) when on screens that do not use numbers for local actions
		if !m.isTextInputActive() && m.CurrentScreen != ScreenFindings && m.CurrentScreen != ScreenIntel && m.CurrentScreen != ScreenAbout {
			switch msg.String() {
			case "1":
				return m.openModule(0)
			case "2":
				return m.openModule(1)
			case "3":
				return m.openModule(2)
			case "4":
				return m.openModule(3)
			case "5":
				return m.openModule(4)
			case "6":
				return m.openModule(5)
			case "7":
				return m.openModule(6)
			}
		}

		// Help toggle
		if key.Matches(msg, m.Keys.Help) && !m.isTextInputActive() {
			if m.CurrentScreen == ScreenHelp {
				m.CurrentScreen = m.PreviousScreen
			} else {
				m.PreviousScreen = m.CurrentScreen
				m.CurrentScreen = ScreenHelp
			}
			return m, nil
		}

		// Quit shortcut from non-input screens
		if key.Matches(msg, m.Keys.Quit) && !m.isTextInputActive() {
			if m.ScanCancel != nil {
				m.ScanCancel()
			}
			m.stopAPIServer()
			m.cancelAIExplanation()
			m.Quitting = true
			return m, tea.Quit
		}
	}

	// Delegate to screen-specific updates
	switch m.CurrentScreen {
	case ScreenDashboard:
		return m.updateDashboard(msg)
	case ScreenHistory:
		return m.updateHistory(msg)
	case ScreenHistoryCorrelate:
		return m.updateHistoryCorrelate(msg)
	case ScreenURLInput:
		return m.updateURLInput(msg)
	case ScreenScanning:
		return m.updateScanning(msg)
	case ScreenOverview:
		return m.updateOverview(msg)
	case ScreenFindings:
		return m.updateFindings(msg)
	case ScreenFindingDetail:
		return m.updateFindingDetail(msg)
	case ScreenCoverage:
		return m.updateCoverage(msg)
	case ScreenExport:
		return m.updateExport(msg)
	case ScreenHelp:
		return m.updateHelp(msg)
	case ScreenIntel:
		return m.updateIntel(msg)
	case ScreenIntelSourceAdd:
		return m.updateIntelSourceAdd(msg)
	case ScreenIntelImportExport:
		return m.updateIntelImportExport(msg)
	case ScreenConfig:
		return m.updateConfig(msg)
	case ScreenServices:
		return m.updateServices(msg)
	case ScreenAbout:
		return m.updateAbout(msg)
	case ScreenCommandPalette:
		return m.updateCommandPalette(msg)
	case ScreenAIModelSelect:
		return m.updateAIModelSelect(msg)
	default:
		return m, nil
	}
}

func (m Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "up", "k":
			if m.DashboardSelectedIdx > 0 {
				m.DashboardSelectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.DashboardSelectedIdx < len(workstationModules)-1 {
				m.DashboardSelectedIdx++
			}
			return m, nil
		case "enter":
			return m.openModule(m.DashboardSelectedIdx)
		case "1":
			return m.openModule(0)
		case "2":
			return m.openModule(1)
		case "3":
			return m.openModule(2)
		case "4":
			return m.openModule(3)
		case "5":
			return m.openModule(4)
		case "6":
			return m.openModule(5)
		case "7":
			return m.openModule(6)
		case "s", "n":
			return m.openModule(0)
		case "h", "H":
			return m.openModule(1)
		case "i", "I":
			return m.openModule(2)
		case "r", "R":
			if m.Assessment != nil {
				m.PreviousScreen = ScreenDashboard
				m.CurrentScreen = ScreenOverview
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) openModule(idx int) (tea.Model, tea.Cmd) {
	m.PreviousScreen = ScreenDashboard
	switch idx {
	case 0: // 1. Target Scanner
		m.URLValidationErr = ""
		m.URLInput.Reset()
		m.URLInput.Focus()
		m.ScanInputFocus = 0
		m.CurrentScreen = ScreenURLInput
		return m, textinput.Blink
	case 1: // 2. Scan History
		m.CurrentScreen = ScreenHistory
		m.HistoryDeleteConfirm = false
		m.HistoryStatusMsg = ""
		m.HistoryPage = 0
		m.HistorySelectedIdx = 0
		m.HistoryFiltering = false
		m.loadHistory()
		return m, nil
	case 2: // 3. Threat Intelligence
		m.CurrentScreen = ScreenIntel
		m.reloadIntelStats()
		return m, nil
	case 3: // 4. Security Reports / Export
		m.CurrentScreen = ScreenExport
		m.ExportSuccess = false
		m.ExportMessage = ""
		m.ExportErr = nil
		m.ExportPathInput.SetValue("bouclier-report.json")
		m.ExportPathInput.Focus()
		return m, textinput.Blink
	case 4: // 5. Configuration
		m.CurrentScreen = ScreenConfig
		return m, nil
	case 5: // 6. API & MCP Services
		m.CurrentScreen = ScreenServices
		return m, nil
	case 6: // 7. About & Integrity
		m.CurrentScreen = ScreenAbout
		m.AboutActiveTab = 0
		return m, nil
	default:
		return m, nil
	}
}

func (m Model) updateURLInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			if m.PreviousScreen == ScreenHistory {
				m.CurrentScreen = ScreenHistory
			} else {
				m.CurrentScreen = ScreenDashboard
			}
			return m, nil

		case "tab":
			m.ScanInputFocus = (m.ScanInputFocus + 1) % 4
			if m.ScanInputFocus == 0 {
				m.URLInput.Focus()
				return m, textinput.Blink
			}
			m.URLInput.Blur()
			return m, nil

		case "shift+tab":
			m.ScanInputFocus = (m.ScanInputFocus + 3) % 4
			if m.ScanInputFocus == 0 {
				m.URLInput.Focus()
				return m, textinput.Blink
			}
			m.URLInput.Blur()
			return m, nil

		case "c":
			if m.ScanInputFocus != 0 {
				m.ScanNoCT = !m.ScanNoCT
				return m, nil
			}

		case "o":
			if m.ScanInputFocus != 0 {
				if m.ScanCTScope == "exact" {
					m.ScanCTScope = "registrable"
				} else {
					m.ScanCTScope = "exact"
				}
				return m, nil
			}

		case "t":
			if m.ScanInputFocus != 0 {
				switch m.ScanTimeoutSec {
				case 5:
					m.ScanTimeoutSec = 8
				case 8:
					m.ScanTimeoutSec = 15
				case 15:
					m.ScanTimeoutSec = 30
				default:
					m.ScanTimeoutSec = 5
				}
				return m, nil
			}

		case " ":
			if m.ScanInputFocus == 1 {
				m.ScanNoCT = !m.ScanNoCT
				return m, nil
			}
			if m.ScanInputFocus == 2 {
				if m.ScanCTScope == "exact" {
					m.ScanCTScope = "registrable"
				} else {
					m.ScanCTScope = "exact"
				}
				return m, nil
			}
			if m.ScanInputFocus == 3 {
				switch m.ScanTimeoutSec {
				case 5:
					m.ScanTimeoutSec = 8
				case 8:
					m.ScanTimeoutSec = 15
				case 15:
					m.ScanTimeoutSec = 30
				default:
					m.ScanTimeoutSec = 5
				}
				return m, nil
			}

		case "enter":
			target := strings.TrimSpace(m.URLInput.Value())
			if target == "" {
				m.URLValidationErr = "Target URL cannot be empty"
				return m, nil
			}

			raw := target
			if !strings.Contains(raw, "://") {
				raw = "https://" + raw
			}
			norm, err := heuristics.NormalizeURL(raw)
			if err != nil {
				m.URLValidationErr = fmt.Sprintf("Invalid URL: %v", err)
				return m, nil
			}

			// Validated: initiate asynchronous scan
			m.cancelAIExplanation()
			m.AIExplanationText = ""
			m.AIExplanationModel = ""
			m.AIExplanationErr = nil
			m.ScanID++
			m.ScanTarget = norm.Normalized
			m.ScanStartTime = time.Now()
			m.ScanElapsed = 0
			m.ScanErr = nil
			m.ScanChan = make(chan tea.Msg, 20)

			for _, s := range m.StageOrder {
				m.Stages[s] = cli.StageStatePending
				m.StageMessages[s] = ""
			}

			ctx, cancel := context.WithCancel(context.Background())
			m.ScanCancel = cancel
			m.CurrentScreen = ScreenScanning

			return m, tea.Batch(
				StartScanCmd(m.ScanID, ctx, m.Config, m.Storage, m.ScanTarget, m.ScanNoCT, m.ScanCTScope, m.ScanTimeoutSec, m.ScanChan),
				TickCmd(),
			)
		}
	}

	if m.ScanInputFocus == 0 {
		var cmd tea.Cmd
		m.URLInput, cmd = m.URLInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) updateScanning(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.CancelScan), key.Matches(keyMsg, m.Keys.Back):
			if m.ScanCancel != nil {
				m.ScanCancel()
				m.ScanCancel = nil
				m.ScanErr = errors.New("scan cancelled by user")
				return m, nil
			}
			if m.ScanErr != nil && key.Matches(keyMsg, m.Keys.Back) {
				m.CurrentScreen = ScreenDashboard
				return m, nil
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Confirm):
			if m.ScanErr != nil {
				// Retry scan
				m.ScanID++
				m.ScanStartTime = time.Now()
				m.ScanElapsed = 0
				m.ScanErr = nil
				m.ScanChan = make(chan tea.Msg, 20)
				for _, s := range m.StageOrder {
					m.Stages[s] = cli.StageStatePending
					m.StageMessages[s] = ""
				}
				ctx, cancel := context.WithCancel(context.Background())
				m.ScanCancel = cancel
				return m, tea.Batch(
					StartScanCmd(m.ScanID, ctx, m.Config, m.Storage, m.ScanTarget, m.ScanNoCT, m.ScanCTScope, m.ScanTimeoutSec, m.ScanChan),
					TickCmd(),
				)
			}
		}
	}
	return m, nil
}

func (m Model) updateOverview(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.ViewFindings), key.Matches(keyMsg, m.Keys.Confirm):
			m.CurrentScreen = ScreenFindings
			m.SelectedFindingIdx = 0
			return m, nil

		case key.Matches(keyMsg, m.Keys.ViewCoverage):
			m.CurrentScreen = ScreenCoverage
			return m, nil

		case key.Matches(keyMsg, m.Keys.ExplainAI):
			if m.Config == nil || !m.Config.AI.Enabled || m.Assessment == nil {
				return m, nil
			}
			m.AIModelListRequest++
			m.AIModelLoading = true
			m.AIModelListErr = nil
			m.AIModels = nil
			m.CurrentScreen = ScreenAIModelSelect
			return m, ListOllamaModelsCmd(m.AIModelListRequest)

		case key.Matches(keyMsg, m.Keys.Export):
			m.CurrentScreen = ScreenExport
			m.ExportFormat = "json"
			m.ExportSuccess = false
			m.ExportErr = nil
			m.ExportPathInput.SetValue("bouclier-report.json")
			m.ExportPathInput.Focus()
			return m, textinput.Blink

		case key.Matches(keyMsg, m.Keys.NewScan):
			m.cancelAIExplanation()
			m.URLValidationErr = ""
			m.URLInput.Reset()
			m.URLInput.Focus()
			m.CurrentScreen = ScreenURLInput
			return m, textinput.Blink

		case key.Matches(keyMsg, m.Keys.Back):
			if m.PreviousScreen == ScreenHistory {
				m.CurrentScreen = ScreenHistory
			} else {
				m.CurrentScreen = ScreenDashboard
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateAIModelSelect(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenOverview
			return m, nil
		case key.Matches(keyMsg, m.Keys.Up):
			if m.AIModelSelectedIdx > 0 {
				m.AIModelSelectedIdx--
			}
			return m, nil
		case key.Matches(keyMsg, m.Keys.Down):
			if m.AIModelSelectedIdx < len(m.AIModels)-1 {
				m.AIModelSelectedIdx++
			}
			return m, nil
		case keyMsg.String() == "r" || keyMsg.String() == "R":
			m.AIModelListRequest++
			m.AIModelLoading = true
			m.AIModelListErr = nil
			m.AIModels = nil
			m.AIModelSelectedIdx = 0
			return m, ListOllamaModelsCmd(m.AIModelListRequest)
		case key.Matches(keyMsg, m.Keys.Confirm):
			if m.AIModelLoading || m.AIModelListErr != nil || m.Config == nil || len(m.AIModels) == 0 || m.AIModelSelectedIdx < 0 || m.AIModelSelectedIdx >= len(m.AIModels) {
				return m, nil
			}
			m.Config.AI.Ollama.Model = m.AIModels[m.AIModelSelectedIdx]
			m.CurrentScreen = ScreenOverview
			return m.startAIExplanation()
		}
	}
	return m, nil
}

func (m Model) startAIExplanation() (tea.Model, tea.Cmd) {
	if m.Config == nil || m.Assessment == nil {
		return m, nil
	}
	m.cancelAIExplanation()
	m.AIExplaining = true
	m.AIExplanationText = ""
	m.AIExplanationModel = ""
	m.AIExplanationErr = nil
	cmd, cancel := StartExplainAssessmentCmd(m.AIExplainRequestID, m.Config, m.Assessment)
	m.AIExplainCancel = cancel
	return m, cmd
}

func (m *Model) cancelAIExplanation() {
	if m.AIExplainCancel != nil {
		m.AIExplainCancel()
		m.AIExplainCancel = nil
	}
	m.AIExplainRequestID++
	m.AIExplaining = false
}

func (m Model) updateFindings(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenOverview
			return m, nil

		case key.Matches(keyMsg, m.Keys.Confirm):
			if len(m.FilteredFindings) > 0 && m.SelectedFindingIdx < len(m.FilteredFindings) {
				m.CurrentScreen = ScreenFindingDetail
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Up):
			if m.SelectedFindingIdx > 0 {
				m.SelectedFindingIdx--
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Down):
			if m.SelectedFindingIdx < len(m.FilteredFindings)-1 {
				m.SelectedFindingIdx++
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Tab):
			m.cycleFilter(true)
			return m, nil

		case key.Matches(keyMsg, m.Keys.ShiftTab):
			m.cycleFilter(false)
			return m, nil

		case key.Matches(keyMsg, m.Keys.Filter1):
			m.setFilter(FilterAll)
			return m, nil
		case key.Matches(keyMsg, m.Keys.Filter2):
			m.setFilter(FilterCritical)
			return m, nil
		case key.Matches(keyMsg, m.Keys.Filter3):
			m.setFilter(FilterHigh)
			return m, nil
		case key.Matches(keyMsg, m.Keys.Filter4):
			m.setFilter(FilterMedium)
			return m, nil
		case key.Matches(keyMsg, m.Keys.Filter5):
			m.setFilter(FilterLow)
			return m, nil
		case key.Matches(keyMsg, m.Keys.Filter6):
			m.setFilter(FilterInfo)
			return m, nil
		}
	}
	return m, nil
}

func (m *Model) cycleFilter(forward bool) {
	filters := []SeverityFilter{
		FilterAll,
		FilterCritical,
		FilterHigh,
		FilterMedium,
		FilterLow,
		FilterInfo,
	}
	cur := 0
	for i, f := range filters {
		if f == m.ActiveFilter {
			cur = i
			break
		}
	}
	if forward {
		cur = (cur + 1) % len(filters)
	} else {
		cur = (cur - 1 + len(filters)) % len(filters)
	}
	m.setFilter(filters[cur])
}

func (m *Model) setFilter(f SeverityFilter) {
	m.ActiveFilter = f
	if m.Assessment != nil {
		m.FilteredFindings = FilterFindings(m.Assessment.Findings, f)
	} else {
		m.FilteredFindings = nil
	}
	m.SelectedFindingIdx = 0
}

func (m Model) updateFindingDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenFindings
			return m, nil

		case key.Matches(keyMsg, m.Keys.PrevItem), key.Matches(keyMsg, m.Keys.Left):
			if m.SelectedFindingIdx > 0 {
				m.SelectedFindingIdx--
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.NextItem), key.Matches(keyMsg, m.Keys.Right):
			if m.SelectedFindingIdx < len(m.FilteredFindings)-1 {
				m.SelectedFindingIdx++
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateCoverage(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenOverview
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateExport(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			if m.PreviousScreen == ScreenHistory {
				m.CurrentScreen = ScreenHistory
			} else {
				m.CurrentScreen = ScreenOverview
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Tab):
			if m.ExportFormat == "json" {
				m.ExportFormat = "markdown"
				if m.ExportPathInput.Value() == "bouclier-report.json" || m.ExportPathInput.Value() == "" {
					m.ExportPathInput.SetValue("bouclier-report.md")
				}
			} else {
				m.ExportFormat = "json"
				if m.ExportPathInput.Value() == "bouclier-report.md" || m.ExportPathInput.Value() == "" {
					m.ExportPathInput.SetValue("bouclier-report.json")
				}
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Confirm):
			path := strings.TrimSpace(m.ExportPathInput.Value())
			if path == "" {
				if m.ExportFormat == "markdown" {
					path = "bouclier-report.md"
				} else {
					path = "bouclier-report.json"
				}
			}

			outOpts := cli.OutputOptions{
				Format: m.ExportFormat,
				Output: path,
			}
			err := cli.RenderAndWrite(m.Assessment, outOpts, nil)
			return m, func() tea.Msg {
				return ExportCompletedMsg{Path: path, Err: err}
			}
		}
	}

	var cmd tea.Cmd
	m.ExportPathInput, cmd = m.ExportPathInput.Update(msg)
	return m, cmd
}

func (m Model) updateHelp(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back), key.Matches(keyMsg, m.Keys.Help):
			m.CurrentScreen = m.PreviousScreen
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateHistory(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		if m.HistoryDeleteConfirm {
			switch strings.ToLower(keyMsg.String()) {
			case "y":
				if m.Storage != nil && m.HistoryDeleteID != "" {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					err := m.Storage.DeleteScan(ctx, m.HistoryDeleteID)
					if err != nil {
						m.HistoryStatusMsg = fmt.Sprintf("Delete failed: %v", err)
					} else {
						m.HistoryStatusMsg = fmt.Sprintf("Scan %s deleted successfully.", m.HistoryDeleteID)
					}
				}
				m.HistoryDeleteConfirm = false
				m.loadHistory()
				m.reloadRecentScans()
				return m, nil

			case "n", "esc":
				m.HistoryDeleteConfirm = false
				return m, nil

			default:
				return m, nil
			}
		}

		// If user is actively typing a target filter
		if m.HistoryFiltering {
			switch keyMsg.String() {
			case "esc":
				m.HistoryFiltering = false
				return m, nil
			case "enter":
				m.HistoryFilterText = strings.TrimSpace(m.HistoryFilterInput.Value())
				m.HistoryFiltering = false
				m.HistoryPage = 0
				m.HistorySelectedIdx = 0
				m.loadHistory()
				return m, nil
			default:
				var cmd tea.Cmd
				m.HistoryFilterInput, cmd = m.HistoryFilterInput.Update(msg)
				return m, cmd
			}
		}

		switch keyMsg.String() {
		case "esc", "b":
			m.CurrentScreen = ScreenDashboard
			return m, nil

		case "f":
			m.HistoryFiltering = true
			m.HistoryFilterInput.Reset()
			m.HistoryFilterInput.Focus()
			return m, textinput.Blink

		case "F":
			m.HistoryFilterText = ""
			m.HistoryPage = 0
			m.HistorySelectedIdx = 0
			m.loadHistory()
			return m, nil

		case "c", "C":
			if len(m.HistoryRecords) > 0 && m.HistorySelectedIdx < len(m.HistoryRecords) {
				rec := m.HistoryRecords[m.HistorySelectedIdx]
				m.correlateTarget(rec.Target)
				m.CurrentScreen = ScreenHistoryCorrelate
				return m, nil
			}
			return m, nil

		case "s", "S", "n":
			return m.openModule(0)

		case "up", "k":
			if m.HistorySelectedIdx > 0 {
				m.HistorySelectedIdx--
			}
			return m, nil

		case "down", "j":
			if m.HistorySelectedIdx < len(m.HistoryRecords)-1 {
				m.HistorySelectedIdx++
			}
			return m, nil

		case "[", "p", "P":
			if m.HistoryPage > 0 {
				m.HistoryPage--
				m.HistorySelectedIdx = 0
				m.loadHistory()
			}
			return m, nil

		case "]", "N":
			totalPages := ((m.HistoryTotal - 1) / m.HistoryPageSize) + 1
			if m.HistoryPage < totalPages-1 {
				m.HistoryPage++
				m.HistorySelectedIdx = 0
				m.loadHistory()
			}
			return m, nil

		case "enter":
			if len(m.HistoryRecords) > 0 && m.HistorySelectedIdx < len(m.HistoryRecords) {
				rec := m.HistoryRecords[m.HistorySelectedIdx]
				if m.Storage != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					rep, err := m.Storage.GetScanReport(ctx, rec.ID)
					if err == nil && rep != nil && rep.Assessment != nil {
						m.Assessment = rep.Assessment
						m.FilteredFindings = rep.Assessment.Findings
						m.ActiveFilter = FilterAll
						m.SelectedFindingIdx = 0
						m.PreviousScreen = ScreenHistory
						m.CurrentScreen = ScreenOverview
						return m, nil
					}
					m.HistoryStatusMsg = fmt.Sprintf("Failed to load scan report: %v", err)
				}
			}
			return m, nil

		case "e", "E":
			if len(m.HistoryRecords) > 0 && m.HistorySelectedIdx < len(m.HistoryRecords) {
				rec := m.HistoryRecords[m.HistorySelectedIdx]
				if m.Storage != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					rep, err := m.Storage.GetScanReport(ctx, rec.ID)
					if err == nil && rep != nil && rep.Assessment != nil {
						m.Assessment = rep.Assessment
						m.FilteredFindings = rep.Assessment.Findings
						m.ActiveFilter = FilterAll
						m.SelectedFindingIdx = 0
						m.PreviousScreen = ScreenHistory
						m.CurrentScreen = ScreenExport
						m.ExportFormat = "json"
						m.ExportSuccess = false
						m.ExportErr = nil
						m.ExportPathInput.SetValue(fmt.Sprintf("bouclier-%s.json", rec.ShortID()))
						m.ExportPathInput.Focus()
						return m, textinput.Blink
					}
					m.HistoryStatusMsg = fmt.Sprintf("Failed to load scan report: %v", err)
				}
			}
			return m, nil

		case "d", "x":
			if len(m.HistoryRecords) > 0 && m.HistorySelectedIdx < len(m.HistoryRecords) {
				rec := m.HistoryRecords[m.HistorySelectedIdx]
				m.HistoryDeleteConfirm = true
				m.HistoryDeleteID = rec.ShortID()
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateHistoryCorrelate(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc", "b":
			m.CurrentScreen = ScreenHistory
			return m, nil
		case "q":
			m.Quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *Model) correlateTarget(rawTarget string) {
	if m.Storage == nil {
		m.HistoryCorrelateErr = errors.New("storage repository not connected")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	targetHost := rawTarget
	if strings.Contains(targetHost, "://") {
		if parsed, err := heuristics.NormalizeURL(targetHost); err == nil {
			targetHost = parsed.Hostname
		}
	}
	m.HistoryCorrelateTarget = targetHost

	filter := storage.ListFilter{
		Target: targetHost,
		Limit:  100,
	}
	records, err := m.Storage.ListScans(ctx, filter)
	if err != nil {
		m.HistoryCorrelateErr = fmt.Errorf("list scans: %w", err)
		return
	}
	if len(records) == 0 {
		m.HistoryCorrelateReport = &report.Correlation{Target: targetHost, Scans: nil}
		m.HistoryCorrelateErr = nil
		return
	}

	entries := make([]report.CorrelationEntry, 0, len(records))
	for _, rec := range records {
		entry, err := m.Storage.GetScanEntry(ctx, rec.ID)
		if err == nil && entry != nil && entry.Assessment != nil {
			entries = append(entries, report.CorrelationEntry{
				ID:         rec.ID,
				StartedAt:  rec.StartedAt,
				Assessment: entry.Assessment,
			})
		}
	}

	corr, err := report.Correlate(targetHost, entries)
	if err != nil {
		m.HistoryCorrelateErr = err
		return
	}
	m.HistoryCorrelateReport = &corr
	m.HistoryCorrelateErr = nil
}

func (m *Model) loadHistory() {
	if m.Storage == nil {
		m.HistoryRecords = nil
		m.HistoryTotal = 0
		return
	}
	if m.HistoryPageSize <= 0 {
		m.HistoryPageSize = 10
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	filter := storage.ListFilter{
		Target: m.HistoryFilterText,
		Limit:  m.HistoryPageSize,
		Offset: m.HistoryPage * m.HistoryPageSize,
	}
	records, err := m.Storage.ListScans(ctx, filter)
	if err != nil {
		m.HistoryStatusMsg = fmt.Sprintf("Error listing scans: %v", err)
		return
	}
	total, err := m.Storage.CountScans(ctx, storage.ListFilter{Target: m.HistoryFilterText})
	if err != nil {
		total = len(records)
	}

	m.HistoryRecords = records
	m.HistoryTotal = total
	if m.HistorySelectedIdx >= len(m.HistoryRecords) {
		if len(m.HistoryRecords) > 0 {
			m.HistorySelectedIdx = len(m.HistoryRecords) - 1
		} else {
			m.HistorySelectedIdx = 0
		}
	}
}

func (m *Model) reloadRecentScans() {
	if m.Storage == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if list, err := m.Storage.ListScans(ctx, storage.ListFilter{Limit: 5}); err == nil {
		m.RecentScans = list
	}
}

func (m *Model) reloadIntelStats() {
	if m.Storage == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if stats, err := m.Storage.GetIntelStats(ctx); err == nil {
		m.IntelStats = stats
	}
	if srcs, err := m.Storage.ListSources(ctx); err == nil {
		m.IntelSources = srcs
	}
}

func (m Model) updateIntel(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		if m.IntelPruneConfirm {
			switch strings.ToLower(keyMsg.String()) {
			case "y":
				if m.Storage != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					pruned, err := m.Storage.PruneExpiredIndicators(ctx, time.Now().UTC(), false)
					if err != nil {
						m.IntelErr = err
					} else {
						m.IntelUpdateMsg = fmt.Sprintf("Pruned %d expired indicators.", pruned)
					}
				}
				m.IntelPruneConfirm = false
				m.reloadIntelStats()
				return m, nil
			case "n", "esc":
				m.IntelPruneConfirm = false
				return m, nil
			default:
				return m, nil
			}
		}

		if m.IntelDeleteSourceConfirm {
			switch strings.ToLower(keyMsg.String()) {
			case "y":
				if m.Storage != nil && m.IntelDeleteSourceID != "" {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					err := m.Storage.DeleteSource(ctx, m.IntelDeleteSourceID)
					if err != nil {
						m.IntelErr = err
					} else {
						m.IntelUpdateMsg = fmt.Sprintf("Source %q deleted.", m.IntelDeleteSourceID)
					}
				}
				m.IntelDeleteSourceConfirm = false
				m.reloadIntelStats()
				return m, nil
			case "n", "esc":
				m.IntelDeleteSourceConfirm = false
				return m, nil
			default:
				return m, nil
			}
		}

		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenDashboard
			return m, nil

		case keyMsg.String() == "tab":
			m.IntelActiveTab = (m.IntelActiveTab + 1) % 3
			if m.IntelActiveTab == 2 {
				m.IntelSearchInput.Focus()
				return m, textinput.Blink
			}
			return m, nil

		case keyMsg.String() == "1":
			m.IntelActiveTab = 0
			return m, nil

		case keyMsg.String() == "2":
			m.IntelActiveTab = 1
			return m, nil

		case keyMsg.String() == "3":
			m.IntelActiveTab = 2
			m.IntelSearchInput.Focus()
			return m, textinput.Blink

		case keyMsg.String() == "up", keyMsg.String() == "k":
			if m.IntelActiveTab == 1 && m.IntelSelectedSrc > 0 {
				m.IntelSelectedSrc--
			}
			return m, nil

		case keyMsg.String() == "down", keyMsg.String() == "j":
			if m.IntelActiveTab == 1 && m.IntelSelectedSrc < len(m.IntelSources)-1 {
				m.IntelSelectedSrc++
			}
			return m, nil

		case keyMsg.String() == "a", keyMsg.String() == "A":
			if m.IntelActiveTab == 1 {
				m.CurrentScreen = ScreenIntelSourceAdd
				m.IntelAddFocus = 0
				m.IntelAddIDInput.Reset()
				m.IntelAddIDInput.Focus()
				m.IntelAddNameInput.Reset()
				m.IntelAddEndpointInput.Reset()
				m.IntelAddEnvInput.Reset()
				m.IntelAddErr = nil
				return m, textinput.Blink
			}
			return m, nil

		case keyMsg.String() == "t", keyMsg.String() == "T":
			if m.IntelActiveTab == 1 && len(m.IntelSources) > 0 && m.IntelSelectedSrc < len(m.IntelSources) {
				src := m.IntelSources[m.IntelSelectedSrc]
				if m.Storage != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Storage.SetSourceEnabled(ctx, src.ID, !src.Enabled)
					m.reloadIntelStats()
				}
			}
			return m, nil

		case keyMsg.String() == "d", keyMsg.String() == "D":
			if m.IntelActiveTab == 1 && len(m.IntelSources) > 0 && m.IntelSelectedSrc < len(m.IntelSources) {
				src := m.IntelSources[m.IntelSelectedSrc]
				m.IntelDeleteSourceConfirm = true
				m.IntelDeleteSourceID = src.ID
			}
			return m, nil

		case keyMsg.String() == "p", keyMsg.String() == "P":
			if m.IntelActiveTab == 0 {
				m.IntelPruneConfirm = true
			}
			return m, nil

		case keyMsg.String() == "m", keyMsg.String() == "M":
			if m.IntelActiveTab == 0 {
				m.CurrentScreen = ScreenIntelImportExport
				m.IntelBundleMode = "import"
				m.IntelBundleSuccess = false
				m.IntelBundleMsg = ""
				m.IntelBundleErr = nil
				m.IntelBundlePathInput.Reset()
				m.IntelBundlePathInput.Focus()
				return m, textinput.Blink
			}
			return m, nil

		case keyMsg.String() == "x", keyMsg.String() == "X":
			if m.IntelActiveTab == 0 {
				m.CurrentScreen = ScreenIntelImportExport
				m.IntelBundleMode = "export"
				m.IntelBundleSuccess = false
				m.IntelBundleMsg = ""
				m.IntelBundleErr = nil
				m.IntelBundlePathInput.SetValue("bouclier-intel-bundle.json")
				m.IntelBundlePathInput.Focus()
				return m, textinput.Blink
			}
			return m, nil

		case keyMsg.String() == "u" || keyMsg.String() == "U":
			if !m.IntelUpdating {
				m.IntelUpdating = true
				m.IntelErr = nil
				m.IntelSyncID++
				syncID := m.IntelSyncID
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				m.IntelCancel = cancel
				m.IntelUpdateMsg = "Synchronizing threat intelligence feeds..."
				return m, updateIntelFeedsCmd(ctx, m.Config, syncID)
			}
			return m, nil

		case keyMsg.String() == "c" || keyMsg.String() == "C":
			if m.IntelUpdating {
				if m.IntelCancel != nil {
					m.IntelCancel()
					m.IntelCancel = nil
				}
				m.IntelUpdating = false
				m.IntelSyncID++
				m.IntelErr = nil
				m.IntelUpdateMsg = "Feed synchronization cancelled."
				return m, nil
			}

		case key.Matches(keyMsg, m.Keys.Confirm):
			if m.IntelActiveTab == 2 {
				query := strings.TrimSpace(m.IntelSearchInput.Value())
				return m, searchIntelCmd(m.Storage, query)
			}
		}

		if m.IntelActiveTab == 2 {
			var cmd tea.Cmd
			m.IntelSearchInput, cmd = m.IntelSearchInput.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m Model) updateIntelSourceAdd(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			m.CurrentScreen = ScreenIntel
			return m, nil

		case "tab":
			m.IntelAddFocus = (m.IntelAddFocus + 1) % 6
			m.updateIntelAddInputFocus()
			return m, textinput.Blink

		case "shift+tab":
			m.IntelAddFocus = (m.IntelAddFocus + 5) % 6
			m.updateIntelAddInputFocus()
			return m, textinput.Blink

		case " ":
			if m.IntelAddFocus == 2 {
				if m.IntelAddType == "https_feed" {
					m.IntelAddType = "local_file"
				} else {
					m.IntelAddType = "https_feed"
				}
				return m, nil
			}

		case "enter":
			m.IntelAddErr = nil
			id := strings.TrimSpace(m.IntelAddIDInput.Value())
			name := strings.TrimSpace(m.IntelAddNameInput.Value())
			endpoint := strings.TrimSpace(m.IntelAddEndpointInput.Value())
			envVar := strings.TrimSpace(m.IntelAddEnvInput.Value())

			if id == "" {
				m.IntelAddErr = errors.New("source ID cannot be empty")
				return m, nil
			}
			if name == "" {
				m.IntelAddErr = errors.New("source display name cannot be empty")
				return m, nil
			}
			if endpoint == "" {
				m.IntelAddErr = errors.New("endpoint cannot be empty")
				return m, nil
			}

			// Security constraint: only environment variable name is accepted, never secret values!
			if strings.Contains(envVar, " ") || strings.Contains(envVar, "=") {
				m.IntelAddErr = errors.New("auth header env must be a valid environment variable name (e.g. BOUCLIER_FEED_TOKEN), not a secret value")
				return m, nil
			}

			src := storage.IntelSource{
				ID:            id,
				Name:          name,
				ProviderType:  m.IntelAddType,
				Endpoint:      endpoint,
				AuthHeaderEnv: envVar,
				Enabled:       true,
			}

			if m.Storage != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := m.Storage.RegisterSource(ctx, src); err != nil {
					m.IntelAddErr = fmt.Errorf("register source: %w", err)
					return m, nil
				}
			}

			m.IntelUpdateMsg = fmt.Sprintf("Source %q registered successfully.", id)
			m.CurrentScreen = ScreenIntel
			m.reloadIntelStats()
			return m, nil
		}
	}

	var cmd tea.Cmd
	switch m.IntelAddFocus {
	case 0:
		m.IntelAddIDInput, cmd = m.IntelAddIDInput.Update(msg)
	case 1:
		m.IntelAddNameInput, cmd = m.IntelAddNameInput.Update(msg)
	case 3:
		m.IntelAddEndpointInput, cmd = m.IntelAddEndpointInput.Update(msg)
	case 4:
		m.IntelAddEnvInput, cmd = m.IntelAddEnvInput.Update(msg)
	}
	return m, cmd
}

func (m *Model) updateIntelAddInputFocus() {
	m.IntelAddIDInput.Blur()
	m.IntelAddNameInput.Blur()
	m.IntelAddEndpointInput.Blur()
	m.IntelAddEnvInput.Blur()
	switch m.IntelAddFocus {
	case 0:
		m.IntelAddIDInput.Focus()
	case 1:
		m.IntelAddNameInput.Focus()
	case 3:
		m.IntelAddEndpointInput.Focus()
	case 4:
		m.IntelAddEnvInput.Focus()
	}
}

func (m Model) updateIntelImportExport(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			m.CurrentScreen = ScreenIntel
			return m, nil

		case " ":
			if m.IntelBundleMode == "export" {
				m.IntelBundleMode = "import"
			} else {
				m.IntelBundleMode = "export"
			}
			return m, nil

		case "enter":
			path := strings.TrimSpace(m.IntelBundlePathInput.Value())
			if path == "" {
				path = "bouclier-intel-bundle.json"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			if m.IntelBundleMode == "export" {
				opts := cli.IntelExportOptions{
					OutputPath: path,
				}
				err := cli.RunIntelExport(ctx, m.Config, opts, nil)
				if err != nil {
					m.IntelBundleSuccess = false
					m.IntelBundleErr = err
				} else {
					m.IntelBundleSuccess = true
					m.IntelBundleMsg = fmt.Sprintf("Exported bundle to %s", path)
					m.IntelBundleErr = nil
				}
			} else {
				opts := cli.IntelImportOptions{
					FilePath: path,
					Format:   "bundle",
				}
				err := cli.RunIntelImport(ctx, m.Config, opts, nil)
				if err != nil {
					m.IntelBundleSuccess = false
					m.IntelBundleErr = err
				} else {
					m.IntelBundleSuccess = true
					m.IntelBundleMsg = fmt.Sprintf("Imported bundle from %s", path)
					m.IntelBundleErr = nil
					m.reloadIntelStats()
				}
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.IntelBundlePathInput, cmd = m.IntelBundlePathInput.Update(msg)
	return m, cmd
}

func (m Model) updateConfig(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc", "b":
			m.CurrentScreen = ScreenDashboard
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateServices(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc", "b":
			m.CurrentScreen = ScreenDashboard
			return m, nil
		case "s", "S":
			m.startAPIServer()
			return m, nil
		case "x", "X":
			m.stopAPIServer()
			return m, nil
		}
	}
	return m, nil
}

func (m *Model) startAPIServer() {
	if m.APIServerRunning {
		return
	}
	port := m.APIServerPort
	if port <= 0 {
		port = 8081
	}
	if m.Config != nil && m.Config.HTTPServer.Port > 0 {
		port = m.Config.HTTPServer.Port
	}
	m.APIServerPort = port

	serverCfg := config.HTTPServerConfig{
		Host:              "127.0.0.1",
		Port:              port,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxScanDuration:   20 * time.Second,
	}

	srv, err := api.NewServer(serverCfg, slog.Default())
	if err != nil {
		m.APIServerErr = fmt.Errorf("create server: %w", err)
		return
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		m.APIServerErr = fmt.Errorf("bind 127.0.0.1:%d: %w", port, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.APIServerCancel = cancel
	m.APIServerRunning = true
	m.APIServerStarted = time.Now()
	m.APIServerErr = nil

	go func() {
		defer listener.Close()
		go func() {
			<-ctx.Done()
			shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer sCancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
		_ = srv.Serve(listener)
	}()
}

func (m *Model) stopAPIServer() {
	if !m.APIServerRunning {
		return
	}
	if m.APIServerCancel != nil {
		m.APIServerCancel()
		m.APIServerCancel = nil
	}
	m.APIServerRunning = false
	m.APIServerErr = nil
}

func (m Model) updateAbout(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc", "b":
			m.CurrentScreen = ScreenDashboard
			return m, nil
		case "1":
			m.AboutActiveTab = 0
			return m, nil
		case "2":
			m.AboutActiveTab = 1
			return m, nil
		case "3":
			m.AboutActiveTab = 2
			return m, nil
		case "4":
			m.AboutActiveTab = 3
			return m, nil
		case "left", "h":
			if m.AboutActiveTab > 0 {
				m.AboutActiveTab--
			}
			return m, nil
		case "right", "l":
			if m.AboutActiveTab < 3 {
				m.AboutActiveTab++
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateCommandPalette(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "esc":
			m.CurrentScreen = m.PalettePreviousScreen
			return m, nil
		case "up", "k":
			if m.PaletteSelectedIdx > 0 {
				m.PaletteSelectedIdx--
			}
			return m, nil
		case "down", "j":
			if m.PaletteSelectedIdx < len(m.PaletteFiltered)-1 {
				m.PaletteSelectedIdx++
			}
			return m, nil
		case "enter":
			if len(m.PaletteFiltered) > 0 && m.PaletteSelectedIdx < len(m.PaletteFiltered) {
				item := m.PaletteFiltered[m.PaletteSelectedIdx]
				return m.executePaletteItem(item)
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	prevVal := m.PaletteInput.Value()
	m.PaletteInput, cmd = m.PaletteInput.Update(msg)
	newVal := m.PaletteInput.Value()
	if prevVal != newVal {
		m.filterPaletteItems(newVal)
	}
	return m, cmd
}

func (m *Model) openCommandPalette() {
	m.PalettePreviousScreen = m.CurrentScreen
	m.CurrentScreen = ScreenCommandPalette
	m.PaletteInput.Reset()
	m.PaletteInput.Focus()
	m.PaletteFiltered = m.PaletteItems
	m.PaletteSelectedIdx = 0
}

func (m *Model) filterPaletteItems(query string) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		m.PaletteFiltered = m.PaletteItems
		m.PaletteSelectedIdx = 0
		return
	}
	var filtered []PaletteItem
	for _, it := range m.PaletteItems {
		if strings.Contains(strings.ToLower(it.Title), q) ||
			strings.Contains(strings.ToLower(it.Description), q) ||
			strings.Contains(strings.ToLower(it.Category), q) {
			filtered = append(filtered, it)
		}
	}
	m.PaletteFiltered = filtered
	if m.PaletteSelectedIdx >= len(filtered) {
		m.PaletteSelectedIdx = 0
	}
}

func (m Model) executePaletteItem(item PaletteItem) (tea.Model, tea.Cmd) {
	m.CurrentScreen = m.PalettePreviousScreen
	switch item.Action {
	case ActionNavigate:
		m.CurrentScreen = item.TargetScreen
		switch item.TargetScreen {
		case ScreenURLInput:
			m.URLValidationErr = ""
			m.URLInput.Reset()
			m.URLInput.Focus()
			m.ScanInputFocus = 0
			return m, textinput.Blink
		case ScreenHistory:
			m.HistoryDeleteConfirm = false
			m.HistoryStatusMsg = ""
			m.HistoryPage = 0
			m.HistorySelectedIdx = 0
			m.HistoryFiltering = false
			m.loadHistory()
			return m, nil
		case ScreenIntel:
			m.reloadIntelStats()
			return m, nil
		case ScreenExport:
			m.ExportSuccess = false
			m.ExportMessage = ""
			m.ExportErr = nil
			m.ExportPathInput.SetValue("bouclier-report.json")
			m.ExportPathInput.Focus()
			return m, textinput.Blink
		}
		return m, nil

	case ActionSyncIntel:
		m.CurrentScreen = ScreenIntel
		if !m.IntelUpdating {
			m.IntelUpdating = true
			m.IntelErr = nil
			m.IntelSyncID++
			syncID := m.IntelSyncID
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			m.IntelCancel = cancel
			m.IntelUpdateMsg = "Synchronizing threat intelligence feeds..."
			return m, updateIntelFeedsCmd(ctx, m.Config, syncID)
		}
		return m, nil

	case ActionToggleAPIServer:
		m.CurrentScreen = ScreenServices
		if m.APIServerRunning {
			m.stopAPIServer()
		} else {
			m.startAPIServer()
		}
		return m, nil

	case ActionToggleNoColor:
		m.Styles = NewStyles(!m.Styles.NoColor)
		return m, nil

	case ActionPruneIntel:
		m.CurrentScreen = ScreenIntel
		m.IntelPruneConfirm = true
		return m, nil

	case ActionNewScan:
		m.URLValidationErr = ""
		m.URLInput.Reset()
		m.URLInput.Focus()
		m.ScanInputFocus = 0
		m.CurrentScreen = ScreenURLInput
		return m, textinput.Blink

	case ActionQuit:
		if m.ScanCancel != nil {
			m.ScanCancel()
		}
		m.stopAPIServer()
		m.cancelAIExplanation()
		m.Quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) isTextInputActive() bool {
	if m.CurrentScreen == ScreenCommandPalette {
		return true
	}
	if m.CurrentScreen == ScreenURLInput && m.ScanInputFocus == 0 {
		return true
	}
	if m.CurrentScreen == ScreenExport {
		return true
	}
	if m.CurrentScreen == ScreenHistory && m.HistoryFiltering {
		return true
	}
	if m.CurrentScreen == ScreenIntel && m.IntelActiveTab == 2 {
		return true
	}
	if m.CurrentScreen == ScreenIntelSourceAdd && m.IntelAddFocus != 2 && m.IntelAddFocus != 5 {
		return true
	}
	if m.CurrentScreen == ScreenIntelImportExport {
		return true
	}
	return false
}

func searchIntelCmd(repo storage.Repository, query string) tea.Cmd {
	return func() tea.Msg {
		if repo == nil {
			return IntelSearchCompletedMsg{Query: query, Err: fmt.Errorf("storage repository not connected")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		results, total, err := repo.SearchIndicators(ctx, query, 50, 0)
		return IntelSearchCompletedMsg{
			Query:   query,
			Results: results,
			Total:   total,
			Err:     err,
		}
	}
}

func updateIntelFeedsCmd(ctx context.Context, cfg *config.Config, syncID int) tea.Cmd {
	return func() tea.Msg {
		if cfg == nil {
			cfg = config.Default()
		}
		var buf strings.Builder
		err := cli.RunIntelUpdate(ctx, cfg, cli.IntelUpdateOptions{}, &buf)
		msg := "Synchronization complete."
		if err != nil {
			if errors.Is(err, context.Canceled) {
				msg = "Synchronization cancelled."
			} else {
				msg = "Synchronization completed with errors."
			}
		}
		return IntelUpdateCompletedMsg{
			SyncID:  syncID,
			Message: msg,
			Err:     err,
		}
	}
}
