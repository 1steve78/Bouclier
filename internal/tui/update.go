package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
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
			m.cancelAIExplanation()
			m.Quitting = true
			return m, tea.Quit
		}

		// Help toggle
		if key.Matches(msg, m.Keys.Help) && m.CurrentScreen != ScreenURLInput && m.CurrentScreen != ScreenExport {
			if m.CurrentScreen == ScreenHelp {
				m.CurrentScreen = m.PreviousScreen
			} else {
				m.PreviousScreen = m.CurrentScreen
				m.CurrentScreen = ScreenHelp
			}
			return m, nil
		}

		// Quit shortcut from non-input screens
		if key.Matches(msg, m.Keys.Quit) && m.CurrentScreen != ScreenURLInput && m.CurrentScreen != ScreenExport {
			if m.ScanCancel != nil {
				m.ScanCancel()
			}
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
	case ScreenAIModelSelect:
		return m.updateAIModelSelect(msg)
	default:
		return m, nil
	}
}

func (m Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Confirm), key.Matches(keyMsg, m.Keys.NewScan):
			m.URLValidationErr = ""
			m.URLInput.Reset()
			m.URLInput.Focus()
			m.CurrentScreen = ScreenURLInput
			return m, textinput.Blink

		case key.Matches(keyMsg, m.Keys.History), keyMsg.String() == "h", keyMsg.String() == "H":
			m.PreviousScreen = ScreenDashboard
			m.CurrentScreen = ScreenHistory
			m.HistoryDeleteConfirm = false
			m.HistoryStatusMsg = ""
			m.HistoryPage = 0
			m.HistorySelectedIdx = 0
			m.loadHistory()
			return m, nil

		case key.Matches(keyMsg, m.Keys.Intel), keyMsg.String() == "i", keyMsg.String() == "I":
			m.PreviousScreen = ScreenDashboard
			m.CurrentScreen = ScreenIntel
			m.reloadIntelStats()
			return m, nil

		case keyMsg.String() == "r", keyMsg.String() == "R":
			if m.Assessment != nil {
				m.CurrentScreen = ScreenOverview
			}
			return m, nil
		}
	}
	return m, nil
}

func (m Model) updateURLInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			if m.PreviousScreen == ScreenHistory {
				m.CurrentScreen = ScreenHistory
			} else {
				m.CurrentScreen = ScreenDashboard
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Confirm):
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
				StartScanCmd(m.ScanID, ctx, m.Config, m.Storage, m.ScanTarget, m.ScanChan),
				TickCmd(),
			)
		}
	}

	var cmd tea.Cmd
	m.URLInput, cmd = m.URLInput.Update(msg)
	return m, cmd
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
					StartScanCmd(m.ScanID, ctx, m.Config, m.Storage, m.ScanTarget, m.ScanChan),
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
				// Ignore other keys during confirmation prompt
				return m, nil
			}
		}

		switch {
		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenDashboard
			return m, nil

		case key.Matches(keyMsg, m.Keys.NewScan), keyMsg.String() == "s", keyMsg.String() == "S":
			m.URLValidationErr = ""
			m.URLInput.Reset()
			m.URLInput.Focus()
			m.CurrentScreen = ScreenURLInput
			return m, textinput.Blink

		case key.Matches(keyMsg, m.Keys.Up):
			if m.HistorySelectedIdx > 0 {
				m.HistorySelectedIdx--
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Down):
			if m.HistorySelectedIdx < len(m.HistoryRecords)-1 {
				m.HistorySelectedIdx++
			}
			return m, nil

		case keyMsg.String() == "[", keyMsg.String() == "p", keyMsg.String() == "P":
			if m.HistoryPage > 0 {
				m.HistoryPage--
				m.HistorySelectedIdx = 0
				m.loadHistory()
			}
			return m, nil

		case keyMsg.String() == "]", keyMsg.String() == "n", keyMsg.String() == "N":
			totalPages := ((m.HistoryTotal - 1) / m.HistoryPageSize) + 1
			if m.HistoryPage < totalPages-1 {
				m.HistoryPage++
				m.HistorySelectedIdx = 0
				m.loadHistory()
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Confirm):
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

		case key.Matches(keyMsg, m.Keys.Export), keyMsg.String() == "e", keyMsg.String() == "E":
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
						m.ExportPathInput.SetValue("bouclier-report.json")
						m.ExportPathInput.Focus()
						return m, textinput.Blink
					}
					m.HistoryStatusMsg = fmt.Sprintf("Failed to load scan report: %v", err)
				}
			}
			return m, nil

		case key.Matches(keyMsg, m.Keys.Delete), keyMsg.String() == "d", keyMsg.String() == "x":
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
		Limit:  m.HistoryPageSize,
		Offset: m.HistoryPage * m.HistoryPageSize,
	}
	records, err := m.Storage.ListScans(ctx, filter)
	if err != nil {
		m.HistoryStatusMsg = fmt.Sprintf("Error listing scans: %v", err)
		return
	}
	total, err := m.Storage.CountScans(ctx, storage.ListFilter{})
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
