package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/heuristics"
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

	case tea.KeyMsg:
		// Force quit from anywhere
		if key.Matches(msg, m.Keys.ForceQuit) {
			if m.ScanCancel != nil {
				m.ScanCancel()
			}
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
			m.Quitting = true
			return m, tea.Quit
		}
	}

	// Delegate to screen-specific updates
	switch m.CurrentScreen {
	case ScreenDashboard:
		return m.updateDashboard(msg)
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

		case keyMsg.String() == "r":
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
			m.CurrentScreen = ScreenDashboard
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
				StartScanCmd(m.ScanID, ctx, m.Config, m.ScanTarget, m.ScanChan),
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
			}
			m.ScanErr = errors.New("scan cancelled by user")
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
					StartScanCmd(m.ScanID, ctx, m.Config, m.ScanTarget, m.ScanChan),
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

		case key.Matches(keyMsg, m.Keys.Export):
			m.CurrentScreen = ScreenExport
			m.ExportFormat = "json"
			m.ExportSuccess = false
			m.ExportErr = nil
			m.ExportPathInput.SetValue("bouclier-report.json")
			m.ExportPathInput.Focus()
			return m, textinput.Blink

		case key.Matches(keyMsg, m.Keys.NewScan):
			m.URLValidationErr = ""
			m.URLInput.Reset()
			m.URLInput.Focus()
			m.CurrentScreen = ScreenURLInput
			return m, textinput.Blink

		case key.Matches(keyMsg, m.Keys.Back):
			m.CurrentScreen = ScreenDashboard
			return m, nil
		}
	}
	return m, nil
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
			m.CurrentScreen = ScreenOverview
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
