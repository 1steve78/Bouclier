package tui

import (
	"strings"

	"bouclier/internal/risk"
)

// View renders the currently active screen.
func (m Model) View() string {
	if m.Quitting {
		return m.Styles.Muted.Render("Bouclier closed.\n")
	}

	var content string

	switch m.CurrentScreen {
	case ScreenDashboard:
		content = RenderDashboard(m.Styles, m.Width, m.Assessment)

	case ScreenURLInput:
		content = RenderURLInput(m.Styles, m.URLInput, m.URLValidationErr, m.Width)

	case ScreenScanning:
		content = RenderProgress(
			m.Styles,
			m.ScanTarget,
			m.ScanElapsed,
			m.Stages,
			m.StageOrder,
			m.StageMessages,
			m.ScanErr,
			m.Width,
		)

	case ScreenOverview:
		content = RenderOverview(m.Styles, m.Assessment, m.Width)

	case ScreenFindings:
		maxVisible := m.Height - 14
		if maxVisible < 5 {
			maxVisible = 5
		}
		var allFindings []risk.NormalizedFinding
		if m.Assessment != nil {
			allFindings = m.Assessment.Findings
		}
		content = RenderFindings(
			m.Styles,
			allFindings,
			m.FilteredFindings,
			m.SelectedFindingIdx,
			m.ActiveFilter,
			m.Width,
			maxVisible,
		)

	case ScreenFindingDetail:
		if len(m.FilteredFindings) > 0 && m.SelectedFindingIdx < len(m.FilteredFindings) {
			content = RenderFindingDetail(
				m.Styles,
				m.FilteredFindings[m.SelectedFindingIdx],
				m.SelectedFindingIdx,
				len(m.FilteredFindings),
				m.Width,
			)
		} else {
			content = m.Styles.Muted.Render("No finding selected. Press Esc to return to findings list.")
		}

	case ScreenCoverage:
		if m.Assessment != nil {
			content = RenderCoverage(m.Styles, m.Assessment, m.Width)
		} else {
			content = m.Styles.Muted.Render("No active assessment to display coverage for.")
		}

	case ScreenExport:
		content = RenderExport(
			m.Styles,
			m.ExportFormat,
			m.ExportPathInput,
			m.ExportSuccess,
			m.ExportMessage,
			m.ExportErr,
			m.Width,
		)

	case ScreenHelp:
		content = RenderHelp(m.Styles, m.Width)

	default:
		content = RenderDashboard(m.Styles, m.Width, m.Assessment)
	}

	// Ensure padding and consistent newline
	return "\n " + strings.ReplaceAll(content, "\n", "\n ") + "\n"
}
