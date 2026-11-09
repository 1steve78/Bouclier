package tui

import (
	"strings"

	"bouclier/internal/risk"
)

// View renders the currently active screen of the workstation.
func (m Model) View() string {
	if m.Quitting {
		return m.Styles.Muted.Render("Bouclier Workstation closed.\n")
	}

	// Terminal size advisory if terminal is too small for workstation
	if m.Width > 0 && m.Height > 0 && (m.Width < 60 || m.Height < 16) {
		return "\n" + m.Styles.ErrorText.Render("⚠ Terminal window too small") + "\n" +
			m.Styles.Muted.Render("Please expand your terminal to at least 80 columns by 24 rows for the full workstation experience.\n")
	}

	var content string

	switch m.CurrentScreen {
	case ScreenDashboard:
		content = RenderDashboard(
			m.Styles,
			m.Width,
			m.Assessment,
			m.RecentScans,
			m.IntelStats,
			m.IntelSources,
			m.dbPathDisplay(),
			m.APIServerRunning,
			m.APIServerPort,
			m.DashboardSelectedIdx,
			m.StorageErr,
		)

	case ScreenHistory:
		content = RenderHistory(
			m.Styles,
			m.HistoryRecords,
			m.HistorySelectedIdx,
			m.HistoryTotal,
			m.HistoryPage,
			m.HistoryPageSize,
			m.HistoryDeleteConfirm,
			m.HistoryDeleteID,
			m.HistoryStatusMsg,
			m.HistoryFilterInput,
			m.HistoryFiltering,
			m.HistoryFilterText,
			m.Width,
		)

	case ScreenHistoryCorrelate:
		content = RenderHistoryCorrelate(
			m.Styles,
			m.HistoryCorrelateTarget,
			m.HistoryCorrelateReport,
			m.HistoryCorrelateErr,
			m.Width,
		)

	case ScreenURLInput:
		content = RenderURLInput(
			m.Styles,
			m.URLInput,
			m.URLValidationErr,
			m.ScanNoCT,
			m.ScanCTScope,
			m.ScanTimeoutSec,
			m.ScanInputFocus,
			m.Width,
		)

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
		content = RenderOverview(m.Styles, m.Assessment, m.Width, AIExplanationState{
			Enabled: m.Config != nil && m.Config.AI.Enabled,
			Loading: m.AIExplaining,
			Text:    m.AIExplanationText,
			Model:   m.AIExplanationModel,
			Err:     m.AIExplanationErr,
		})

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

	case ScreenIntel:
		content = RenderIntel(m)

	case ScreenIntelSourceAdd:
		content = RenderIntelSourceAdd(
			m.Styles,
			m.IntelAddIDInput,
			m.IntelAddNameInput,
			m.IntelAddType,
			m.IntelAddEndpointInput,
			m.IntelAddEnvInput,
			m.IntelAddFocus,
			m.IntelAddErr,
			m.Width,
		)

	case ScreenIntelImportExport:
		content = RenderIntelImportExport(
			m.Styles,
			m.IntelBundleMode,
			m.IntelBundlePathInput,
			m.IntelBundleSuccess,
			m.IntelBundleMsg,
			m.IntelBundleErr,
			m.Width,
		)

	case ScreenConfig:
		content = RenderConfig(m.Styles, m.Config, m.Width)

	case ScreenServices:
		content = RenderServices(
			m.Styles,
			m.APIServerRunning,
			m.APIServerPort,
			m.APIServerStarted,
			m.APIServerErr,
			m.Width,
		)

	case ScreenAbout:
		content = RenderAbout(m.Styles, m.AboutActiveTab, m.AboutScrollOffset, m.Width)

	case ScreenAIModelSelect:
		content = RenderAIModelSelect(m)

	case ScreenCommandPalette:
		content = RenderPalette(
			m.Styles,
			m.PaletteInput.View(),
			m.PaletteFiltered,
			m.PaletteSelectedIdx,
			m.Width,
		)

	default:
		content = RenderDashboard(
			m.Styles,
			m.Width,
			m.Assessment,
			m.RecentScans,
			m.IntelStats,
			m.IntelSources,
			m.dbPathDisplay(),
			m.APIServerRunning,
			m.APIServerPort,
			m.DashboardSelectedIdx,
			m.StorageErr,
		)
	}

	// Ensure padding and consistent newline
	return "\n " + strings.ReplaceAll(content, "\n", "\n ") + "\n"
}

func (m Model) dbPathDisplay() string {
	if m.Config != nil && m.Config.Storage.DatabasePath != "" {
		return m.Config.Storage.DatabasePath
	}
	return "bouclier.db"
}
