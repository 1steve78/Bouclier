package tui

import (
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
	tea "github.com/charmbracelet/bubbletea"
)

// ScanStartedMsg indicates a scan has officially initiated.
type ScanStartedMsg struct {
	ScanID uint64
	Target string
}

// ScanProgressMsg reports progress updates from the background scan pipeline.
type ScanProgressMsg struct {
	ScanID  uint64
	Stage   cli.ScanStage
	State   cli.StageState
	Message string
}

// ScanCompletedMsg delivers the final assessment or error from the background scan pipeline.
type ScanCompletedMsg struct {
	ScanID        uint64
	Assessment    *risk.RiskAssessment
	ScanRecord    *storage.ScanRecord
	IsSSRFBlocked bool
	Err           error
}

type AIExplanationCompletedMsg struct {
	RequestID uint64
	Text      string
	Model     string
	Err       error
}

type AIModelsLoadedMsg struct {
	RequestID uint64
	Models    []string
	Err       error
}

// TickMsg updates elapsed scan duration.
type TickMsg time.Time

// TickCmd produces a tick every 100ms during an active scan.
func TickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// ExportCompletedMsg reports the outcome of exporting a report to disk.
type ExportCompletedMsg struct {
	Path string
	Err  error
}

// IntelStatsLoadedMsg delivers intelligence metrics and configured sources.
type IntelStatsLoadedMsg struct {
	Stats   *storage.IntelStats
	Sources []storage.IntelSource
	Err     error
}

// IntelSearchCompletedMsg delivers local indicator search results.
type IntelSearchCompletedMsg struct {
	Query   string
	Results []storage.IntelIndicator
	Total   int
	Err     error
}

// IntelUpdateCompletedMsg reports the outcome of a feed sync operation.
type IntelUpdateCompletedMsg struct {
	SyncID  int
	Message string
	Err     error
}
