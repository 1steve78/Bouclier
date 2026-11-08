package tui

import (
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/risk"
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
	IsSSRFBlocked bool
	Err           error
}

// TickMsg updates elapsed scan duration.
type TickMsg time.Time

// ExportCompletedMsg reports the outcome of exporting a report to disk.
type ExportCompletedMsg struct {
	Path string
	Err  error
}
