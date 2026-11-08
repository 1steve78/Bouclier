package tui

import (
	"context"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/risk"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// Screen represents the active visible view of the application.
type Screen int

const (
	ScreenDashboard Screen = iota
	ScreenURLInput
	ScreenScanning
	ScreenOverview
	ScreenFindings
	ScreenFindingDetail
	ScreenCoverage
	ScreenExport
	ScreenHelp
)

// Model is the main Bubble Tea application state model.
type Model struct {
	Config         *config.Config
	Styles         Styles
	Keys           KeyMap
	CurrentScreen  Screen
	PreviousScreen Screen
	Width          int
	Height         int

	// URL Input
	URLInput         textinput.Model
	URLValidationErr string

	// Active Scan State
	ScanID        uint64
	ScanTarget    string
	ScanStartTime time.Time
	ScanElapsed   time.Duration
	ScanCancel    context.CancelFunc
	ScanChan      chan tea.Msg
	Stages        map[cli.ScanStage]cli.StageState
	StageOrder    []cli.ScanStage
	StageMessages map[cli.ScanStage]string
	ScanErr       error
	IsSSRFBlocked bool

	// Completed Assessment & Exploration
	Assessment         *risk.RiskAssessment
	ActiveFilter       SeverityFilter
	FilteredFindings   []risk.NormalizedFinding
	SelectedFindingIdx int

	// Export Screen
	ExportFormat    string // "json" or "markdown"
	ExportPathInput textinput.Model
	ExportSuccess   bool
	ExportMessage   string
	ExportErr       error

	// Lifecycle
	Quitting bool
}

// NewModel constructs a fresh Bubble Tea model initialized with defaults.
func NewModel(cfg *config.Config, noColor bool) Model {
	if cfg == nil {
		cfg = config.Default()
	}

	ti := textinput.New()
	ti.Placeholder = "https://example.com"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 60

	ei := textinput.New()
	ei.Placeholder = "bouclier-report.json"
	ei.CharLimit = 256
	ei.Width = 60

	stageOrder := []cli.ScanStage{
		cli.StageURLAnalysis,
		cli.StageDomainIntelligence,
		cli.StageTLSAndCertificates,
		cli.StageCertificateTransparency,
		cli.StageHTTPSecurity,
		cli.StageRiskAggregation,
	}

	stages := make(map[cli.ScanStage]cli.StageState, len(stageOrder))
	for _, s := range stageOrder {
		stages[s] = cli.StageStatePending
	}

	return Model{
		Config:        cfg,
		Styles:        NewStyles(noColor),
		Keys:          DefaultKeyMap(),
		CurrentScreen: ScreenDashboard,
		Width:         80,
		Height:        24,

		URLInput:        ti,
		ExportPathInput: ei,
		ExportFormat:    "json",

		StageOrder:    stageOrder,
		Stages:        stages,
		StageMessages: make(map[cli.ScanStage]string),
		ActiveFilter:  FilterAll,
	}
}

// Init initializes the Bubble Tea model.
func (m Model) Init() tea.Cmd {
	return textinput.Blink
}
