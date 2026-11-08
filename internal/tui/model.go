package tui

import (
	"context"
	"os"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
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
	ScreenHistory
	ScreenIntel
	ScreenAIModelSelect
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
	AIExplanationText  string
	AIExplanationModel string
	AIExplanationErr   error
	AIExplaining       bool
	AIExplainRequestID uint64
	AIExplainCancel    context.CancelFunc
	AIModels           []string
	AIModelSelectedIdx int
	AIModelLoading     bool
	AIModelListErr     error
	AIModelListRequest uint64

	// Export Screen
	ExportFormat    string // "json" or "markdown"
	ExportPathInput textinput.Model
	ExportSuccess   bool
	ExportMessage   string
	ExportErr       error

	// Storage & Scan History
	Storage              storage.Repository
	StorageErr           error
	RecentScans          []storage.ScanRecord
	HistoryRecords       []storage.ScanRecord
	HistorySelectedIdx   int
	HistoryTotal         int
	HistoryPage          int
	HistoryPageSize      int
	HistoryDeleteConfirm bool
	HistoryDeleteID      string
	HistoryStatusMsg     string

	// Threat Intelligence State
	IntelStats         *storage.IntelStats
	IntelSources       []storage.IntelSource
	IntelSelectedSrc   int
	IntelSearchInput   textinput.Model
	IntelSearchResults []storage.IntelIndicator
	IntelSelectedInd   int
	IntelUpdating      bool
	IntelUpdateMsg     string
	IntelErr           error
	IntelActiveTab     int // 0: Overview, 1: Sources, 2: Search
	IntelSyncID        int
	IntelCancel        context.CancelFunc

	// Lifecycle
	Quitting bool
}

// NewModel constructs a fresh Bubble Tea model initialized with defaults.
func NewModel(cfg *config.Config, noColor bool) Model {
	return NewModelWithStorage(cfg, noColor, nil)
}

// NewModelWithStorage constructs a Bubble Tea model with an attached SQLite storage repository.
func NewModelWithStorage(cfg *config.Config, noColor bool, repo storage.Repository) Model {
	if cfg == nil {
		cfg = config.Default()
	}
	if !noColor && os.Getenv("NO_COLOR") != "" {
		noColor = true
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

	isi := textinput.New()
	isi.Placeholder = "Search domain, URL, IP, or category..."
	isi.CharLimit = 128
	isi.Width = 50

	stageOrder := []cli.ScanStage{
		cli.StageURLAnalysis,
		cli.StageDomainIntelligence,
		cli.StageTLSAndCertificates,
		cli.StageCertificateTransparency,
		cli.StageHTTPSecurity,
		cli.StageThreatIntelligence,
		cli.StageRiskAggregation,
	}

	stages := make(map[cli.ScanStage]cli.StageState, len(stageOrder))
	for _, s := range stageOrder {
		stages[s] = cli.StageStatePending
	}

	var recentScans []storage.ScanRecord
	var intelStats *storage.IntelStats
	var intelSources []storage.IntelSource
	if repo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if list, err := repo.ListScans(ctx, storage.ListFilter{Limit: 5}); err == nil {
			recentScans = list
		}
		if stats, err := repo.GetIntelStats(ctx); err == nil {
			intelStats = stats
		}
		if srcs, err := repo.ListSources(ctx); err == nil {
			intelSources = srcs
		}
	}

	return Model{
		Config:        cfg,
		Styles:        NewStyles(noColor),
		Keys:          DefaultKeyMap(),
		CurrentScreen: ScreenDashboard,
		Width:         80,
		Height:        24,

		Storage:         repo,
		RecentScans:     recentScans,
		HistoryPageSize: 10,

		IntelStats:   intelStats,
		IntelSources: intelSources,

		URLInput:         ti,
		ExportPathInput:  ei,
		ExportFormat:     "json",
		IntelSearchInput: isi,

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
