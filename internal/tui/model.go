package tui

import (
	"context"
	"os"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/report"
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
	ScreenHistoryCorrelate
	ScreenIntel
	ScreenIntelSourceAdd
	ScreenIntelImportExport
	ScreenConfig
	ScreenServices
	ScreenAbout
	ScreenAIModelSelect
	ScreenCommandPalette
)

// PaletteAction defines actions triggered from the command palette.
type PaletteAction int

const (
	ActionNavigate PaletteAction = iota
	ActionSyncIntel
	ActionToggleAPIServer
	ActionToggleNoColor
	ActionPruneIntel
	ActionNewScan
	ActionQuit
)

// PaletteItem represents a single executable entry in the command palette.
type PaletteItem struct {
	Title        string
	Description  string
	Category     string
	Action       PaletteAction
	TargetScreen Screen
}

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

	// Workstation Dashboard State
	DashboardSelectedIdx int

	// Command Palette State
	PaletteInput          textinput.Model
	PaletteItems          []PaletteItem
	PaletteFiltered       []PaletteItem
	PaletteSelectedIdx    int
	PalettePreviousScreen Screen

	// Scanner Options
	ScanNoCT       bool
	ScanCTScope    string // "exact" or "registrable"
	ScanTimeoutSec int    // e.g. 8
	ScanInputFocus int    // 0: URL input, 1: CT toggle, 2: Scope, 3: Timeout

	// History Search & Correlation
	HistoryFilterInput     textinput.Model
	HistoryFiltering       bool
	HistoryFilterText      string
	HistoryCorrelateTarget string
	HistoryCorrelateReport *report.Correlation
	HistoryCorrelateErr    error

	// Threat Intelligence Extended State
	IntelAddIDInput          textinput.Model
	IntelAddNameInput        textinput.Model
	IntelAddType             string // "local_file" or "https_feed"
	IntelAddEndpointInput    textinput.Model
	IntelAddEnvInput         textinput.Model
	IntelAddFocus            int // 0: ID, 1: Name, 2: Type, 3: Endpoint, 4: Env, 5: Submit
	IntelAddErr              error
	IntelBundlePathInput     textinput.Model
	IntelBundleMode          string // "import" or "export"
	IntelBundleSuccess       bool
	IntelBundleMsg           string
	IntelBundleErr           error
	IntelPruneConfirm        bool
	IntelDeleteSourceConfirm bool
	IntelDeleteSourceID      string

	// In-Process REST API Server Management
	APIServerRunning bool
	APIServerPort    int
	APIServerStarted time.Time
	APIServerCancel  context.CancelFunc
	APIServerErr     error

	// Configuration & About Screens
	ConfigScrollOffset int
	ConfigSubsystem    int // 0: All, 1: Scanner, 2: Storage, 3: ThreatIntel, 4: HTTPServer, 5: Logging, 6: AI
	AboutScrollOffset  int
	AboutActiveTab     int // 0: Metadata, 1: License, 2: Notices, 3: Security

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

	pi := textinput.New()
	pi.Placeholder = "Type a command or navigate..."
	pi.CharLimit = 64
	pi.Width = 50

	hfi := textinput.New()
	hfi.Placeholder = "Filter by target hostname..."
	hfi.CharLimit = 128
	hfi.Width = 35

	addID := textinput.New()
	addID.Placeholder = "source-id (e.g. enterprise-feed)"
	addID.CharLimit = 64
	addID.Width = 40

	addName := textinput.New()
	addName.Placeholder = "Display Name"
	addName.CharLimit = 64
	addName.Width = 40

	addEndpoint := textinput.New()
	addEndpoint.Placeholder = "https://feed.example.org/feed.json or local/path.json"
	addEndpoint.CharLimit = 256
	addEndpoint.Width = 50

	addEnv := textinput.New()
	addEnv.Placeholder = "BOUCLIER_FEED_TOKEN (environment variable name only)"
	addEnv.CharLimit = 64
	addEnv.Width = 40

	bundlePath := textinput.New()
	bundlePath.Placeholder = "bundle.json"
	bundlePath.CharLimit = 256
	bundlePath.Width = 45

	paletteItems := defaultPaletteItems()

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

		PaletteInput:       pi,
		PaletteItems:       paletteItems,
		PaletteFiltered:    paletteItems,
		PaletteSelectedIdx: 0,

		ScanCTScope:    "exact",
		ScanTimeoutSec: 8,

		HistoryFilterInput: hfi,

		IntelAddIDInput:       addID,
		IntelAddNameInput:     addName,
		IntelAddType:          "https_feed",
		IntelAddEndpointInput: addEndpoint,
		IntelAddEnvInput:      addEnv,
		IntelBundlePathInput:  bundlePath,
		IntelBundleMode:       "export",

		APIServerPort: 8081,

		StageOrder:    stageOrder,
		Stages:        stages,
		StageMessages: make(map[cli.ScanStage]string),
		ActiveFilter:  FilterAll,
	}
}

func defaultPaletteItems() []PaletteItem {
	return []PaletteItem{
		{
			Title:        "Target Scanner",
			Description:  "Assess a URL for phishing and security weaknesses",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenURLInput,
		},
		{
			Title:        "Scan History",
			Description:  "Inspect saved scans, search targets, and correlate trends",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenHistory,
		},
		{
			Title:        "Threat Intelligence",
			Description:  "Manage feeds, inspect indicator stats, and search indicators",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenIntel,
		},
		{
			Title:        "Security Reports",
			Description:  "Export security assessment reports to JSON or Markdown",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenExport,
		},
		{
			Title:        "Configuration Inspector",
			Description:  "Inspect active scanner, storage, and server settings",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenConfig,
		},
		{
			Title:        "API & MCP Services",
			Description:  "Manage background REST server and view MCP client guides",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenServices,
		},
		{
			Title:        "About & Integrity",
			Description:  "View build metadata, MIT license, notices, and security model",
			Category:     "Navigate",
			Action:       ActionNavigate,
			TargetScreen: ScreenAbout,
		},
		{
			Title:       "Synchronize Threat Feeds",
			Description: "Trigger background download and parsing of enabled feeds",
			Category:    "Action",
			Action:      ActionSyncIntel,
		},
		{
			Title:       "Toggle REST API Server",
			Description: "Start or stop the in-process HTTP API daemon on 127.0.0.1:8081",
			Category:    "Action",
			Action:      ActionToggleAPIServer,
		},
		{
			Title:       "Prune Expired Indicators",
			Description: "Clean expired indicators from local threat database",
			Category:    "Action",
			Action:      ActionPruneIntel,
		},
		{
			Title:       "Toggle Color Theme",
			Description: "Switch between high-contrast color and monochrome themes",
			Category:    "Action",
			Action:      ActionToggleNoColor,
		},
		{
			Title:       "Quit Bouclier",
			Description: "Close the workstation session and return to terminal",
			Category:    "Action",
			Action:      ActionQuit,
		},
	}
}

// Init initializes the Bubble Tea model.
func (m Model) Init() tea.Cmd {
	return textinput.Blink
}
