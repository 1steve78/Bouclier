package tui

import (
	"fmt"
	"strings"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
	"github.com/charmbracelet/lipgloss"
)

// WorkstationModule describes a primary module of the workstation.
type WorkstationModule struct {
	Number      string
	Title       string
	Description string
}

var workstationModules = []WorkstationModule{
	{"1", "Target Scanner", "Assess a target URL for phishing, TLS, headers, and risk"},
	{"2", "Scan History", "Browse past security assessments, search by domain, correlate trends"},
	{"3", "Threat Intelligence", "Manage threat feeds, search indicators, sync and prune"},
	{"4", "Security Reports", "Export assessments to JSON/Markdown, correlate targets"},
	{"5", "Configuration", "Inspect active scanner, storage, server, and AI parameters"},
	{"6", "API & MCP Services", "Control local REST daemon, MCP stdio client setup"},
	{"7", "About & Integrity", "Build metadata, license, third-party notices, security policy"},
}

// RenderDashboard renders the main welcoming dashboard view.
func RenderDashboard(
	styles Styles,
	width int,
	recentAssessment *risk.RiskAssessment,
	recentScans []storage.ScanRecord,
	intelStats *storage.IntelStats,
	intelSources []storage.IntelSource,
	dbPath string,
	apiRunning bool,
	apiPort int,
	selectedIdx int,
	storageErr error,
) string {
	contentWidth := width - 6
	if contentWidth < 40 {
		contentWidth = 40
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	banner := renderBanner(styles, contentWidth)

	var b strings.Builder
	b.WriteString(banner)
	b.WriteString("\n\n")

	// Greeting & Prompt
	greeting := timeOfDayGreeting()
	b.WriteString(fmt.Sprintf("%s  %s\n\n",
		styles.Header.Render(greeting),
		styles.Subtitle.Render("What would you like to investigate?"),
	))

	// System Status Summary Card
	var statText strings.Builder
	statText.WriteString(styles.CardTitle.Render("System Status & Environment") + "\n\n")

	// Scan metrics
	totalScans := len(recentScans)
	scans24h := 0
	now := time.Now()
	for _, s := range recentScans {
		if now.Sub(s.StartedAt) < 24*time.Hour {
			scans24h++
		}
	}
	statText.WriteString(fmt.Sprintf("• %-18s %s (recent cached), %s in last 24h\n",
		styles.Bold.Render("Scans:"),
		styles.ScoreMed.Render(fmt.Sprintf("%d", totalScans)),
		styles.ScoreClean.Render(fmt.Sprintf("%d", scans24h)),
	))

	// Threat intel metrics
	activeFeeds := len(intelSources)
	var activeIndicators int
	if intelStats != nil {
		activeIndicators = intelStats.TotalIndicators
	}
	statText.WriteString(fmt.Sprintf("• %-18s %d configured, %s active indicators\n",
		styles.Bold.Render("Threat Feeds:"),
		activeFeeds,
		styles.ScoreLow.Render(fmt.Sprintf("%d", activeIndicators)),
	))

	// Storage metrics
	dbDisplay := dbPath
	if dbDisplay == "" {
		dbDisplay = "~/.bouclier/bouclier.db"
	}
	if len(dbDisplay) > contentWidth-32 && len(dbDisplay) > 20 {
		dbDisplay = "..." + dbDisplay[len(dbDisplay)-(contentWidth-35):]
	}
	storageStatus := styles.ScoreClean.Render("Connected (WAL mode)")
	if storageErr != nil {
		storageStatus = styles.ErrorText.Render("Storage Notice: " + storageErr.Error())
	}
	statText.WriteString(fmt.Sprintf("• %-18s %s [%s]\n",
		styles.Bold.Render("Storage Engine:"),
		storageStatus,
		styles.Muted.Render(dbDisplay),
	))

	// Services metrics
	apiStatus := styles.Muted.Render("Stopped")
	if apiRunning {
		apiStatus = styles.SuccessText.Render(fmt.Sprintf("Running (http://127.0.0.1:%d)", apiPort))
	}
	statText.WriteString(fmt.Sprintf("• %-18s REST API: %s  •  MCP: %s\n",
		styles.Bold.Render("Services:"),
		apiStatus,
		styles.ScoreClean.Render("Ready (stdio)"),
	))

	b.WriteString(styles.Card.Width(contentWidth).Render(statText.String()))
	b.WriteString("\n\n")

	// 7 Workstation Modules Card
	var modText strings.Builder
	modText.WriteString(styles.CardTitle.Render("Workstation Modules") + "  " + styles.Muted.Render("(press 1–7 or use ↑/↓ and Enter)") + "\n\n")

	for i, mod := range workstationModules {
		cursor := "  "
		isSelected := (i == selectedIdx)
		if isSelected {
			cursor = styles.Bold.Render("▶ ")
		}

		keyBadge := styles.Key.Render(fmt.Sprintf("[%s]", mod.Number))
		title := mod.Title
		if isSelected {
			title = styles.Bold.Render(title)
		}

		modText.WriteString(fmt.Sprintf("%s%s %-22s %s\n",
			cursor,
			keyBadge,
			title,
			styles.Muted.Render(mod.Description),
		))
	}

	if recentAssessment != nil {
		modText.WriteString("\n" + fmt.Sprintf("%s %s %s\n",
			styles.Key.Render(" [ R ]"),
			styles.Bold.Render("Active Scan:"),
			styles.Muted.Render(fmt.Sprintf("%s (%s - score %d)", recentAssessment.Target, recentAssessment.Classification, recentAssessment.OverallScore)),
		))
	}

	b.WriteString(styles.ActiveCard.Width(contentWidth).Render(modText.String()))
	b.WriteString("\n\n")

	// Recent Scans Table
	var recText strings.Builder
	recText.WriteString(styles.CardTitle.Render("Recent Scans") + "\n\n")
	if len(recentScans) > 0 {
		for _, r := range recentScans {
			timeStr := r.StartedAt.UTC().Format("2006-01-02 15:04")
			scoreStyle := styles.ScoreStyle(r.OverallScore)
			scoreStr := scoreStyle.Render(fmt.Sprintf("%2d/100", r.OverallScore))
			classStr := styles.SeverityShortBadge(string(r.Classification))

			target := r.Target
			availTarget := contentWidth - 44
			if availTarget > 12 && len(target) > availTarget {
				target = target[:availTarget-3] + "..."
			}

			recText.WriteString(fmt.Sprintf("%-8s  %-24s  %s  %s  %s\n",
				styles.Bold.Render(r.ShortID()),
				target,
				styles.Muted.Render(timeStr),
				scoreStr,
				classStr,
			))
		}
		recText.WriteString("\n" + styles.Muted.Render("Press [ 2 ] or [ H ] to view full scan history, inspect details, or export."))
	} else if storageErr != nil {
		recText.WriteString(styles.Muted.Render(fmt.Sprintf("Local history storage notice: %v\n", storageErr)))
	} else {
		recText.WriteString(styles.Muted.Render("No scan history found. Press [ 1 ] or [ Enter ] to start your first scan.\n"))
	}
	b.WriteString(styles.Card.Width(contentWidth).Render(recText.String()))

	// Keybar
	b.WriteString("\n\n")
	keybar := styles.FormatKeybar([][2]string{
		{"1-7", "navigate"},
		{"Enter", "select"},
		{"/", "palette"},
		{"?", "help"},
		{"q", "quit"},
	})
	b.WriteString(keybar)

	return b.String()
}

func timeOfDayGreeting() string {
	h := time.Now().Hour()
	switch {
	case h >= 5 && h < 12:
		return "Good morning!"
	case h >= 12 && h < 17:
		return "Good afternoon!"
	case h >= 17 && h < 22:
		return "Good evening!"
	default:
		return "Good night!"
	}
}

func renderBanner(styles Styles, width int) string {
	title := styles.Title.Render("BOUCLIER")
	identity := styles.Bold.Render("Security Intelligence Workstation")
	version := styles.Subtitle.Render("v" + cli.AppVersion)
	headerLine := fmt.Sprintf("%s  •  %s  •  %s", title, identity, version)
	subLine := styles.Subtitle.Render("Unified Phishing Detection, TLS Inspection, Threat Intelligence & Risk Posture")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00D4FF")).
		Padding(0, 2).
		Width(width)

	if styles.NoColor {
		box = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 2).
			Width(width)
	}

	return box.Render(headerLine + "\n" + subLine)
}
