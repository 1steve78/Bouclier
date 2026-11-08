package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Styles encapsulates all Lipgloss styles for the TUI.
type Styles struct {
	NoColor bool

	// Typography
	Title       lipgloss.Style
	Subtitle    lipgloss.Style
	Header      lipgloss.Style
	CardTitle   lipgloss.Style
	Muted       lipgloss.Style
	Bold        lipgloss.Style
	ErrorText   lipgloss.Style
	SuccessText lipgloss.Style

	// Containers & Borders
	Card       lipgloss.Style
	ActiveCard lipgloss.Style
	HelpBox    lipgloss.Style
	BorderBox  lipgloss.Style

	// Badges & Statuses
	CritBadge lipgloss.Style
	HighBadge lipgloss.Style
	MedBadge  lipgloss.Style
	LowBadge  lipgloss.Style
	InfoBadge lipgloss.Style

	ScoreClean lipgloss.Style
	ScoreLow   lipgloss.Style
	ScoreMed   lipgloss.Style
	ScoreHigh  lipgloss.Style
	ScoreCrit  lipgloss.Style

	StagePending   lipgloss.Style
	StageRunning   lipgloss.Style
	StageCompleted lipgloss.Style
	StagePartial   lipgloss.Style
	StageFailed    lipgloss.Style
	StageSkipped   lipgloss.Style

	// Interactive Controls
	TabActive   lipgloss.Style
	TabInactive lipgloss.Style
	Cursor      lipgloss.Style
	SelectedRow lipgloss.Style
	Footer      lipgloss.Style
	Key         lipgloss.Style
	KeyDesc     lipgloss.Style
}

// NewStyles constructs a theme configured for color or monochrome terminals.
func NewStyles(noColor bool) Styles {
	if noColor {
		return monochromeStyles()
	}
	return colorStyles()
}

func colorStyles() Styles {
	cyan := lipgloss.Color("#00D4FF")
	red := lipgloss.Color("#FF4757")
	orange := lipgloss.Color("#FF6B6B")
	yellow := lipgloss.Color("#FFA502")
	green := lipgloss.Color("#2ED573")
	blue := lipgloss.Color("#70A1FF")
	gray := lipgloss.Color("#747D8C")
	darkGray := lipgloss.Color("#2F3542")
	white := lipgloss.Color("#FFFFFF")

	return Styles{
		NoColor:     false,
		Title:       lipgloss.NewStyle().Bold(true).Foreground(cyan),
		Subtitle:    lipgloss.NewStyle().Foreground(gray),
		Header:      lipgloss.NewStyle().Bold(true).Foreground(white),
		CardTitle:   lipgloss.NewStyle().Bold(true).Foreground(cyan),
		Muted:       lipgloss.NewStyle().Foreground(gray),
		Bold:        lipgloss.NewStyle().Bold(true),
		ErrorText:   lipgloss.NewStyle().Foreground(red).Bold(true),
		SuccessText: lipgloss.NewStyle().Foreground(green).Bold(true),

		Card: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(darkGray).
			Padding(0, 1),
		ActiveCard: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cyan).
			Padding(0, 1),
		HelpBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(gray).
			Padding(1, 2),
		BorderBox: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(darkGray),

		CritBadge: lipgloss.NewStyle().Bold(true).Foreground(white).Background(red).Padding(0, 1),
		HighBadge: lipgloss.NewStyle().Bold(true).Foreground(white).Background(orange).Padding(0, 1),
		MedBadge:  lipgloss.NewStyle().Bold(true).Foreground(white).Background(yellow).Padding(0, 1),
		LowBadge:  lipgloss.NewStyle().Bold(true).Foreground(white).Background(green).Padding(0, 1),
		InfoBadge: lipgloss.NewStyle().Bold(true).Foreground(white).Background(blue).Padding(0, 1),

		ScoreClean: lipgloss.NewStyle().Bold(true).Foreground(green),
		ScoreLow:   lipgloss.NewStyle().Bold(true).Foreground(blue),
		ScoreMed:   lipgloss.NewStyle().Bold(true).Foreground(yellow),
		ScoreHigh:  lipgloss.NewStyle().Bold(true).Foreground(orange),
		ScoreCrit:  lipgloss.NewStyle().Bold(true).Foreground(red),

		StagePending:   lipgloss.NewStyle().Foreground(gray),
		StageRunning:   lipgloss.NewStyle().Bold(true).Foreground(yellow),
		StageCompleted: lipgloss.NewStyle().Bold(true).Foreground(green),
		StagePartial:   lipgloss.NewStyle().Bold(true).Foreground(yellow),
		StageFailed:    lipgloss.NewStyle().Bold(true).Foreground(red),
		StageSkipped:   lipgloss.NewStyle().Foreground(gray),

		TabActive: lipgloss.NewStyle().
			Bold(true).
			Foreground(white).
			Background(cyan).
			Padding(0, 1),
		TabInactive: lipgloss.NewStyle().
			Foreground(gray).
			Padding(0, 1),
		Cursor: lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan),
		SelectedRow: lipgloss.NewStyle().
			Bold(true).
			Foreground(white).
			Background(darkGray),
		Footer: lipgloss.NewStyle().
			Foreground(gray).
			Padding(0, 1),
		Key: lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan),
		KeyDesc: lipgloss.NewStyle().
			Foreground(gray),
	}
}

func monochromeStyles() Styles {
	return Styles{
		NoColor:     true,
		Title:       lipgloss.NewStyle().Bold(true),
		Subtitle:    lipgloss.NewStyle(),
		Header:      lipgloss.NewStyle().Bold(true),
		CardTitle:   lipgloss.NewStyle().Bold(true),
		Muted:       lipgloss.NewStyle(),
		Bold:        lipgloss.NewStyle().Bold(true),
		ErrorText:   lipgloss.NewStyle().Bold(true),
		SuccessText: lipgloss.NewStyle().Bold(true),

		Card: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1),
		ActiveCard: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1),
		HelpBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2),
		BorderBox: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()),

		CritBadge: lipgloss.NewStyle().Bold(true),
		HighBadge: lipgloss.NewStyle().Bold(true),
		MedBadge:  lipgloss.NewStyle().Bold(true),
		LowBadge:  lipgloss.NewStyle().Bold(true),
		InfoBadge: lipgloss.NewStyle().Bold(true),

		ScoreClean: lipgloss.NewStyle().Bold(true),
		ScoreLow:   lipgloss.NewStyle().Bold(true),
		ScoreMed:   lipgloss.NewStyle().Bold(true),
		ScoreHigh:  lipgloss.NewStyle().Bold(true),
		ScoreCrit:  lipgloss.NewStyle().Bold(true),

		StagePending:   lipgloss.NewStyle(),
		StageRunning:   lipgloss.NewStyle().Bold(true),
		StageCompleted: lipgloss.NewStyle().Bold(true),
		StagePartial:   lipgloss.NewStyle().Bold(true),
		StageFailed:    lipgloss.NewStyle().Bold(true),
		StageSkipped:   lipgloss.NewStyle(),

		TabActive: lipgloss.NewStyle().
			Bold(true).
			Underline(true).
			Padding(0, 1),
		TabInactive: lipgloss.NewStyle().
			Padding(0, 1),
		Cursor: lipgloss.NewStyle().
			Bold(true),
		SelectedRow: lipgloss.NewStyle().
			Bold(true).
			Underline(true),
		Footer: lipgloss.NewStyle().
			Padding(0, 1),
		Key: lipgloss.NewStyle().
			Bold(true),
		KeyDesc: lipgloss.NewStyle(),
	}
}

// SeverityBadge renders a styled severity tag.
func (s Styles) SeverityBadge(severity string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))
	switch sev {
	case "CRITICAL":
		return s.CritBadge.Render("[CRITICAL]")
	case "HIGH":
		return s.HighBadge.Render("[HIGH]")
	case "MEDIUM":
		return s.MedBadge.Render("[MEDIUM]")
	case "LOW":
		return s.LowBadge.Render("[LOW]")
	default:
		return s.InfoBadge.Render("[INFO]")
	}
}

// SeverityShortBadge renders a compact 3-letter severity tag.
func (s Styles) SeverityShortBadge(severity string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))
	switch sev {
	case "CRITICAL":
		return s.CritBadge.Render("CRIT")
	case "HIGH":
		return s.HighBadge.Render("HIGH")
	case "MEDIUM":
		return s.MedBadge.Render("MED ")
	case "LOW":
		return s.LowBadge.Render("LOW ")
	default:
		return s.InfoBadge.Render("INFO")
	}
}

// ScoreStyle returns the appropriate style for a given score and tier.
func (s Styles) ScoreStyle(score int) lipgloss.Style {
	switch {
	case score >= 80:
		return s.ScoreCrit
	case score >= 50:
		return s.ScoreHigh
	case score >= 20:
		return s.ScoreMed
	case score > 0:
		return s.ScoreLow
	default:
		return s.ScoreClean
	}
}

// FormatKeybar renders a horizontal list of keyboard shortcuts for the footer.
func (s Styles) FormatKeybar(pairs [][2]string) string {
	items := make([]string, len(pairs))
	for i, pair := range pairs {
		items[i] = fmt.Sprintf("%s %s", s.Key.Render(pair[0]), s.KeyDesc.Render(pair[1]))
	}
	return strings.Join(items, "  •  ")
}
