package tui

import (
	"fmt"
	"strings"
)

// RenderHelp renders the interactive help, keyboard shortcuts, and scoring guide.
func RenderHelp(styles Styles, width int) string {
	contentWidth := width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("HELP & METHODOLOGY") + "\n")
	b.WriteString(styles.Subtitle.Render("Keyboard shortcuts and risk assessment model") + "\n\n")

	// Keyboard Shortcuts Card
	var keys strings.Builder
	keys.WriteString(styles.CardTitle.Render("Keyboard Shortcuts") + "\n\n")
	shortcuts := [][2]string{
		{"q", "Quit application from anywhere"},
		{"?", "Toggle this help screen"},
		{"esc", "Return to previous screen / cancel modal"},
		{"enter", "Select item / confirm form action"},
		{"↑ / ↓ (k / j)", "Navigate lists and menus"},
		{"tab / shift+tab", "Cycle filters and controls"},
		{"1 – 6", "Direct severity filter shortcuts in findings explorer"},
		{"c", "Cancel scan while running / view coverage from overview"},
		{"f", "View findings list from overview"},
		{"e", "Export report to JSON or Markdown"},
		{"a", "Choose an installed Ollama model and explain the assessment"},
		{"n / s", "Initiate a new scan"},
		{"ctrl+c", "Safe force exit"},
	}

	for _, sc := range shortcuts {
		keys.WriteString(fmt.Sprintf("%-18s %s\n", styles.Key.Render(sc[0]), sc[1]))
	}
	b.WriteString(styles.Card.Width(contentWidth).Render(keys.String()))
	b.WriteString("\n\n")

	// Methodology Card
	var meth strings.Builder
	meth.WriteString(styles.CardTitle.Render("Risk Scoring Model & Tiers") + "\n\n")
	meth.WriteString("Bouclier computes a deterministic 0–100 integer risk score using capped integer\n")
	meth.WriteString("weights and confidence adjustments. The score is a relative product indicator,\n")
	meth.WriteString(styles.Bold.Render("NOT") + " a probability of compromise.\n\n")

	tiers := [][2]string{
		{"0", "CLEAN: No scored risk indicators observed in performed checks"},
		{"1 – 19", "LOW: Minor or informational anomalies; standard posture review"},
		{"20 – 49", "MEDIUM: Moderate security gaps or suspicious patterns requiring inspection"},
		{"50 – 79", "HIGH: Multiple significant indicators; high probability of phishing or severe misconfiguration"},
		{"80 – 100", "CRITICAL: Severe compromise, critical certificate failure, or confirmed impersonation"},
	}
	for _, t := range tiers {
		meth.WriteString(fmt.Sprintf("%-10s %s\n", styles.Bold.Render(t[0]), t[1]))
	}

	b.WriteString(styles.Card.Width(contentWidth).Render(meth.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"Esc / ?", "Return to Previous Screen"},
	}))

	return b.String()
}
