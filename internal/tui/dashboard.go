package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/cli"
	"bouclier/internal/risk"
	"github.com/charmbracelet/lipgloss"
)

// RenderDashboard renders the main welcoming dashboard view.
func RenderDashboard(styles Styles, width int, recentAssessment *risk.RiskAssessment) string {
	contentWidth := width - 4
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

	// Capabilities card
	var capText strings.Builder
	capText.WriteString(styles.CardTitle.Render("Security Intelligence Engine") + "\n\n")
	capText.WriteString(fmt.Sprintf("• %s Homographs, entropy, suspicious TLDs, IP literals\n", styles.Bold.Render("URL & Domain:")))
	capText.WriteString(fmt.Sprintf("• %s Handshake, cert validity, key strength, CT logs\n", styles.Bold.Render("TLS & Certificates:")))
	capText.WriteString(fmt.Sprintf("• %s Security headers, cookies, CORS, disclosure\n", styles.Bold.Render("HTTP Posture:")))
	capText.WriteString(fmt.Sprintf("• %s Capped integer-weighted sum (0–100 relative index)\n", styles.Bold.Render("Unified Risk Score:")))

	b.WriteString(styles.Card.Width(contentWidth).Render(capText.String()))
	b.WriteString("\n\n")

	// Actions card
	var actText strings.Builder
	actText.WriteString(styles.CardTitle.Render("Actions") + "\n\n")
	actText.WriteString(fmt.Sprintf("%s   %s\n", styles.Key.Render("[ Enter / S ]"), "Start a new website scan"))
	if recentAssessment != nil {
		actText.WriteString(fmt.Sprintf("%s       %s (%s - %s)\n",
			styles.Key.Render("[ R ]"),
			"Return to active assessment",
			recentAssessment.Target,
			recentAssessment.Classification,
		))
	}
	actText.WriteString(fmt.Sprintf("%s       %s\n", styles.Key.Render("[ ? ]"), "View keyboard shortcuts and methodology"))
	actText.WriteString(fmt.Sprintf("%s       %s\n", styles.Key.Render("[ Q ]"), "Exit Bouclier"))

	b.WriteString(styles.ActiveCard.Width(contentWidth).Render(actText.String()))

	if recentAssessment != nil {
		b.WriteString("\n\n")
		var recText strings.Builder
		recText.WriteString(styles.Muted.Render(fmt.Sprintf("Last target: %s  |  Score: %d/100 (%s)",
			recentAssessment.Target,
			recentAssessment.OverallScore,
			strings.ToUpper(string(recentAssessment.Classification)),
		)))
		b.WriteString(styles.Card.Width(contentWidth).Render(recText.String()))
	}

	return b.String()
}

func renderBanner(styles Styles, width int) string {
	title := styles.Title.Render("BOUCLIER")
	version := styles.Subtitle.Render("v" + cli.AppVersion)
	headerLine := fmt.Sprintf("%s  %s", title, version)
	subLine := styles.Subtitle.Render("Interactive Website Security Assessment & Phishing Detection")

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
