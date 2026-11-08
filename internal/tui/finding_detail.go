package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/risk"
)

// RenderFindingDetail renders the in-depth inspection view for a single finding.
func RenderFindingDetail(
	styles Styles,
	finding risk.NormalizedFinding,
	currentIndex int,
	totalFindings int,
	width int,
) string {
	contentWidth := width - 4
	if contentWidth < 45 {
		contentWidth = 45
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder
	badge := styles.SeverityBadge(string(finding.Severity))
	b.WriteString(fmt.Sprintf("%s  %s\n", badge, styles.Title.Render(finding.Title)))
	b.WriteString(styles.Subtitle.Render(fmt.Sprintf("Finding %d of %d in current view", currentIndex+1, totalFindings)) + "\n\n")

	var card strings.Builder

	// Metadata Table
	card.WriteString(styles.CardTitle.Render("Metadata") + "\n\n")
	card.WriteString(fmt.Sprintf("%-18s %s\n", styles.Bold.Render("Finding Code:"), finding.Code))
	card.WriteString(fmt.Sprintf("%-18s %s\n", styles.Bold.Render("Category:"), finding.Category))
	card.WriteString(fmt.Sprintf("%-18s %s\n", styles.Bold.Render("Scoring Group:"), finding.ScoringCategory))
	card.WriteString(fmt.Sprintf("%-18s %s  •  Confidence: %s\n",
		styles.Bold.Render("Severity:"),
		finding.Severity,
		finding.Confidence,
	))
	impactText := fmt.Sprintf("+%d points", finding.ScoreImpact)
	if finding.ScoreImpact == 0 {
		impactText = "0 points (informational or unscored)"
	}
	card.WriteString(fmt.Sprintf("%-18s %s\n", styles.Bold.Render("Score Impact:"), styles.Bold.Render(impactText)))
	card.WriteString(fmt.Sprintf("%-18s %s\n", styles.Bold.Render("Source Subsystem:"), finding.Source))
	if len(finding.Sources) > 1 {
		card.WriteString(fmt.Sprintf("%-18s %s\n", styles.Bold.Render("All Sources:"), strings.Join(finding.Sources, ", ")))
	}
	card.WriteString("\n")

	// Description
	card.WriteString(styles.CardTitle.Render("Description") + "\n\n")
	card.WriteString(wrapText(finding.Description, contentWidth-6) + "\n\n")

	// Technical Evidence
	card.WriteString(styles.CardTitle.Render("Technical Evidence") + "\n\n")
	evidence := finding.Evidence
	if strings.TrimSpace(evidence) == "" {
		evidence = "(no additional technical evidence attached)"
	}
	card.WriteString(styles.Muted.Render(wrapText(evidence, contentWidth-6)) + "\n\n")

	// Recommended Action
	card.WriteString(styles.CardTitle.Render("Recommended Action") + "\n\n")
	remediation := finding.Remediation
	if strings.TrimSpace(remediation) == "" {
		remediation = "Investigate the affected security posture configuration or domain attributes."
	}
	card.WriteString(wrapText(remediation, contentWidth-6) + "\n")

	b.WriteString(styles.Card.Width(contentWidth).Render(card.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"P / ←", "Previous Finding"},
		{"N / →", "Next Finding"},
		{"Esc", "Back to Findings List"},
	}))

	return b.String()
}

func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var lines []string
	var current strings.Builder
	for _, word := range words {
		if current.Len()+len(word)+1 > width {
			lines = append(lines, current.String())
			current.Reset()
			current.WriteString(word)
		} else {
			if current.Len() > 0 {
				current.WriteString(" ")
			}
			current.WriteString(word)
		}
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return strings.Join(lines, "\n")
}
