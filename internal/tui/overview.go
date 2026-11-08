package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/risk"
	"github.com/charmbracelet/lipgloss"
)

type AIExplanationState struct {
	Enabled bool
	Loading bool
	Text    string
	Model   string
	Err     error
}

// RenderOverview renders the post-scan assessment overview screen.
func RenderOverview(styles Styles, assessment *risk.RiskAssessment, width int, aiStates ...AIExplanationState) string {
	if assessment == nil {
		return styles.Muted.Render("No active assessment to display.")
	}

	contentWidth := width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 88 {
		contentWidth = 88
	}

	var b strings.Builder

	// Header banner
	header := fmt.Sprintf("ASSESSMENT OVERVIEW: %s", assessment.Target)
	b.WriteString(styles.Title.Render(header) + "\n")
	b.WriteString(styles.Subtitle.Render(fmt.Sprintf("Policy: %s %s  •  Analyzed: %s",
		assessment.PolicyID,
		assessment.PolicyVersion,
		assessment.AnalyzedAt.Format("2006-01-02 15:04:05 UTC"),
	)) + "\n\n")

	// Risk Score & Classification Card
	scoreStyle := styles.ScoreStyle(assessment.OverallScore)
	tierStr := strings.ToUpper(string(assessment.Classification))
	scoreBox := fmt.Sprintf("%s\n%s",
		scoreStyle.Render(fmt.Sprintf("%d / 100", assessment.OverallScore)),
		scoreStyle.Render(tierStr),
	)

	sevSummary := renderSeverityCounts(styles, assessment)

	var topBlock string
	if contentWidth < 60 {
		topBlock = lipgloss.JoinVertical(
			lipgloss.Left,
			styles.Card.Width(contentWidth).Render(styles.CardTitle.Render("Risk Score")+"\n\n"+scoreBox+"\n\n"+styles.Muted.Render("Relative product indicator (0–100), not a probability.")),
			styles.Card.Width(contentWidth).Render(styles.CardTitle.Render("Finding Counts")+"\n\n"+sevSummary),
		)
	} else {
		halfWidth := (contentWidth / 2) - 3
		topBlock = lipgloss.JoinHorizontal(
			lipgloss.Top,
			styles.Card.Width(halfWidth).Render(styles.CardTitle.Render("Risk Score")+"\n\n"+scoreBox+"\n\n"+styles.Muted.Render("Relative product indicator (0–100), not a probability.")),
			styles.Card.Width(halfWidth).Render(styles.CardTitle.Render("Finding Counts")+"\n\n"+sevSummary),
		)
	}
	b.WriteString(topBlock)
	b.WriteString("\n\n")

	// Top Risk Factors Card
	var topFactors strings.Builder
	topFactors.WriteString(styles.CardTitle.Render("Top Contributing Risk Factors") + "\n\n")
	if len(assessment.TopRiskFactors) == 0 {
		topFactors.WriteString(styles.Muted.Render("No significant risk factors observed."))
	} else {
		for i, factor := range assessment.TopRiskFactors {
			if i >= 5 {
				break
			}
			f := factor.Finding
			badge := styles.SeverityBadge(string(f.Severity))
			topFactors.WriteString(fmt.Sprintf("%s %s  %s\n",
				badge,
				styles.Bold.Render(fmt.Sprintf("+%d pts", factor.Contribution)),
				f.Title,
			))
		}
	}
	b.WriteString(styles.Card.Width(contentWidth).Render(topFactors.String()))
	b.WriteString("\n\n")

	// Coverage & Limitations Summary Card
	var covSummary strings.Builder
	covSummary.WriteString(styles.CardTitle.Render("Analysis Coverage & Limitations") + "\n\n")
	var comp, part, fail, skip int
	for _, c := range assessment.AnalysisCoverage {
		switch c.State {
		case risk.ComponentCompleted:
			comp++
		case risk.ComponentPartial:
			part++
		case risk.ComponentFailed:
			fail++
		case risk.ComponentSkipped:
			skip++
		}
	}
	covSummary.WriteString(fmt.Sprintf("Component status: %s  •  %s  •  %s  •  %s\n",
		styles.StageCompleted.Render(fmt.Sprintf("%d Completed", comp)),
		styles.StagePartial.Render(fmt.Sprintf("%d Partial", part)),
		styles.StageFailed.Render(fmt.Sprintf("%d Failed", fail)),
		styles.StageSkipped.Render(fmt.Sprintf("%d Skipped", skip)),
	))
	if len(assessment.Limitations) > 0 {
		covSummary.WriteString(styles.Muted.Render(fmt.Sprintf("Notice: %d assessment limitation(s) noted (press [C] for full coverage breakdown).", len(assessment.Limitations))))
	}
	b.WriteString(styles.Card.Width(contentWidth).Render(covSummary.String()))
	b.WriteString("\n\n")

	var aiState AIExplanationState
	if len(aiStates) > 0 {
		aiState = aiStates[0]
	}
	if aiState.Enabled {
		var explanation strings.Builder
		explanation.WriteString(styles.CardTitle.Render("AI-generated explanation (assessment remains authoritative)") + "\n\n")
		switch {
		case aiState.Loading:
			explanation.WriteString(styles.Muted.Render("Requesting an explanation from the configured local Ollama model..."))
		case aiState.Err != nil:
			explanation.WriteString(styles.StageFailed.Render("Explanation failed: " + aiState.Err.Error()))
		case aiState.Text != "":
			if aiState.Model != "" {
				explanation.WriteString(styles.Muted.Render("Model: "+aiState.Model) + "\n\n")
			}
			explanation.WriteString(wrapText(aiState.Text, contentWidth-8))
		default:
			explanation.WriteString(styles.Muted.Render("Press [A] to select an installed local Ollama model and explain this assessment."))
		}
		b.WriteString(styles.Card.Width(contentWidth).Render(explanation.String()))
		b.WriteString("\n\n")
	}

	// Navigation Keybar
	keybar := [][2]string{
		{"F / Enter", "View Findings"},
		{"C", "Coverage & Limitations"},
		{"E", "Export Report"},
		{"N", "New Scan"},
		{"?", "Help"},
		{"Q", "Quit"},
	}
	if aiState.Enabled {
		keybar = append(keybar, [2]string{"A", "Explain with local AI"})
	}
	b.WriteString(styles.FormatKeybar(keybar))

	return b.String()
}

func renderSeverityCounts(styles Styles, assessment *risk.RiskAssessment) string {
	counts := make(map[risk.Severity]int)
	for _, sc := range assessment.SeverityCounts {
		counts[sc.Severity] = sc.Count
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s  %d\n", styles.CritBadge.Render("CRIT"), counts[risk.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("%s  %d\n", styles.HighBadge.Render("HIGH"), counts[risk.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("%s  %d\n", styles.MedBadge.Render("MED "), counts[risk.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("%s  %d\n", styles.LowBadge.Render("LOW "), counts[risk.SeverityLow]))
	sb.WriteString(fmt.Sprintf("%s  %d", styles.InfoBadge.Render("INFO"), counts[risk.SeverityInformational]))
	return sb.String()
}
