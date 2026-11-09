package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/report"
)

// RenderHistoryCorrelate renders the multi-scan historical trend correlation view.
func RenderHistoryCorrelate(
	styles Styles,
	target string,
	corr *report.Correlation,
	corrErr error,
	width int,
) string {
	contentWidth := width - 6
	if contentWidth < 50 {
		contentWidth = 50
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder

	// Header
	title := styles.Title.Render("TARGET RISK TREND CORRELATION")
	sub := styles.Subtitle.Render(fmt.Sprintf("Historical security posture evolution for %s", styles.Bold.Render(target)))
	b.WriteString(fmt.Sprintf("%s\n%s\n\n", title, sub))

	if corrErr != nil {
		b.WriteString(styles.Card.Width(contentWidth).Render(
			styles.ErrorText.Render(fmt.Sprintf("Correlation Error: %v\n", corrErr)),
		))
		b.WriteString("\n\n" + styles.FormatKeybar([][2]string{{"Esc / b", "back to history"}}))
		return b.String()
	}

	if corr == nil || len(corr.Scans) == 0 {
		b.WriteString(styles.Card.Width(contentWidth).Render(
			styles.Muted.Render(fmt.Sprintf("No historical scans found for target %q.\nRun at least one scan to establish a baseline.", target)),
		))
		b.WriteString("\n\n" + styles.FormatKeybar([][2]string{{"Esc / b", "back to history"}}))
		return b.String()
	}

	// 1. Summary Card
	var sum strings.Builder
	sum.WriteString(styles.CardTitle.Render("Correlation Summary") + "\n\n")
	sum.WriteString(fmt.Sprintf("• Target Host:       %s\n", styles.Bold.Render(corr.Target)))
	sum.WriteString(fmt.Sprintf("• Total Scans:       %d\n", len(corr.Scans)))

	firstScan := corr.Scans[0]
	lastScan := corr.Scans[len(corr.Scans)-1]
	sum.WriteString(fmt.Sprintf("• First Seen:        %s (Score: %d)\n", firstScan.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"), firstScan.Score))
	sum.WriteString(fmt.Sprintf("• Last Seen:         %s (Score: %d)\n", lastScan.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"), lastScan.Score))

	delta := lastScan.Score - firstScan.Score
	trendBadge := styles.ScoreMed.Render("STABLE")
	if delta > 0 {
		trendBadge = styles.ScoreCrit.Render(fmt.Sprintf("ELEVATING (+%d)", delta))
	} else if delta < 0 {
		trendBadge = styles.ScoreClean.Render(fmt.Sprintf("IMPROVING (%d)", delta))
	}
	sum.WriteString(fmt.Sprintf("• Risk Trend:        %s (Net Delta: %+d)\n", trendBadge, delta))

	b.WriteString(styles.Card.Width(contentWidth).Render(sum.String()))
	b.WriteString("\n\n")

	// 2. Timeline Chart Card
	var chart strings.Builder
	chart.WriteString(styles.CardTitle.Render("Historical Risk Progression") + "\n\n")

	maxBarWidth := 20
	if contentWidth > 70 {
		maxBarWidth = 28
	}

	for _, pt := range corr.Scans {
		timeStr := pt.StartedAt.UTC().Format("2006-01-02 15:04")
		scoreVal := pt.Score
		fillLen := (scoreVal * maxBarWidth) / 100
		if fillLen > maxBarWidth {
			fillLen = maxBarWidth
		}
		emptyLen := maxBarWidth - fillLen

		scoreStyle := styles.ScoreStyle(scoreVal)
		barStr := scoreStyle.Render(strings.Repeat("■", fillLen)) + styles.Muted.Render(strings.Repeat("·", emptyLen))
		scoreStr := scoreStyle.Render(fmt.Sprintf("%2d/100", scoreVal))
		badge := styles.SeverityShortBadge(string(pt.Classification))

		diffStr := ""
		if len(pt.NewFindings) > 0 {
			diffStr += fmt.Sprintf(" +%d new", len(pt.NewFindings))
		}
		if len(pt.ResolvedFindings) > 0 {
			diffStr += fmt.Sprintf(" -%d res", len(pt.ResolvedFindings))
		}

		chart.WriteString(fmt.Sprintf("  %-16s  [%s]  %s  %s%s\n",
			styles.Muted.Render(timeStr),
			barStr,
			scoreStr,
			badge,
			styles.Muted.Render(diffStr),
		))
	}

	b.WriteString(styles.Card.Width(contentWidth).Render(chart.String()))
	b.WriteString("\n\n")

	// 3. Finding Transitions Card
	var findingsText strings.Builder
	findingsText.WriteString(styles.CardTitle.Render("Latest Scan Finding State Transitions") + "\n\n")
	findingsText.WriteString(fmt.Sprintf("• New Emerged Findings:    %s\n", styles.ScoreCrit.Render(fmt.Sprintf("%d", len(lastScan.NewFindings)))))
	findingsText.WriteString(fmt.Sprintf("• Resolved Findings:        %s\n", styles.ScoreClean.Render(fmt.Sprintf("%d", len(lastScan.ResolvedFindings)))))

	if len(lastScan.NewFindings) > 0 {
		findingsText.WriteString("\n" + styles.Bold.Render("Recently Emerged Findings:") + "\n")
		for _, f := range lastScan.NewFindings {
			findingsText.WriteString(fmt.Sprintf("  + [%s] %s\n", styles.CritBadge.Render(f.Code), f.Title))
		}
	}
	if len(lastScan.ResolvedFindings) > 0 {
		findingsText.WriteString("\n" + styles.Bold.Render("Resolved Findings:") + "\n")
		for _, f := range lastScan.ResolvedFindings {
			findingsText.WriteString(fmt.Sprintf("  - [%s] %s\n", styles.ScoreClean.Render(f.Code), f.Title))
		}
	}

	b.WriteString(styles.Card.Width(contentWidth).Render(findingsText.String()))

	// Keybar
	b.WriteString("\n\n")
	keybar := styles.FormatKeybar([][2]string{
		{"Esc / b", "back to history"},
		{"1-7", "switch module"},
		{"/", "palette"},
		{"?", "help"},
		{"q", "quit"},
	})
	b.WriteString(keybar)

	return b.String()
}
