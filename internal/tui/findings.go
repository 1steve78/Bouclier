package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/risk"
)

type SeverityFilter string

const (
	FilterAll      SeverityFilter = "All"
	FilterCritical SeverityFilter = "Critical"
	FilterHigh     SeverityFilter = "High"
	FilterMedium   SeverityFilter = "Medium"
	FilterLow      SeverityFilter = "Low"
	FilterInfo     SeverityFilter = "Informational"
)

// FilterFindings returns the findings matching the specified severity filter.
func FilterFindings(findings []risk.NormalizedFinding, filter SeverityFilter) []risk.NormalizedFinding {
	if filter == FilterAll || filter == "" {
		return findings
	}
	target := strings.ToLower(string(filter))
	result := make([]risk.NormalizedFinding, 0)
	for _, f := range findings {
		if strings.ToLower(string(f.Severity)) == target {
			result = append(result, f)
		}
	}
	return result
}

// RenderFindings renders the findings list explorer view.
func RenderFindings(
	styles Styles,
	findings []risk.NormalizedFinding,
	filtered []risk.NormalizedFinding,
	selectedIndex int,
	activeFilter SeverityFilter,
	width int,
	maxVisible int,
) string {
	contentWidth := width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 90 {
		contentWidth = 90
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("FINDINGS EXPLORER") + "\n")
	b.WriteString(styles.Subtitle.Render(fmt.Sprintf("%d total finding(s) observed across all security subsystems", len(findings))) + "\n\n")

	// Filter Bar
	filterBar := renderFilterBar(styles, findings, activeFilter)
	b.WriteString(filterBar + "\n\n")

	if len(filtered) == 0 {
		var empty strings.Builder
		empty.WriteString(styles.Muted.Render(fmt.Sprintf("No findings match filter %q.", activeFilter)) + "\n\n")
		empty.WriteString(styles.Muted.Render("Press [1] or [Tab] to view all findings, or [Esc] to return to overview."))
		b.WriteString(styles.Card.Width(contentWidth).Render(empty.String()))
		b.WriteString("\n\n")
		b.WriteString(styles.FormatKeybar([][2]string{
			{"1-6 / Tab", "Switch Filter"},
			{"Esc", "Back to Overview"},
		}))
		return b.String()
	}

	// Calculate scrolling window
	if maxVisible <= 0 {
		maxVisible = 8
	}
	startIdx := 0
	if selectedIndex >= maxVisible {
		startIdx = selectedIndex - maxVisible + 1
	}
	endIdx := startIdx + maxVisible
	if endIdx > len(filtered) {
		endIdx = len(filtered)
	}

	var list strings.Builder
	for i := startIdx; i < endIdx; i++ {
		f := filtered[i]
		isCursor := (i == selectedIndex)

		cursor := "  "
		if isCursor {
			cursor = styles.Cursor.Render("> ")
		}

		badge := styles.SeverityShortBadge(string(f.Severity))
		impact := fmt.Sprintf("+%2d", f.ScoreImpact)
		if f.ScoreImpact == 0 {
			impact = "  0"
		}

		title := f.Title
		maxTitleLen := contentWidth - 32
		if maxTitleLen > 10 && len(title) > maxTitleLen {
			title = title[:maxTitleLen-3] + "..."
		}

		var line string
		if contentWidth < 55 {
			compactTitle := title
			avail := contentWidth - 14
			if avail > 5 && len(compactTitle) > avail {
				compactTitle = compactTitle[:avail-3] + "..."
			}
			line = fmt.Sprintf("%s%s %s %s", cursor, badge, styles.Bold.Render(impact), compactTitle)
		} else {
			line = fmt.Sprintf("%s%s  %s pts  %-22s  %s",
				cursor,
				badge,
				styles.Bold.Render(impact),
				styles.Muted.Render(f.Code),
				title,
			)
		}

		if isCursor {
			list.WriteString(styles.SelectedRow.Width(contentWidth - 2).Render(line))
		} else {
			list.WriteString(line)
		}
		list.WriteString("\n")
	}

	pagination := styles.Muted.Render(fmt.Sprintf("Showing %d–%d of %d findings (Page %d/%d)",
		startIdx+1,
		endIdx,
		len(filtered),
		(selectedIndex/maxVisible)+1,
		((len(filtered)-1)/maxVisible)+1,
	))
	list.WriteString("\n" + pagination)

	b.WriteString(styles.Card.Width(contentWidth).Render(list.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"↑/↓", "Navigate"},
		{"Enter", "Inspect Detail"},
		{"1-6 / Tab", "Filter Severity"},
		{"Esc", "Back to Overview"},
	}))

	return b.String()
}

func renderFilterBar(styles Styles, all []risk.NormalizedFinding, current SeverityFilter) string {
	counts := make(map[SeverityFilter]int)
	counts[FilterAll] = len(all)
	for _, f := range all {
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			counts[FilterCritical]++
		case "high":
			counts[FilterHigh]++
		case "medium":
			counts[FilterMedium]++
		case "low":
			counts[FilterLow]++
		case "informational":
			counts[FilterInfo]++
		}
	}

	filters := []struct {
		Key    string
		Filter SeverityFilter
		Label  string
	}{
		{"1", FilterAll, "All"},
		{"2", FilterCritical, "Crit"},
		{"3", FilterHigh, "High"},
		{"4", FilterMedium, "Med"},
		{"5", FilterLow, "Low"},
		{"6", FilterInfo, "Info"},
	}

	var items []string
	for _, f := range filters {
		label := fmt.Sprintf("[%s: %s (%d)]", f.Key, f.Label, counts[f.Filter])
		if f.Filter == current {
			items = append(items, styles.TabActive.Render(label))
		} else {
			items = append(items, styles.TabInactive.Render(label))
		}
	}
	return strings.Join(items, " ")
}
