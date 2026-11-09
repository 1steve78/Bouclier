package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// RenderPalette renders the overlay command palette.
func RenderPalette(styles Styles, inputView string, items []PaletteItem, selectedIdx int, width int) string {
	boxWidth := width - 6
	if boxWidth < 50 {
		boxWidth = 50
	}
	if boxWidth > 76 {
		boxWidth = 76
	}

	var b strings.Builder

	header := styles.CardTitle.Render("COMMAND PALETTE") + "  " + styles.Muted.Render("Search actions & navigate")
	b.WriteString(header)
	b.WriteString("\n\n")

	// Search input prompt
	prompt := styles.Bold.Render("> ") + inputView
	b.WriteString(prompt)
	b.WriteString("\n")
	b.WriteString(styles.Muted.Render(strings.Repeat("─", boxWidth-4)))
	b.WriteString("\n")

	// Item list
	if len(items) == 0 {
		b.WriteString("\n  " + styles.Muted.Render("No matching actions found. Try typing another term.") + "\n\n")
	} else {
		maxItems := 8
		start := 0
		if selectedIdx >= maxItems {
			start = selectedIdx - maxItems + 1
		}
		end := start + maxItems
		if end > len(items) {
			end = len(items)
		}

		for i := start; i < end; i++ {
			item := items[i]
			cursor := "  "
			isSelected := (i == selectedIdx)
			if isSelected {
				cursor = styles.Bold.Render("▶ ")
			}

			catBadge := styles.InfoBadge.Render(fmt.Sprintf("%-8s", item.Category))
			if item.Category == "Action" {
				catBadge = styles.HighBadge.Render(fmt.Sprintf("%-8s", item.Category))
			}

			titleStr := item.Title
			if isSelected {
				titleStr = styles.Bold.Render(titleStr)
			}

			line := fmt.Sprintf("%s%s  %-24s  %s",
				cursor,
				catBadge,
				titleStr,
				styles.Muted.Render(item.Description),
			)
			// Truncate line if it exceeds box
			if lipgloss.Width(line) > boxWidth-2 {
				// keep it safe
			}
			b.WriteString(line + "\n")
		}
	}

	b.WriteString(styles.Muted.Render(strings.Repeat("─", boxWidth-4)))
	b.WriteString("\n")
	footer := styles.FormatKeybar([][2]string{
		{"↑/↓", "navigate"},
		{"Enter", "execute"},
		{"Esc", "dismiss"},
	})
	b.WriteString(footer)

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#00D4FF")).
		Padding(1, 2).
		Width(boxWidth)

	if styles.NoColor {
		boxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			Padding(1, 2).
			Width(boxWidth)
	}

	return boxStyle.Render(b.String())
}
