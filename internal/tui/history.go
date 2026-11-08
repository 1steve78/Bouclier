package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/storage"
)

// RenderHistory renders the persisted scan history explorer screen.
func RenderHistory(
	styles Styles,
	records []storage.ScanRecord,
	selectedIdx int,
	total int,
	page int,
	pageSize int,
	deleteConfirm bool,
	deleteID string,
	statusMsg string,
	width int,
) string {
	contentWidth := width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 96 {
		contentWidth = 96
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("SCAN HISTORY") + "\n")
	b.WriteString(styles.Subtitle.Render(fmt.Sprintf("%d total scan assessment(s) stored in local database", total)) + "\n\n")

	if len(records) == 0 {
		var empty strings.Builder
		empty.WriteString(styles.CardTitle.Render("No Scan History") + "\n\n")
		empty.WriteString(styles.Muted.Render("No previous scans found in local SQLite database.\nPress [ Esc ] to return to dashboard, or [ S ] to start a scan."))
		b.WriteString(styles.Card.Width(contentWidth).Render(empty.String()))
		b.WriteString("\n\n")
		b.WriteString(styles.FormatKeybar([][2]string{
			{"S", "New Scan"},
			{"Esc", "Back to Dashboard"},
		}))
		return b.String()
	}

	var list strings.Builder
	for i, r := range records {
		isCursor := (i == selectedIdx)
		cursor := "  "
		if isCursor {
			cursor = styles.Cursor.Render("> ")
		}

		timeStr := r.StartedAt.UTC().Format("2006-01-02 15:04")
		scoreStyle := styles.ScoreStyle(r.OverallScore)
		scoreStr := scoreStyle.Render(fmt.Sprintf("%2d/100", r.OverallScore))
		classStr := styles.SeverityShortBadge(string(r.Classification))

		target := r.Target
		availTarget := contentWidth - 48
		if availTarget > 12 && len(target) > availTarget {
			target = target[:availTarget-3] + "..."
		}

		var line string
		if contentWidth < 60 {
			line = fmt.Sprintf("%s%-8s %-16s %s %s", cursor, r.ShortID(), target, scoreStr, classStr)
		} else {
			line = fmt.Sprintf("%s%-8s  %-26s  %s  %s  %s  %-9s",
				cursor,
				styles.Bold.Render(r.ShortID()),
				target,
				styles.Muted.Render(timeStr),
				scoreStr,
				classStr,
				styles.Muted.Render(string(r.Status)),
			)
		}

		if isCursor {
			list.WriteString(styles.SelectedRow.Width(contentWidth - 2).Render(line))
		} else {
			list.WriteString(line)
		}
		list.WriteString("\n")
	}

	start := page*pageSize + 1
	end := page*pageSize + len(records)
	totalPages := ((total - 1) / pageSize) + 1
	if totalPages <= 0 {
		totalPages = 1
	}
	pagination := styles.Muted.Render(fmt.Sprintf("Showing %d–%d of %d scans  •  Page %d/%d (use [ / ] to flip)",
		start, end, total, page+1, totalPages))
	list.WriteString("\n" + pagination)

	b.WriteString(styles.Card.Width(contentWidth).Render(list.String()))
	b.WriteString("\n\n")

	if deleteConfirm {
		var confirmCard strings.Builder
		confirmCard.WriteString(styles.ErrorText.Render("⚠ Confirm Deletion") + "\n\n")
		confirmCard.WriteString(fmt.Sprintf("Are you sure you want to permanently delete scan record %s?\n", deleteID))
		confirmCard.WriteString(styles.Muted.Render("This will permanently remove the metadata and full report from local SQLite storage.\n\n"))
		confirmCard.WriteString(styles.FormatKeybar([][2]string{
			{"Y", "Confirm Delete"},
			{"N / Esc", "Cancel"},
		}))
		b.WriteString(styles.ActiveCard.Width(contentWidth).Render(confirmCard.String()))
		b.WriteString("\n\n")
	} else if statusMsg != "" {
		b.WriteString(styles.SuccessText.Render("✔ "+statusMsg) + "\n\n")
	}

	if !deleteConfirm {
		b.WriteString(styles.FormatKeybar([][2]string{
			{"↑/↓ (j/k)", "Navigate"},
			{"Enter", "Open Report"},
			{"E", "Export"},
			{"D", "Delete"},
			{"[ / ]", "Page"},
			{"Esc", "Dashboard"},
		}))
	}

	return b.String()
}
