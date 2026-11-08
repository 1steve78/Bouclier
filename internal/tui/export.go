package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
)

// RenderExport renders the report export screen.
func RenderExport(
	styles Styles,
	format string,
	input textinput.Model,
	exportSuccess bool,
	exportMsg string,
	exportErr error,
	width int,
) string {
	contentWidth := width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 80 {
		contentWidth = 80
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("EXPORT REPORT") + "\n")
	b.WriteString(styles.Subtitle.Render("Export the completed risk assessment to a file on disk") + "\n\n")

	var form strings.Builder
	form.WriteString(styles.Bold.Render("Report Format:") + "\n")

	jsonRadio := "[ ] JSON (bouclier-risk/v1)"
	mdRadio := "[ ] Markdown"
	if strings.ToLower(format) == "json" {
		jsonRadio = styles.Bold.Render("[•] JSON (bouclier-risk/v1)")
	} else {
		mdRadio = styles.Bold.Render("[•] Markdown")
	}
	form.WriteString(fmt.Sprintf("%s    %s\n", jsonRadio, mdRadio))
	form.WriteString(styles.Muted.Render("Press [Tab] to toggle between JSON and Markdown.") + "\n\n")

	form.WriteString(styles.Bold.Render("Destination File Path:") + "\n")
	form.WriteString(input.View() + "\n\n")

	if exportSuccess {
		form.WriteString(styles.SuccessText.Render("✔ "+exportMsg) + "\n\n")
	} else if exportErr != nil {
		form.WriteString(styles.ErrorText.Render(fmt.Sprintf("✖ Export failed: %v", exportErr)) + "\n\n")
	}

	form.WriteString(styles.Muted.Render("File permissions are restricted to 0600 (owner read/write only).\nSensitive headers, credentials, and cookies are automatically redacted."))

	b.WriteString(styles.ActiveCard.Width(contentWidth).Render(form.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"Enter", "Save Report"},
		{"Tab", "Toggle Format"},
		{"Esc", "Cancel / Return"},
	}))

	return b.String()
}
