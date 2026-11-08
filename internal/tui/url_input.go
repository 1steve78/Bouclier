package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
)

// RenderURLInput renders the URL input screen.
func RenderURLInput(styles Styles, input textinput.Model, validationErr string, width int) string {
	contentWidth := width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 80 {
		contentWidth = 80
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("TARGET SELECTION") + "\n")
	b.WriteString(styles.Subtitle.Render("Enter a website URL or hostname to assess") + "\n\n")

	var form strings.Builder
	form.WriteString(styles.Bold.Render("Website Target:") + "\n")
	form.WriteString(input.View() + "\n\n")

	if validationErr != "" {
		form.WriteString(styles.ErrorText.Render("⚠ "+validationErr) + "\n\n")
	} else {
		form.WriteString(styles.Muted.Render("Examples: example.com, https://security.org, https://sub.bank.com") + "\n\n")
	}

	form.WriteString(styles.Muted.Render("Supports HTTP and HTTPS. Bare hostnames default to https://.\nSSRF protections strictly block private, loopback, and internal IPs."))

	b.WriteString(styles.ActiveCard.Width(contentWidth).Render(form.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"Enter", "Start Scan"},
		{"Esc", "Back to Dashboard"},
	}))

	return b.String()
}
