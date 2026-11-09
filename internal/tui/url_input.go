package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
)

// RenderURLInput renders the URL input and scan configuration screen.
func RenderURLInput(
	styles Styles,
	input textinput.Model,
	validationErr string,
	noCT bool,
	ctScope string,
	timeoutSec int,
	focusIdx int,
	width int,
) string {
	contentWidth := width - 6
	if contentWidth < 40 {
		contentWidth = 40
	}
	if contentWidth > 80 {
		contentWidth = 80
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("TARGET SCANNER") + "\n")
	b.WriteString(styles.Subtitle.Render("Enter a website URL or hostname to assess") + "\n\n")

	var form strings.Builder
	form.WriteString(styles.Bold.Render("Website Target:") + "\n")
	form.WriteString(input.View() + "\n\n")

	if validationErr != "" {
		form.WriteString(styles.ErrorText.Render("⚠ "+validationErr) + "\n\n")
	} else {
		form.WriteString(styles.Muted.Render("Examples: example.com, https://security.org, https://sub.bank.com") + "\n\n")
	}

	// Scan options section
	form.WriteString(styles.Bold.Render("Scan Options:") + "\n")

	ctBox := "[X] Enabled"
	if noCT {
		ctBox = "[ ] Disabled (--no-ct)"
	}
	c1 := "  "
	if focusIdx == 1 {
		c1 = styles.Bold.Render("▶ ")
	}
	form.WriteString(fmt.Sprintf("%sCertificate Transparency:  %s  %s\n",
		c1,
		styles.Key.Render(ctBox),
		styles.Muted.Render("(press 'c' to toggle)"),
	))

	if ctScope == "" {
		ctScope = "exact"
	}
	scopeBox := fmt.Sprintf("[ %s ]", ctScope)
	c2 := "  "
	if focusIdx == 2 {
		c2 = styles.Bold.Render("▶ ")
	}
	form.WriteString(fmt.Sprintf("%sCT Match Scope:            %s  %s\n",
		c2,
		styles.Key.Render(scopeBox),
		styles.Muted.Render("(press 'o' to toggle exact / registrable)"),
	))

	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	timeoutBox := fmt.Sprintf("[ %ds ]", timeoutSec)
	c3 := "  "
	if focusIdx == 3 {
		c3 = styles.Bold.Render("▶ ")
	}
	form.WriteString(fmt.Sprintf("%sAnalysis Timeout:          %s  %s\n\n",
		c3,
		styles.Key.Render(timeoutBox),
		styles.Muted.Render("(press 't' to cycle 5s / 8s / 15s / 30s)"),
	))

	form.WriteString(styles.Muted.Render("SSRF protections strictly block private, loopback, and internal IPs."))

	b.WriteString(styles.ActiveCard.Width(contentWidth).Render(form.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"Enter", "start scan"},
		{"Tab", "cycle options"},
		{"Esc / b", "dashboard"},
		{"q", "quit"},
	}))

	return b.String()
}
