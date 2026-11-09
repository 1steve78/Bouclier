package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// RenderIntelImportExport renders the Threat Intelligence Bundle Import/Export dialog.
func RenderIntelImportExport(
	styles Styles,
	mode string,
	pathInput textinput.Model,
	success bool,
	msg string,
	err error,
	width int,
) string {
	boxWidth := width - 6
	if boxWidth < 50 {
		boxWidth = 50
	}
	if boxWidth > 76 {
		boxWidth = 76
	}

	var b strings.Builder

	titleStr := "EXPORT THREAT INTELLIGENCE BUNDLE"
	if mode == "import" {
		titleStr = "IMPORT THREAT INTELLIGENCE BUNDLE"
	}
	b.WriteString(styles.CardTitle.Render(titleStr))
	b.WriteString("\n" + styles.Subtitle.Render("Portable indicators bundle (schema: bouclier-intel-bundle/v1)") + "\n\n")

	if err != nil {
		b.WriteString(styles.ErrorText.Render(fmt.Sprintf("Error: %v\n\n", err)))
	} else if success {
		b.WriteString(styles.SuccessText.Render(fmt.Sprintf("✓ %s\n\n", msg)))
	}

	// Mode selector
	modeDesc := "Export active local indicators into a JSON bundle."
	if mode == "import" {
		modeDesc = "Import indicators from an external JSON bundle into local storage."
	}
	b.WriteString(styles.Bold.Render("Operation Mode:") + "\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n\n",
		styles.Key.Render(fmt.Sprintf("[ %s ]", strings.ToUpper(mode))),
		styles.Muted.Render("(press Space to toggle import/export)"),
	))
	b.WriteString(styles.Muted.Render(modeDesc) + "\n\n")

	// Destination / Source File Path
	pathLabel := "Destination File Path:"
	if mode == "import" {
		pathLabel = "Source Bundle File Path:"
	}
	b.WriteString(styles.Bold.Render(pathLabel) + "\n")
	b.WriteString(pathInput.View() + "\n\n")

	// Execute button
	btnLabel := " [ EXPORT BUNDLE ] "
	if mode == "import" {
		btnLabel = " [ IMPORT BUNDLE ] "
	}
	b.WriteString(styles.ActiveCard.Render(styles.Bold.Render(btnLabel)) + "\n\n")

	// Keybar
	b.WriteString(styles.FormatKeybar([][2]string{
		{"Space", "toggle mode"},
		{"Enter", "execute"},
		{"Esc", "cancel"},
	}))

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00D4FF")).
		Padding(1, 2).
		Width(boxWidth)

	if styles.NoColor {
		boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2).
			Width(boxWidth)
	}

	return boxStyle.Render(b.String())
}
