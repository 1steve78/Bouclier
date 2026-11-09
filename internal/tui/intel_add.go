package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// RenderIntelSourceAdd renders the Add Threat Intelligence Source dialog.
func RenderIntelSourceAdd(
	styles Styles,
	idInput textinput.Model,
	nameInput textinput.Model,
	srcType string,
	endpointInput textinput.Model,
	envInput textinput.Model,
	focusIdx int,
	addErr error,
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

	// Header
	header := styles.CardTitle.Render("REGISTER THREAT FEED SOURCE")
	b.WriteString(header)
	b.WriteString("\n" + styles.Subtitle.Render("Add a local JSON feed file or authenticated HTTPS threat feed") + "\n\n")

	if addErr != nil {
		b.WriteString(styles.ErrorText.Render(fmt.Sprintf("Error: %v\n\n", addErr)))
	}

	// 1. Source ID
	b.WriteString(styles.Bold.Render("1. Source Identifier:") + "\n")
	b.WriteString(idInput.View() + "\n\n")

	// 2. Display Name
	b.WriteString(styles.Bold.Render("2. Friendly Display Name:") + "\n")
	b.WriteString(nameInput.View() + "\n\n")

	// 3. Source Type
	b.WriteString(styles.Bold.Render("3. Source Protocol Type:") + "\n")
	typeStr := "[ local_file ]"
	if srcType == "https_feed" {
		typeStr = "[ https_feed ]"
	}
	focusIndicator := "  "
	if focusIdx == 2 {
		focusIndicator = styles.Bold.Render("▶ ")
	}
	b.WriteString(fmt.Sprintf("%s%s  %s\n\n", focusIndicator, styles.Key.Render(typeStr), styles.Muted.Render("(press Space to toggle)")))

	// 4. Endpoint
	b.WriteString(styles.Bold.Render("4. Endpoint URL / File Path:") + "\n")
	b.WriteString(endpointInput.View() + "\n\n")

	// 5. Auth Header Env Variable
	b.WriteString(styles.Bold.Render("5. Auth Header Environment Variable (Optional):") + "\n")
	b.WriteString(envInput.View() + "\n")
	b.WriteString(styles.Muted.Render("  Notice: Provide ONLY the environment variable name (e.g. BOUCLIER_FEED_TOKEN).\n  Plaintext secrets and tokens are never stored at rest.") + "\n\n")

	// Submit button
	btnStyle := styles.Card
	if focusIdx == 5 {
		btnStyle = styles.ActiveCard
	}
	b.WriteString(btnStyle.Render(styles.Bold.Render(" [ SAVE THREAT SOURCE ] ")) + "\n\n")

	// Keybar
	b.WriteString(styles.FormatKeybar([][2]string{
		{"Tab / Shift+Tab", "navigate fields"},
		{"Space", "toggle type"},
		{"Enter", "save source"},
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
