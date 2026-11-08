package tui

import (
	"fmt"
	"strings"
)

func RenderAIModelSelect(m Model) string {
	width := m.Width - 6
	if width < 30 {
		width = 30
	}
	if width > 86 {
		width = 86
	}

	var b strings.Builder
	b.WriteString(m.Styles.Title.Render("SELECT LOCAL OLLAMA MODEL") + "\n")
	b.WriteString(m.Styles.Subtitle.Render("Models are read from the output of `ollama list`.") + "\n\n")

	var card strings.Builder
	switch {
	case m.AIModelLoading:
		card.WriteString(m.Styles.Muted.Render("Loading installed models with `ollama list`..."))
	case m.AIModelListErr != nil:
		card.WriteString(m.Styles.ErrorText.Render("Could not load Ollama models: " + m.AIModelListErr.Error()))
		card.WriteString("\n\n" + m.Styles.Muted.Render("Confirm Ollama is installed and available on PATH, then press [R] to retry."))
	case len(m.AIModels) == 0:
		card.WriteString(m.Styles.Muted.Render("No models are installed. Run `ollama pull <model>` and press [R] to refresh."))
	default:
		card.WriteString(m.Styles.CardTitle.Render("Installed models") + "\n\n")
		for i, model := range m.AIModels {
			cursor := "  "
			if i == m.AIModelSelectedIdx {
				cursor = m.Styles.Cursor.Render("> ")
			}
			current := ""
			if m.Config != nil && model == m.Config.AI.Ollama.Model {
				current = m.Styles.Muted.Render(" (configured)")
			}
			line := fmt.Sprintf("%s%s%s", cursor, model, current)
			if i == m.AIModelSelectedIdx {
				card.WriteString(m.Styles.SelectedRow.Width(width - 6).Render(line))
			} else {
				card.WriteString(line)
			}
			card.WriteByte('\n')
		}
	}
	b.WriteString(m.Styles.Card.Width(width).Render(card.String()))
	b.WriteString("\n\n")

	keybar := [][2]string{{"↑/↓ (j/k)", "Select model"}, {"Enter", "Use model and explain"}}
	if m.AIModelListErr != nil || len(m.AIModels) == 0 {
		keybar = append(keybar, [2]string{"R", "Reload model list"})
	}
	keybar = append(keybar, [2]string{"Esc", "Back"})
	b.WriteString(m.Styles.FormatKeybar(keybar))
	return b.String()
}
