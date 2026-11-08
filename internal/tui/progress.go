package tui

import (
	"fmt"
	"strings"
	"time"

	"bouclier/internal/cli"
)

// RenderProgress renders the active scan progress view.
func RenderProgress(
	styles Styles,
	target string,
	elapsed time.Duration,
	stages map[cli.ScanStage]cli.StageState,
	stageOrder []cli.ScanStage,
	messages map[cli.ScanStage]string,
	scanErr error,
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
	b.WriteString(styles.Title.Render("SCANNING IN PROGRESS") + "\n")
	b.WriteString(styles.Subtitle.Render(fmt.Sprintf("Target: %s  •  Elapsed: %0.1fs", target, elapsed.Seconds())) + "\n\n")

	var list strings.Builder
	for _, stage := range stageOrder {
		state := stages[stage]
		badge := stageBadge(styles, state)
		name := stageTitle(styles, stage, state)
		list.WriteString(fmt.Sprintf("%s  %s", badge, name))

		msg := messages[stage]
		if msg != "" && (state == cli.StageStateRunning || state == cli.StageStateFailed || state == cli.StageStatePartial) {
			list.WriteString("\n     " + styles.Muted.Render(msg))
		}
		list.WriteString("\n")
	}

	b.WriteString(styles.Card.Width(contentWidth).Render(list.String()))
	b.WriteString("\n\n")

	if scanErr != nil {
		var errCard strings.Builder
		errCard.WriteString(styles.ErrorText.Render("Scan Unsuccessful") + "\n\n")
		errCard.WriteString(fmt.Sprintf("Error: %v\n\n", scanErr))
		errCard.WriteString(styles.Muted.Render("Press Enter to retry scan, or Esc to return to dashboard."))
		b.WriteString(styles.Card.Width(contentWidth).Render(errCard.String()))
		b.WriteString("\n\n")
		b.WriteString(styles.FormatKeybar([][2]string{
			{"Enter", "Retry Scan"},
			{"Esc", "Return to Dashboard"},
		}))
	} else {
		b.WriteString(styles.FormatKeybar([][2]string{
			{"C / Esc", "Cancel Scan"},
		}))
	}

	return b.String()
}

func stageBadge(styles Styles, state cli.StageState) string {
	switch state {
	case cli.StageStateCompleted:
		return styles.StageCompleted.Render("[✓]")
	case cli.StageStateRunning:
		return styles.StageRunning.Render("[●]")
	case cli.StageStateFailed:
		return styles.StageFailed.Render("[✗]")
	case cli.StageStatePartial:
		return styles.StagePartial.Render("[~]")
	case cli.StageStateSkipped:
		return styles.StageSkipped.Render("[-]")
	default:
		return styles.StagePending.Render("[ ]")
	}
}

func stageTitle(styles Styles, stage cli.ScanStage, state cli.StageState) string {
	str := string(stage)
	switch state {
	case cli.StageStateCompleted:
		return styles.StageCompleted.Render(str)
	case cli.StageStateRunning:
		return styles.StageRunning.Render(str)
	case cli.StageStateFailed:
		return styles.StageFailed.Render(str)
	case cli.StageStatePartial:
		return styles.StagePartial.Render(str)
	case cli.StageStateSkipped:
		return styles.StageSkipped.Render(str + " (skipped)")
	default:
		return styles.StagePending.Render(str)
	}
}
