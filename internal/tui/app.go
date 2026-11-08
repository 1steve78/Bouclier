package tui

import (
	"errors"
	"fmt"
	"os"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/storage"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
)

// Options configures the launch of the interactive TUI.
type Options struct {
	NoColor          bool
	ForceInteractive bool
}

// Run launches the Bubble Tea interactive application.
func Run(cfg *config.Config, opts Options) error {
	if cfg == nil {
		cfg = config.Default()
	}

	// Check terminal interactivity unless forced (e.g. in test harness)
	if !opts.ForceInteractive {
		if !isInteractiveTerminal() {
			return cli.NewExitError(
				cli.ExitInvalidUsage,
				"bouclier tui requires an interactive terminal (stdin and stdout must be attached to a terminal). Use 'bouclier scan <url>' for non-interactive scanning.",
			)
		}
	}

	noColor := opts.NoColor || os.Getenv("NO_COLOR") != ""
	var repo storage.Repository
	var storageErr error
	if cfg != nil && cfg.Storage.DatabasePath != "" {
		r, err := storage.Open(cfg.Storage.DatabasePath)
		if err == nil {
			repo = r
			defer repo.Close()
		} else {
			storageErr = err
		}
	}

	model := NewModelWithStorage(cfg, noColor, repo)
	model.StorageErr = storageErr
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
	)

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("tui runtime error: %w", err)
	}

	if m, ok := finalModel.(Model); ok && m.ScanErr != nil && !errors.Is(m.ScanErr, contextCanceled(m.ScanErr)) {
		// Log or preserve scan error if needed
	}

	return nil
}

func contextCanceled(err error) error {
	return errors.New("scan cancelled by user")
}

func isInteractiveTerminal() bool {
	stdinFd := os.Stdin.Fd()
	stdoutFd := os.Stdout.Fd()

	stdinOk := isatty.IsTerminal(stdinFd) || isatty.IsCygwinTerminal(stdinFd)
	stdoutOk := isatty.IsTerminal(stdoutFd) || isatty.IsCygwinTerminal(stdoutFd)

	return stdinOk && stdoutOk
}
