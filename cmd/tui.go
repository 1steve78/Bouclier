package cmd

import (
	"bouclier/internal/config"
	"bouclier/internal/tui"
	"github.com/spf13/cobra"
)

func newTUICommand(getConfig func() *config.Config) *cobra.Command {
	var noColor bool

	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal user interface",
		Long: `Start Bouclier's interactive terminal user interface (TUI).
Allows inspecting, starting scans, filtering findings, and reviewing
analysis coverage using an interactive, keyboard-driven interface.

Examples:
  bouclier tui
  bouclier tui --no-color
  bouclier tui --config configs/config.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getConfig()
			opts := tui.Options{
				NoColor: noColor,
			}
			return tui.Run(cfg, opts)
		},
	}

	tuiCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable terminal colors in interactive UI")

	return tuiCmd
}
