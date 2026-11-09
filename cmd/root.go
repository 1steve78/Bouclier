package cmd

import (
	"fmt"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/logging"
	"bouclier/internal/tui"
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	var configPath string
	var cfg *config.Config

	rootCmd := &cobra.Command{
		Use:   "bouclier",
		Short: "Bouclier | Security Intelligence Workstation",
		Long: `Bouclier is a terminal-first security workstation and command-line engine for
phishing detection, URL intelligence, domain analysis, TLS inspection,
and passive website security assessment.

Running 'bouclier' directly in an interactive terminal launches the full
security workstation dashboard. In non-interactive pipelines or scripts,
it displays command help and flags.

Commands:
  tui       Launch the interactive terminal user interface
  scan      Assess a target URL for phishing indicators and security risks
  history   Inspect and manage saved scan assessments
  intel     Manage local threat intelligence feeds and indicators
  mcp       Start the stdio Model Context Protocol server
  serve     Start the local Bouclier HTTP API server
  version   Display version and build metadata
  config    Inspect active scanner and application settings

Examples:
  bouclier                                      # Launch interactive workstation
  bouclier scan https://example.com             # CLI scan
  bouclier scan https://example.com --format json
  bouclier scan https://example.com --format markdown --output report.md
  bouclier scan https://example.com --no-ct --timeout 15s
  bouclier history list
  bouclier history show <scan-id>
  bouclier intel status
  bouclier mcp
  bouclier serve
  bouclier config show
  bouclier version`,
		Version:       cli.AppVersion,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if configPath == "" {
				cfg = config.Default()
			} else {
				cfg, err = config.Load(configPath)
				if err != nil {
					return fmt.Errorf("load configuration: %w", err)
				}
			}

			logger, err := logging.New(cfg.Logging, cmd.ErrOrStderr())
			if err != nil {
				return fmt.Errorf("initialize logger: %w", err)
			}
			cmd.SetContext(logging.WithContext(cmd.Context(), logger))
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if tui.IsInteractiveTerminal() {
				return tui.Run(cfg, tui.Options{})
			}
			return cmd.Help()
		},
	}

	getConfig := func() *config.Config {
		if cfg == nil {
			return config.Default()
		}
		return cfg
	}

	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to a JSON configuration file")

	rootCmd.AddCommand(newTUICommand(getConfig))
	rootCmd.AddCommand(newScanCommand(getConfig))
	rootCmd.AddCommand(newHistoryCommand(getConfig))
	rootCmd.AddCommand(newIntelCommand(getConfig))
	rootCmd.AddCommand(newMCPCommand(getConfig))
	rootCmd.AddCommand(newServeCommand(getConfig))
	rootCmd.AddCommand(newVersionCommand())
	rootCmd.AddCommand(newConfigCommand(getConfig))

	return rootCmd
}

// Execute runs the root command and returns any execution error.
func Execute() error {
	return newRootCommand().Execute()
}
