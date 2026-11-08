package cmd

import (
	"fmt"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/logging"
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	var configPath string
	var cfg *config.Config

	rootCmd := &cobra.Command{
		Use:   "bouclier",
		Short: "Intelligent phishing detection and website security scanner.",
		Long: `Bouclier is a command-line application for phishing detection and website security assessment.
It brings together URL heuristic analysis, domain intelligence, TLS verification,
and passive website security checks into a unified, explainable risk assessment.

Commands:
  tui       Launch the interactive terminal user interface
  scan      Assess a target URL for phishing indicators and security risks
  serve     Start the local Bouclier HTTP API server
  version   Display version and build metadata
  config    Inspect active scanner and application settings

Examples:
  bouclier tui
  bouclier scan https://example.com
  bouclier scan https://example.com --format json
  bouclier scan https://example.com --format markdown --output report.md
  bouclier scan https://example.com --no-ct --timeout 15s
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
	rootCmd.AddCommand(newServeCommand(getConfig))
	rootCmd.AddCommand(newVersionCommand())
	rootCmd.AddCommand(newConfigCommand(getConfig))

	return rootCmd
}

// Execute runs the root command and returns any execution error.
func Execute() error {
	return newRootCommand().Execute()
}
