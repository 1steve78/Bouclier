package cmd

import (
	"fmt"

	"bouclier/internal/config"
	"bouclier/internal/logging"
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	var configPath string
	rootCmd := &cobra.Command{
		Use:   "bouclier",
		Short: "Intelligent phishing detection and website security scanner.",
		Long: `Bouclier is a command-line application for phishing detection and website security assessment.
It will bring together URL analysis, security checks, and actionable results in a focused CLI
and, in a future phase, an interactive terminal interface. Scanning functionality is under
active development and is not available yet.`,
		Version:       "0.1.0-dev",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg *config.Config
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
	}
	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to a JSON configuration file")
	return rootCmd
}

// Execute runs the root command and returns any execution error.
func Execute() error {
	return newRootCommand().Execute()
}
