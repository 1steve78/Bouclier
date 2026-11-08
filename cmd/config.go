package cmd

import (
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"github.com/spf13/cobra"
)

func newConfigCommand(getConfig func() *config.Config) *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect Bouclier configuration",
		Long:  "Commands to view and inspect active Bouclier scanner and application settings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	configCmd.AddCommand(newConfigShowCommand(getConfig))
	return configCmd
}

func newConfigShowCommand(getConfig func() *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Display effective configuration",
		Long:  "Displays the active configuration settings used by Bouclier.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getConfig()
			return cli.RunConfigShow(cfg, cmd.OutOrStdout())
		},
	}
}
