package cmd

import (
	"bouclier/internal/cli"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display application version and build information",
		Long:  "Displays the Bouclier application version, Go runtime, platform, and build revision.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunVersion(cmd.OutOrStdout())
		},
	}
}
