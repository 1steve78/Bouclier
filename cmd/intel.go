package cmd

import (
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	"github.com/spf13/cobra"
)

func newIntelCommand(getConfig func() *config.Config) *cobra.Command {
	intelCmd := &cobra.Command{
		Use:   "intel",
		Short: "Manage local threat intelligence feeds and indicators",
		Long: `Manage threat intelligence sources, synchronize local indicators, search indicators,
and explicitly import or export collaborative threat bundles without background sharing.

Commands:
  status    Display summary statistics and health of the intelligence database
  sources   List configured threat intelligence sources
  update    Synchronize enabled threat intelligence feeds
  search    Search local indicators by target, domain, IP, or category
  import    Import threat intelligence indicators from a bundle, JSON, or CSV file
  export    Export local intelligence indicators to a validated collaborative bundle
  prune     Remove expired indicators from the local database

Examples:
  bouclier intel status
  bouclier intel sources
  bouclier intel update
  bouclier intel update feed-1
  bouclier intel search example.com
  bouclier intel import bundle.json
  bouclier intel export shared_bundle.json --category phishing
  bouclier intel prune --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := cli.IntelStatusOptions{}
			return cli.RunIntelStatus(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	intelCmd.AddCommand(newIntelStatusCommand(getConfig))
	intelCmd.AddCommand(newIntelSourcesCommand(getConfig))
	intelCmd.AddCommand(newIntelUpdateCommand(getConfig))
	intelCmd.AddCommand(newIntelSearchCommand(getConfig))
	intelCmd.AddCommand(newIntelImportCommand(getConfig))
	intelCmd.AddCommand(newIntelExportCommand(getConfig))
	intelCmd.AddCommand(newIntelPruneCommand(getConfig))

	return intelCmd
}

func newIntelStatusCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelStatusOptions

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display intelligence database health and metrics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunIntelStatus(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")
	return cmd
}

func newIntelSourcesCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelSourcesOptions

	cmd := &cobra.Command{
		Use:   "sources",
		Short: "List and manage configured threat intelligence sources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunIntelSources(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")

	cmd.AddCommand(newIntelSourcesListCommand(getConfig))
	cmd.AddCommand(newIntelSourcesAddCommand(getConfig))
	cmd.AddCommand(newIntelSourcesRemoveCommand(getConfig))
	cmd.AddCommand(newIntelSourcesEnableCommand(getConfig))
	cmd.AddCommand(newIntelSourcesDisableCommand(getConfig))

	return cmd
}

func newIntelSourcesListCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelSourcesOptions

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured intelligence sources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunIntelSources(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")
	return cmd
}

func newIntelSourcesAddCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelSourceAddOptions
	var intervalStr string

	cmd := &cobra.Command{
		Use:   "add <id> <name> <type> <endpoint>",
		Short: "Register a new intelligence source (local_file or https_feed)",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ID = args[0]
			opts.Name = args[1]
			opts.ProviderType = args[2]
			opts.Endpoint = args[3]
			if intervalStr != "" {
				d, err := time.ParseDuration(intervalStr)
				if err != nil {
					return cli.NewExitError(cli.ExitInvalidUsage, "invalid --interval duration %q: %v", intervalStr, err)
				}
				opts.UpdateInterval = d
			}
			return cli.RunIntelSourceAdd(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "Feed format ('json' or 'csv')")
	cmd.Flags().StringVar(&opts.AuthHeaderEnv, "auth-header-env", "", "Environment variable containing the authorization header value (e.g. 'BOUCLIER_FEED_TOKEN')")
	cmd.Flags().StringVar(&opts.Attribution, "attribution", "", "Source provider attribution text")
	cmd.Flags().StringVar(&opts.License, "license", "", "Source data license")
	cmd.Flags().StringVar(&intervalStr, "interval", "24h", "Update interval (e.g. '12h', '24h')")
	cmd.Flags().BoolVar(&opts.Disabled, "disabled", false, "Register the source as disabled")
	return cmd
}

func newIntelSourcesRemoveCommand(getConfig func() *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove <id>",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a configured intelligence source",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunIntelSourceRemove(cmd.Context(), getConfig(), args[0], cmd.OutOrStdout())
		},
	}
	return cmd
}

func newIntelSourcesEnableCommand(getConfig func() *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <id>",
		Short: "Enable a configured intelligence source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunIntelSourceSetEnabled(cmd.Context(), getConfig(), args[0], true, cmd.OutOrStdout())
		},
	}
	return cmd
}

func newIntelSourcesDisableCommand(getConfig func() *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "Disable a configured intelligence source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunIntelSourceSetEnabled(cmd.Context(), getConfig(), args[0], false, cmd.OutOrStdout())
		},
	}
	return cmd
}

func newIntelUpdateCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelUpdateOptions

	cmd := &cobra.Command{
		Use:   "update [source-id]",
		Short: "Synchronize threat intelligence feeds",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				opts.SourceID = args[0]
			}
			return cli.RunIntelUpdate(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")
	return cmd
}

func newIntelSearchCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelSearchOptions

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search local intelligence indicators",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Query = args[0]
			return cli.RunIntelSearch(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().IntVar(&opts.Limit, "limit", 20, "Maximum number of indicators to display")
	cmd.Flags().IntVar(&opts.Offset, "offset", 0, "Number of indicators to skip (pagination)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")
	return cmd
}

func newIntelImportCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelImportOptions

	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import indicators from a file or bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.FilePath = args[0]
			return cli.RunIntelImport(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&opts.SourceID, "source-id", "bundle-import", "Source identifier to assign to imported indicators")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "", "Format override ('json' or 'csv'; auto-detected by default)")
	return cmd
}

func newIntelExportCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelExportOptions

	cmd := &cobra.Command{
		Use:   "export <file>",
		Short: "Export local indicators to an intelligence bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.OutputPath = args[0]
			return cli.RunIntelExport(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&opts.Category, "category", "", "Filter exported indicators by threat category")
	cmd.Flags().IntVar(&opts.MinConfidence, "min-confidence", 0, "Minimum confidence threshold (0-100)")
	return cmd
}

func newIntelPruneCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.IntelPruneOptions
	var beforeStr string

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove expired intelligence records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if beforeStr != "" {
				t, err := time.Parse(time.RFC3339, beforeStr)
				if err != nil {
					return cli.NewExitError(cli.ExitInvalidUsage, "invalid --before timestamp (expected RFC3339): %v", err)
				}
				opts.Before = t
			}
			return cli.RunIntelPrune(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Preview the number of expired records that would be removed without deleting")
	cmd.Flags().StringVar(&beforeStr, "before", "", "Prune indicators expired before this timestamp (RFC3339, default: now)")
	return cmd
}
