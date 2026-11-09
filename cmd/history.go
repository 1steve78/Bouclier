package cmd

import (
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"github.com/spf13/cobra"
)

func newHistoryCommand(getConfig func() *config.Config) *cobra.Command {
	historyCmd := &cobra.Command{
		Use:   "history",
		Short: "Inspect and manage saved scan assessments",
		Long: `Inspect and manage historical scan assessments stored in local SQLite database.
Allows browsing past scans, viewing full risk reports, and managing retained history.

Examples:
  bouclier history list
  bouclier history list --target example.com
  bouclier history list --classification critical
  bouclier history correlate example.com --format markdown --output trend.md
  bouclier history anchor 7a9b2c3d --rpc-url https://rpc.example --contract-address 0x... --risk-level 1
  bouclier history verify 7a9b2c3d --rpc-url https://rpc.example --contract-address 0x...
  bouclier history show 7a9b2c3d
  bouclier history show 7a9b2c3d --format markdown --output report.md
  bouclier history delete 7a9b2c3d`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default to listing history if invoked without subcommands
			opts := cli.HistoryListOptions{
				Limit: 20,
			}
			return cli.RunHistoryList(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}

	historyCmd.AddCommand(newHistoryListCommand(getConfig))
	historyCmd.AddCommand(newHistoryShowCommand(getConfig))
	historyCmd.AddCommand(newHistoryCorrelateCommand(getConfig))
	historyCmd.AddCommand(newHistoryAnchorCommand(getConfig))
	historyCmd.AddCommand(newHistoryVerifyAnchorCommand(getConfig))
	historyCmd.AddCommand(newHistoryDeleteCommand(getConfig))

	return historyCmd
}

func newHistoryListCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.HistoryListOptions
	var minScore, maxScore int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List previous scan assessments",
		Long:  "Displays a tabular or JSON list of previously executed website security scans.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("min-score") {
				opts.MinScore = &minScore
			}
			if cmd.Flags().Changed("max-score") {
				opts.MaxScore = &maxScore
			}
			cfg := getConfig()
			return cli.RunHistoryList(cmd.Context(), cfg, opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().IntVar(&opts.Limit, "limit", 20, "Maximum number of scans to display")
	cmd.Flags().IntVar(&opts.Offset, "offset", 0, "Number of scans to skip (for pagination)")
	cmd.Flags().StringVar(&opts.Target, "target", "", "Filter scans by target domain or URL substring")
	cmd.Flags().StringVar(&opts.Classification, "classification", "", "Filter by risk tier (low, guarded, elevated, high, critical)")
	cmd.Flags().IntVar(&minScore, "min-score", -1, "Filter by minimum overall risk score (0-100)")
	cmd.Flags().IntVar(&maxScore, "max-score", -1, "Filter by maximum overall risk score (0-100)")
	cmd.Flags().StringVar(&opts.Status, "status", "", "Filter by scan status (completed, partial, failed, cancelled)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")

	return cmd
}

func newHistoryShowCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.HistoryShowOptions

	cmd := &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Display full assessment report for a historical scan",
		Long: `Display the detailed risk assessment findings and analysis coverage for a previous scan.
Supports terminal, JSON, and Markdown formats without triggering new network scans.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ID = args[0]
			cfg := getConfig()
			return cli.RunHistoryShow(cmd.Context(), cfg, opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json, markdown)")
	cmd.Flags().StringVarP(&opts.Output, "output", "o", "", "Write report output to specified file")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable color in terminal output")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "Display full technical findings details")

	return cmd
}

func newHistoryCorrelateCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.HistoryCorrelateOptions
	cmd := &cobra.Command{
		Use:   "correlate <target>",
		Short: "Compare reports over time and render a risk trend graph",
		Long: `Correlate saved reports for the same hostname. Shows score trend, finding changes,
and supports terminal, JSON, or Markdown output.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Target = args[0]
			return cli.RunHistoryCorrelate(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().IntVar(&opts.Limit, "limit", 100, "Maximum number of reports to compare (up to 500)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json, markdown)")
	cmd.Flags().StringVarP(&opts.Output, "output", "o", "", "Write correlation report to a file")
	return cmd
}

func newHistoryAnchorCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.ReportAnchorOptions
	cmd := &cobra.Command{
		Use:   "anchor <scan-id>",
		Short: "Commit a reviewed report hash to an EVM registry",
		Long: `Submit only the stored SHA-256 report hash and a manually selected risk level to a
ThreatRegistry-compatible EVM contract. The report contents and target are not sent on-chain.
The signing key must be provided through BOUCLIER_EVM_PRIVATE_KEY or the environment variable
named by --private-key-env.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ScanID = args[0]
			return cli.RunHistoryAnchor(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.RPCURL, "rpc-url", "", "EVM JSON-RPC endpoint URL")
	cmd.Flags().StringVar(&opts.ContractAddress, "contract-address", "", "deployed ThreatRegistry contract address")
	cmd.Flags().IntVar(&opts.RiskLevel, "risk-level", 0, "reviewer-selected registry level: 1 suspicious, 2 high risk, or 3 confirmed malicious")
	cmd.Flags().StringVar(&opts.PrivateKeyEnv, "private-key-env", "BOUCLIER_EVM_PRIVATE_KEY", "environment variable containing the EVM signing key")
	return cmd
}

func newHistoryVerifyAnchorCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.ReportVerifyOptions
	cmd := &cobra.Command{
		Use:   "verify <scan-id>",
		Short: "Verify a saved report hash against an EVM registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ScanID = args[0]
			return cli.RunHistoryVerifyAnchor(cmd.Context(), getConfig(), opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.RPCURL, "rpc-url", "", "EVM JSON-RPC endpoint URL")
	cmd.Flags().StringVar(&opts.ContractAddress, "contract-address", "", "deployed ThreatRegistry contract address")
	return cmd
}

func newHistoryDeleteCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.HistoryDeleteOptions

	cmd := &cobra.Command{
		Use:   "delete <scan-id>",
		Short: "Delete a scan assessment from local history",
		Long:  "Permanently removes the specified scan record and its serialized report from local SQLite storage.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ID = args[0]
			cfg := getConfig()
			return cli.RunHistoryDelete(cmd.Context(), cfg, opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().BoolVarP(&opts.Yes, "yes", "y", false, "Bypass interactive confirmation prompt")

	return cmd
}
