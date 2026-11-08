package cmd

import (
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"github.com/spf13/cobra"
)

func newScanCommand(getConfig func() *config.Config) *cobra.Command {
	var opts cli.ScanOptions
	var failOnRisk int

	scanCmd := &cobra.Command{
		Use:   "scan <url>",
		Short: "Scan a website URL for phishing indicators and security weaknesses",
		Long: `Perform an end-to-end security assessment of a target URL.
Aggregates URL structure heuristics, domain analysis, TLS certificates,
and passive website security headers into an explainable, unified risk assessment.

Examples:
  bouclier scan https://example.com
  bouclier scan https://example.com --format json
  bouclier scan https://example.com --format markdown --output report.md
  bouclier scan https://example.com --no-ct --timeout 15s
  bouclier scan https://example.com --verbose`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Target = args[0]
			if cmd.Flags().Changed("fail-on-risk") {
				opts.FailOnRisk = &failOnRisk
			}
			cfg := getConfig()
			return cli.RunScan(cmd.Context(), cfg, opts, cmd.OutOrStdout())
		},
	}

	scanCmd.Flags().StringVarP(&opts.Format, "format", "f", "terminal", "Output format (terminal, json, markdown)")
	scanCmd.Flags().StringVarP(&opts.Output, "output", "o", "", "Write report to the specified file")
	scanCmd.Flags().DurationVar(&opts.Timeout, "timeout", 0, "Override effective scan timeout (e.g. 15s, 1m)")
	scanCmd.Flags().BoolVar(&opts.NoCT, "no-ct", false, "Disable optional Certificate Transparency analysis")
	scanCmd.Flags().StringVar(&opts.CTScope, "ct-scope", "exact", "Certificate Transparency query scope (exact, registrable)")
	scanCmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "Display diagnostic details")
	scanCmd.Flags().BoolVarP(&opts.Quiet, "quiet", "q", false, "Suppress nonessential informational output")
	scanCmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable terminal colors")
	scanCmd.Flags().IntVar(&failOnRisk, "fail-on-risk", -1, "Exit with code 5 if risk score reaches or exceeds this threshold (0-100)")

	return scanCmd
}
