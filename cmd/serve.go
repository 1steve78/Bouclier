package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"bouclier/internal/api"
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/logging"
	"bouclier/internal/risk"
	"bouclier/internal/webcheck"
	"github.com/spf13/cobra"
)

func newServeCommand(getConfig func() *config.Config) *cobra.Command {
	var host string
	var port int

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Bouclier HTTP API server",
		Long: `Start the Bouclier HTTP API server.

The server exposes health, readiness, API metadata, and synchronous URL scanning.
It binds to localhost by default and shuts down gracefully on interrupt or termination.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			appConfig := getConfig()
			serverConfig := appConfig.HTTPServer
			if cmd.Flags().Changed("host") {
				serverConfig.Host = host
			}
			if cmd.Flags().Changed("port") {
				serverConfig.Port = port
			}
			if err := serverConfig.Validate(); err != nil {
				return fmt.Errorf("invalid HTTP server configuration: %w", err)
			}

			scanService := pipelineScanService{config: appConfig}
			server, err := api.NewServerWithScanService(serverConfig, loggerForCommand(cmd), scanService, appConfig.Scanner.MaxConcurrentScans)
			if err != nil {
				return err
			}
			listener, err := net.Listen("tcp", server.Addr)
			if err != nil {
				return cli.NewExitError(cli.ExitGeneralError, "listen on %s: %w", server.Addr, err)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := api.Serve(ctx, server, listener, loggerForCommand(cmd)); err != nil {
				return cli.NewExitError(cli.ExitGeneralError, "serve HTTP API: %w", err)
			}
			return nil
		},
	}

	serveCmd.Flags().StringVar(&host, "host", "", "HTTP server host (defaults to the configuration value)")
	serveCmd.Flags().IntVar(&port, "port", 0, "HTTP server port (defaults to the configuration value)")
	return serveCmd
}

type pipelineScanService struct {
	config *config.Config
}

func (s pipelineScanService) Scan(ctx context.Context, target string) (*risk.RiskAssessment, error) {
	normalized, err := heuristics.NormalizeURL(target)
	if err != nil {
		return nil, api.ErrInvalidTarget
	}
	if err := webcheck.ValidateTarget(normalized); err != nil {
		if errors.Is(err, webcheck.ErrUnsafeTarget) {
			return nil, api.ErrDestinationNotAllowed
		}
		return nil, api.ErrInvalidTarget
	}

	result, err := cli.ExecuteScanPipeline(ctx, s.config, cli.ScanOptions{Target: normalized.Normalized, NoPersist: true}, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("scan pipeline returned no result")
	}
	if result.IsSSRFBlocked {
		return nil, api.ErrDestinationNotAllowed
	}
	if result.WebResult != nil && errors.Is(result.WebResult.HTTPStatus.Err, webcheck.ErrUnsafeTarget) {
		return nil, api.ErrDestinationNotAllowed
	}
	if result.Assessment == nil {
		return nil, errors.New("scan pipeline returned no assessment")
	}
	return result.Assessment, nil
}

func loggerForCommand(cmd *cobra.Command) *slog.Logger {
	if logger, ok := logging.FromContext(cmd.Context()); ok {
		return logger
	}
	return slog.Default()
}
