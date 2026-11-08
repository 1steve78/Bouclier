package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"bouclier/internal/api"
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/logging"
	"github.com/spf13/cobra"
)

func newServeCommand(getConfig func() *config.Config) *cobra.Command {
	var host string
	var port int

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Bouclier HTTP API server",
		Long: `Start the Bouclier HTTP API server.

The initial server exposes only health, readiness, and API metadata endpoints.
It binds to localhost by default and shuts down gracefully on interrupt or termination.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverConfig := getConfig().HTTPServer
			if cmd.Flags().Changed("host") {
				serverConfig.Host = host
			}
			if cmd.Flags().Changed("port") {
				serverConfig.Port = port
			}
			if err := serverConfig.Validate(); err != nil {
				return fmt.Errorf("invalid HTTP server configuration: %w", err)
			}

			server, err := api.NewServer(serverConfig, loggerForCommand(cmd))
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

func loggerForCommand(cmd *cobra.Command) *slog.Logger {
	if logger, ok := logging.FromContext(cmd.Context()); ok {
		return logger
	}
	return slog.Default()
}
