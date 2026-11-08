package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"bouclier/internal/config"
	"bouclier/internal/mcpserver"
	"bouclier/internal/storage"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func newMCPCommand(getConfig func() *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start the Bouclier MCP server over stdio",
		Long: `Start the Bouclier Model Context Protocol server using newline-delimited JSON-RPC on stdin/stdout.
Configure this command as an MCP server in your client. Diagnostic output is sent to stderr.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := getConfig()
			repo, err := storage.Open(cfg.Storage.DatabasePath)
			if err != nil {
				return fmt.Errorf("open local MCP storage: %w", err)
			}
			defer func() {
				if err := repo.Close(); err != nil {
					loggerForCommand(cmd).Error("close MCP storage", "error", err)
				}
			}()

			server, err := mcpserver.New(cfg, repo)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("run MCP stdio server: %w", err)
			}
			return nil
		},
	}
}
