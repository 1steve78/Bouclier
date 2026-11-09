package tui

import (
	"fmt"
	"strings"
	"time"
)

// RenderServices renders the Services Management screen (REST API Daemon & MCP Guidance).
func RenderServices(
	styles Styles,
	apiRunning bool,
	apiPort int,
	apiStarted time.Time,
	apiErr error,
	width int,
) string {
	contentWidth := width - 6
	if contentWidth < 50 {
		contentWidth = 50
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder

	// Header
	title := styles.Title.Render("API & MCP SERVICES")
	sub := styles.Subtitle.Render("Manage in-process background REST server and view MCP tool catalog")
	b.WriteString(fmt.Sprintf("%s\n%s\n\n", title, sub))

	// 1. REST API Daemon Card
	var apiText strings.Builder
	apiText.WriteString(styles.CardTitle.Render("Loopback REST API Server") + "\n\n")

	if apiRunning {
		statusBadge := styles.SuccessText.Render("● RUNNING")
		uptime := time.Since(apiStarted).Truncate(time.Second)
		apiText.WriteString(fmt.Sprintf("• Status:     %s on %s\n", statusBadge, styles.Bold.Render(fmt.Sprintf("http://127.0.0.1:%d", apiPort))))
		apiText.WriteString(fmt.Sprintf("• Uptime:     %s (started %s)\n", uptime, apiStarted.Format("15:04:05")))
		apiText.WriteString(fmt.Sprintf("• Security:   %s\n\n", styles.Muted.Render("Strict loopback binding (SSRF-protected, non-routable)")))
		apiText.WriteString(fmt.Sprintf("Press %s to stop the REST API server.\n\n", styles.Key.Render("[ X ]")))
	} else {
		statusBadge := styles.Muted.Render("○ STOPPED")
		apiText.WriteString(fmt.Sprintf("• Status:     %s (default port: %d)\n", statusBadge, apiPort))
		if apiErr != nil {
			apiText.WriteString(fmt.Sprintf("• Notice:     %s\n", styles.ErrorText.Render(apiErr.Error())))
		}
		apiText.WriteString(fmt.Sprintf("Press %s to start the in-process REST API server on loopback.\n\n", styles.Key.Render("[ S ]")))
	}

	apiText.WriteString(styles.Bold.Render("Available Endpoints:") + "\n")
	apiText.WriteString(fmt.Sprintf("  %-20s %s\n", "GET  /health", styles.Muted.Render("Liveness & readiness probe")))
	apiText.WriteString(fmt.Sprintf("  %-20s %s\n", "POST /api/v1/scan", styles.Muted.Render("Execute synchronous assessment")))
	apiText.WriteString(fmt.Sprintf("  %-20s %s\n", "GET  /api/v1/history", styles.Muted.Render("Query past scans & findings")))
	apiText.WriteString(fmt.Sprintf("  %-20s %s\n", "GET  /api/v1/intel/stats", styles.Muted.Render("Threat indicators overview")))
	apiText.WriteString(fmt.Sprintf("  %-20s %s\n", "POST /api/v1/intel/sync", styles.Muted.Render("Trigger feed synchronization")))

	if apiRunning {
		b.WriteString(styles.ActiveCard.Width(contentWidth).Render(apiText.String()))
	} else {
		b.WriteString(styles.Card.Width(contentWidth).Render(apiText.String()))
	}
	b.WriteString("\n\n")

	// 2. MCP Server Guidance Card
	var mcpText strings.Builder
	mcpText.WriteString(styles.CardTitle.Render("Model Context Protocol (MCP) Server") + "\n\n")
	mcpText.WriteString(styles.Bold.Render("Stdio Isolation Note:") + "\n")
	mcpText.WriteString(styles.Muted.Render("MCP uses stdin/stdout for JSON-RPC 2.0 communication. To prevent collisions\nwith terminal graphics, run MCP as a dedicated subprocess:") + "\n\n")
	mcpText.WriteString(fmt.Sprintf("  %s\n\n", styles.Bold.Render("$ bouclier mcp")))

	mcpText.WriteString(styles.Bold.Render("Client Configuration (Claude Desktop / Cursor):") + "\n")
	snippet := "{\n  \"mcpServers\": {\n    \"bouclier\": {\n      \"command\": \"bouclier\",\n      \"args\": [\"mcp\"]\n    }\n  }\n}"
	mcpText.WriteString(styles.Muted.Render(snippet) + "\n\n")

	mcpText.WriteString(styles.Bold.Render("Catalog of 7 Exposed MCP Tools:") + "\n")
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "scan_url", styles.Muted.Render("Assess website phishing & security")))
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "get_scan", styles.Muted.Render("Retrieve full report by scan ID")))
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "list_scans", styles.Muted.Render("Filter historical scan assessments")))
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "search_intel", styles.Muted.Render("Query threat intelligence database")))
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "get_intel_stats", styles.Muted.Render("Indicator counts and source health")))
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "sync_intel_feeds", styles.Muted.Render("Trigger background feed updates")))
	mcpText.WriteString(fmt.Sprintf("  • %-20s %s\n", "get_config", styles.Muted.Render("Inspect active scanner parameters")))

	b.WriteString(styles.Card.Width(contentWidth).Render(mcpText.String()))

	// Keybar
	b.WriteString("\n\n")
	keybar := styles.FormatKeybar([][2]string{
		{"s", "start API server"},
		{"x", "stop API server"},
		{"Esc / b", "dashboard"},
		{"1-7", "switch module"},
		{"/", "palette"},
		{"?", "help"},
		{"q", "quit"},
	})
	b.WriteString(keybar)

	return b.String()
}
