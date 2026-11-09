package tui

import (
	"fmt"
	"net/url"
	"strings"

	"bouclier/internal/config"
)

// RenderConfig renders the Configuration Inspector screen.
func RenderConfig(styles Styles, cfg *config.Config, width int) string {
	contentWidth := width - 6
	if contentWidth < 50 {
		contentWidth = 50
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder

	// Header
	title := styles.Title.Render("CONFIGURATION INSPECTOR")
	sub := styles.Subtitle.Render("Active runtime parameters & subsystem configuration")
	b.WriteString(fmt.Sprintf("%s\n%s\n\n", title, sub))

	if cfg == nil {
		b.WriteString(styles.Muted.Render("No active configuration loaded.\n"))
		return b.String()
	}

	// 1. Application & Scanner
	var col1 strings.Builder
	col1.WriteString(styles.CardTitle.Render("Application & Engine") + "\n\n")
	col1.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Name:"), cfg.Application.Name))
	col1.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Version:"), cfg.Application.Version))
	col1.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Environment:"), cfg.Application.Environment))
	col1.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("User-Agent:"), cfg.Scanner.UserAgent))
	col1.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("HTTP Timeout:"), cfg.Scanner.HTTPTimeout))
	col1.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("TLS Timeout:"), cfg.Scanner.TLSHandshakeTimeout))
	col1.WriteString(fmt.Sprintf("• %-22s %d\n", styles.Bold.Render("Max Redirects:"), cfg.Scanner.MaxRedirects))
	col1.WriteString(fmt.Sprintf("• %-22s %d\n", styles.Bold.Render("Max Concurrent:"), cfg.Scanner.MaxConcurrentScans))
	b.WriteString(styles.Card.Width(contentWidth).Render(col1.String()))
	b.WriteString("\n\n")

	// 2. Storage & Threat Intelligence
	var col2 strings.Builder
	col2.WriteString(styles.CardTitle.Render("Storage & Threat Intelligence") + "\n\n")
	col2.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Database Path:"), cfg.Storage.DatabasePath))
	col2.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Cache TTL:"), cfg.Storage.CacheTTL))
	col2.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Feed Interval:"), cfg.ThreatIntel.FeedUpdateInterval))

	// Redact sensitive feed URLs
	var sanitizedFeeds []string
	for _, feed := range cfg.ThreatIntel.FeedURLs {
		sanitizedFeeds = append(sanitizedFeeds, redactURLSecrets(feed))
	}
	if len(sanitizedFeeds) == 0 {
		col2.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Default Feeds:"), "None configured in file"))
	} else {
		col2.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Feed URLs:"), strings.Join(sanitizedFeeds, ", ")))
	}
	b.WriteString(styles.Card.Width(contentWidth).Render(col2.String()))
	b.WriteString("\n\n")

	// 3. HTTP Server & Logging & AI
	var col3 strings.Builder
	col3.WriteString(styles.CardTitle.Render("HTTP API, Logging & AI") + "\n\n")
	col3.WriteString(fmt.Sprintf("• %-22s %s:%d\n", styles.Bold.Render("API Address:"), cfg.HTTPServer.Host, cfg.HTTPServer.Port))
	col3.WriteString(fmt.Sprintf("• %-22s %s (read) / %s (write)\n", styles.Bold.Render("Timeouts:"), cfg.HTTPServer.ReadTimeout, cfg.HTTPServer.WriteTimeout))
	col3.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("Max Scan Duration:"), cfg.HTTPServer.MaxScanDuration))
	col3.WriteString(fmt.Sprintf("• %-22s %s (structured: %t)\n", styles.Bold.Render("Logging Level:"), cfg.Logging.Level, cfg.Logging.Structured))

	aiStatus := "Disabled"
	if cfg.AI.Enabled {
		aiStatus = fmt.Sprintf("Enabled (%s @ %s)", cfg.AI.Ollama.Model, cfg.AI.Ollama.BaseURL)
	}
	col3.WriteString(fmt.Sprintf("• %-22s %s\n", styles.Bold.Render("AI Explanations:"), aiStatus))
	b.WriteString(styles.Card.Width(contentWidth).Render(col3.String()))

	// Key bar
	b.WriteString("\n\n")
	keybar := styles.FormatKeybar([][2]string{
		{"Esc / b", "dashboard"},
		{"1-7", "switch module"},
		{"/", "palette"},
		{"?", "help"},
		{"q", "quit"},
	})
	b.WriteString(keybar)

	return b.String()
}

// redactURLSecrets sanitizes any credentials present in a URL.
func redactURLSecrets(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.User != nil {
		if _, hasPass := parsed.User.Password(); hasPass {
			parsed.User = url.UserPassword(parsed.User.Username(), "REDACTED")
		}
	}
	q := parsed.Query()
	for _, key := range []string{"token", "key", "secret", "auth", "api_key", "apikey"} {
		if q.Has(key) {
			q.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
