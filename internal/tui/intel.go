package tui

import (
	"fmt"
	"strings"
	"time"
)

// RenderIntel renders the interactive threat intelligence view in the TUI.
func RenderIntel(m Model) string {
	contentWidth := m.Width - 6
	if contentWidth < 30 {
		contentWidth = 30
	}
	if contentWidth > 90 {
		contentWidth = 90
	}

	var b strings.Builder

	// Title
	b.WriteString(m.Styles.Title.Render("Threat Intelligence & IOCs"))
	b.WriteString("\n\n")

	// Tabs: 0: Overview, 1: Sources, 2: Search
	tabs := []string{"[ 1 ] Overview & Health", "[ 2 ] Sources", "[ 3 ] Search Indicators"}
	var tabRow strings.Builder
	for i, tab := range tabs {
		if i == m.IntelActiveTab {
			tabRow.WriteString(m.Styles.TabActive.Render(tab) + " ")
		} else {
			tabRow.WriteString(m.Styles.TabInactive.Render(tab) + " ")
		}
	}
	b.WriteString(tabRow.String())
	b.WriteString("\n\n")

	if m.IntelUpdating {
		b.WriteString(m.Styles.MedBadge.Render(" SYNCHRONIZING FEEDS ") + " " + m.Styles.Muted.Render("Downloading and validating threat indicators...") + "\n\n")
	} else if m.IntelErr != nil {
		b.WriteString(m.Styles.ErrorText.Render("✖ "+m.IntelErr.Error()) + "\n\n")
	} else if m.IntelUpdateMsg != "" {
		b.WriteString(m.Styles.SuccessText.Render("✔ "+m.IntelUpdateMsg) + "\n\n")
	}

	switch m.IntelActiveTab {
	case 0:
		renderIntelOverview(&b, m, contentWidth)
	case 1:
		renderIntelSources(&b, m, contentWidth)
	case 2:
		renderIntelSearch(&b, m, contentWidth)
	}

	// Keybar
	b.WriteString("\n")
	var keybarItems [][2]string
	if m.IntelActiveTab == 2 {
		keybarItems = append(keybarItems, [2]string{"Enter", "Search"})
	}
	keybarItems = append(keybarItems,
		[2]string{"Tab", "Next Tab"},
		[2]string{"1-3", "Select Tab"},
	)
	if m.IntelUpdating {
		keybarItems = append(keybarItems, [2]string{"C", "Cancel Sync"})
	} else {
		keybarItems = append(keybarItems, [2]string{"U", "Update Feeds"})
	}
	keybarItems = append(keybarItems, [2]string{"Esc", "Dashboard"})
	b.WriteString(m.Styles.FormatKeybar(keybarItems))

	return b.String()
}

func renderIntelOverview(b *strings.Builder, m Model, width int) {
	var card strings.Builder
	card.WriteString(m.Styles.CardTitle.Render("Local Intelligence Database") + "\n\n")

	if m.IntelStats != nil {
		card.WriteString(fmt.Sprintf("%-28s %d\n", m.Styles.Bold.Render("Total Active Indicators:"), m.IntelStats.TotalIndicators))
		card.WriteString(fmt.Sprintf("%-28s %d (%d enabled)\n", m.Styles.Bold.Render("Configured Sources:"), m.IntelStats.TotalSources, m.IntelStats.EnabledSources))
		lastSync := "Never"
		if m.IntelStats.LastSyncTime != nil {
			lastSync = m.IntelStats.LastSyncTime.Format(time.RFC3339) + fmt.Sprintf(" (%s)", m.IntelStats.LastSyncStatus)
		}
		card.WriteString(fmt.Sprintf("%-28s %s\n", m.Styles.Bold.Render("Last Synchronization:"), lastSync))

		if m.IntelStats.HasSyncFailures {
			card.WriteString("\n" + m.Styles.HighBadge.Render(" ATTENTION ") + " Last sync encountered errors: " + m.IntelStats.LastErrorMessage + "\n")
		} else {
			card.WriteString(fmt.Sprintf("%-28s %s\n", m.Styles.Bold.Render("Database Status:"), m.Styles.SuccessText.Render("Healthy / Ready")))
		}
	} else {
		card.WriteString(m.Styles.Muted.Render("Threat intelligence database status not loaded.\n"))
	}

	card.WriteString("\n" + m.Styles.Muted.Render("Press [ U ] to trigger an asynchronous feed synchronization.\nAll matching runs 100% locally during scans without remote feed downloads."))

	b.WriteString(m.Styles.Card.Width(width).Render(card.String()))
}

func renderIntelSources(b *strings.Builder, m Model, width int) {
	var card strings.Builder
	card.WriteString(m.Styles.CardTitle.Render("Registered Feed Sources") + "\n\n")

	if len(m.IntelSources) == 0 {
		card.WriteString(m.Styles.Muted.Render("No threat intelligence sources registered yet.\nUse 'bouclier intel import <file>' or CLI commands to add feeds."))
	} else {
		card.WriteString(fmt.Sprintf("%-16s %-24s %-12s %-8s\n", "ID", "NAME", "TYPE", "STATUS"))
		card.WriteString(strings.Repeat("-", width-8) + "\n")
		for _, s := range m.IntelSources {
			statusStr := m.Styles.SuccessText.Render("Enabled")
			if !s.Enabled {
				statusStr = m.Styles.Muted.Render("Disabled")
			}
			card.WriteString(fmt.Sprintf("%-16s %-24s %-12s %-8s\n",
				s.ID, truncateStr(s.Name, 24), s.ProviderType, statusStr))
		}
	}

	b.WriteString(m.Styles.Card.Width(width).Render(card.String()))
}

func renderIntelSearch(b *strings.Builder, m Model, width int) {
	var card strings.Builder
	card.WriteString(m.Styles.CardTitle.Render("Indicator Search") + "\n\n")
	card.WriteString(m.IntelSearchInput.View() + "\n\n")

	if len(m.IntelSearchResults) > 0 {
		card.WriteString(fmt.Sprintf("%-8s %-28s %-16s %-10s %-6s\n", "TYPE", "VALUE", "CATEGORY", "SEVERITY", "CONF"))
		card.WriteString(strings.Repeat("-", width-8) + "\n")
		for _, ind := range m.IntelSearchResults {
			card.WriteString(fmt.Sprintf("%-8s %-28s %-16s %-10s %3d%%\n",
				ind.Type, truncateStr(ind.Value, 28), ind.Category, ind.Severity, ind.Confidence))
		}
	} else if m.IntelSearchInput.Value() != "" {
		card.WriteString(m.Styles.Muted.Render("No active indicators found matching query."))
	} else {
		card.WriteString(m.Styles.Muted.Render("Type a domain, URL, IP, or threat category and press Enter to search."))
	}

	b.WriteString(m.Styles.Card.Width(width).Render(card.String()))
}

func truncateStr(s string, max int) string {
	if len(s) > max && max > 3 {
		return s[:max-3] + "..."
	}
	return s
}
