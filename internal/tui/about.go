package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/cli"
)

// RenderAbout renders the About & Integrity information screen.
func RenderAbout(styles Styles, activeTab int, scrollOffset int, width int) string {
	contentWidth := width - 6
	if contentWidth < 50 {
		contentWidth = 50
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder

	// Header
	title := styles.Title.Render("ABOUT BOUCLIER")
	sub := styles.Subtitle.Render("Workstation architecture, licensing, third-party notices, and security")
	b.WriteString(fmt.Sprintf("%s\n%s\n\n", title, sub))

	// Tab header
	tabs := []string{"[1] Build Metadata", "[2] MIT License", "[3] Third-Party Notices", "[4] Security & Integrity"}
	var tabLine strings.Builder
	for i, t := range tabs {
		if i == activeTab {
			tabLine.WriteString(styles.TabActive.Render(t) + " ")
		} else {
			tabLine.WriteString(styles.TabInactive.Render(t) + " ")
		}
	}
	b.WriteString(tabLine.String() + "\n\n")

	// Tab contents
	var cardText strings.Builder

	switch activeTab {
	case 0:
		// Build Metadata
		meta := cli.GetBuildMetadata()
		cardText.WriteString(styles.CardTitle.Render("Product & Runtime Specification") + "\n\n")
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Product:"), "Bouclier | Security Intelligence Workstation"))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Version:"), "v"+meta.Version))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Git Commit:"), meta.Commit))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Build Time:"), meta.Built))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Go Runtime:"), meta.GoVersion))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Target OS/Arch:"), meta.Platform))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Database Engine:"), "Pure Go SQLite (modernc.org/sqlite, zero CGO)"))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Schemas:"), "bouclier-risk/v1, bouclier-intel-bundle/v1"))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("Repository:"), "https://github.com/1steve78/bouclier"))

	case 1:
		// MIT License
		cardText.WriteString(styles.CardTitle.Render("MIT License") + "\n\n")
		cardText.WriteString(styles.Bold.Render("Copyright (c) 2026 1steve78 and The Bouclier Authors\n\n"))
		licenseBody := `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`
		cardText.WriteString(styles.Muted.Render(licenseBody) + "\n")

	case 2:
		// Third-Party Notices
		cardText.WriteString(styles.CardTitle.Render("Third-Party Open-Source Notices") + "\n\n")
		cardText.WriteString("Bouclier is built with 38 open-source Go libraries:\n\n")
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("18 Dependencies:"), "MIT License (Cobra, Lip Gloss, Bubble Tea, Bubbles, go-isatty)"))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("16 Dependencies:"), "BSD-3-Clause (golang.org/x/crypto, golang.org/x/net, golang.org/x/sys)"))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n", styles.Bold.Render("3 Dependencies:"), "Apache-2.0 License"))
		cardText.WriteString(fmt.Sprintf("• %-20s %s\n\n", styles.Bold.Render("1 Dependency:"), "Public Domain (modernc.org/libc)"))
		cardText.WriteString(styles.Muted.Render("Full preserved copyright notices and licenses are shipped in THIRD_PARTY_NOTICES.md."))

	case 3:
		// Security & Responsible Disclosure
		cardText.WriteString(styles.CardTitle.Render("Security Guarantees & Vulnerability Disclosure") + "\n\n")
		cardText.WriteString(fmt.Sprintf("• %s DNS rebinding defense, socket-pinned HTTP transport, link-local & cloud metadata blocks.\n", styles.Bold.Render("Multi-Layer SSRF Defense:")))
		cardText.WriteString(fmt.Sprintf("• %s Feed auth headers persist ONLY as environment variable names, never plaintext.\n", styles.Bold.Render("Zero Plaintext Secrets:")))
		cardText.WriteString(fmt.Sprintf("• %s Loopback-bound REST API (127.0.0.1) with strict CORS and header verification.\n", styles.Bold.Render("Isolated Services:")))
		cardText.WriteString(fmt.Sprintf("• %s Maximum 10 MiB body streaming and 20s scan timeout guardrails.\n\n", styles.Bold.Render("Resource Caps:")))
		cardText.WriteString(styles.Bold.Render("Responsible Disclosure:") + "\n")
		cardText.WriteString(styles.Muted.Render("To report a security vulnerability, please open a private GitHub Security Advisory\nor email the maintainers as detailed in SECURITY.md."))
	}

	b.WriteString(styles.Card.Width(contentWidth).Render(cardText.String()))

	// Keybar
	b.WriteString("\n\n")
	keybar := styles.FormatKeybar([][2]string{
		{"1-4 / ←/→", "switch tab"},
		{"Esc / b", "dashboard"},
		{"1-7", "switch module"},
		{"/", "palette"},
		{"?", "help"},
		{"q", "quit"},
	})
	b.WriteString(keybar)

	return b.String()
}
