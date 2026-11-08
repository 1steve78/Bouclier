package tui

import (
	"fmt"
	"strings"

	"bouclier/internal/risk"
)

// RenderCoverage renders the component coverage and limitations view.
func RenderCoverage(styles Styles, assessment *risk.RiskAssessment, width int) string {
	contentWidth := width - 4
	if contentWidth < 45 {
		contentWidth = 45
	}
	if contentWidth > 86 {
		contentWidth = 86
	}

	var b strings.Builder
	b.WriteString(styles.Title.Render("ANALYSIS COVERAGE & LIMITATIONS") + "\n")
	b.WriteString(styles.Subtitle.Render("Component execution states and assessment boundaries") + "\n\n")

	var covTable strings.Builder
	covTable.WriteString(styles.CardTitle.Render("Subsystem Coverage Breakdown") + "\n\n")

	for _, c := range assessment.AnalysisCoverage {
		stateBadge := formatCoverageState(styles, c.State)
		compName := humanizeComponentName(c.Component)
		line := fmt.Sprintf("%-28s %s", compName, stateBadge)
		if c.Detail != "" && (c.State == risk.ComponentFailed || c.State == risk.ComponentPartial) {
			line += fmt.Sprintf("\n  %s", styles.Muted.Render(c.Detail))
		}
		covTable.WriteString(line + "\n")
	}

	b.WriteString(styles.Card.Width(contentWidth).Render(covTable.String()))
	b.WriteString("\n\n")

	// Limitations & Context Card
	var limCard strings.Builder
	limCard.WriteString(styles.CardTitle.Render("Limitations & Assessment Caveats") + "\n\n")
	if len(assessment.Limitations) == 0 {
		limCard.WriteString(styles.Muted.Render("No specific operational limitations recorded for this assessment."))
	} else {
		for _, lim := range assessment.Limitations {
			limCard.WriteString(fmt.Sprintf("• %s\n", styles.Muted.Render(lim)))
		}
	}
	limCard.WriteString("\n" + styles.Bold.Render("Important Boundary:") + "\n")
	limCard.WriteString(styles.Muted.Render("Skipped or failed components do NOT imply a clean result. The score summarizes only observed indicators from components that executed successfully."))

	b.WriteString(styles.Card.Width(contentWidth).Render(limCard.String()))
	b.WriteString("\n\n")

	b.WriteString(styles.FormatKeybar([][2]string{
		{"Esc", "Back to Overview"},
	}))

	return b.String()
}

func formatCoverageState(styles Styles, state risk.ComponentState) string {
	switch state {
	case risk.ComponentCompleted:
		return styles.StageCompleted.Render("[ COMPLETED ]")
	case risk.ComponentPartial:
		return styles.StagePartial.Render("[ PARTIAL   ]")
	case risk.ComponentFailed:
		return styles.StageFailed.Render("[ FAILED    ]")
	case risk.ComponentSkipped:
		return styles.StageSkipped.Render("[ SKIPPED   ]")
	default:
		return styles.StagePending.Render(fmt.Sprintf("[ %-9s ]", strings.ToUpper(string(state))))
	}
}

func humanizeComponentName(comp string) string {
	names := map[string]string{
		"url_analysis":               "URL Structure",
		"domain_structure":           "Domain Structure",
		"registration_age":           "Registration Age",
		"tls_connection":             "TLS Connection",
		"certificate_analysis":       "Certificate Analysis",
		"ct_lookup":                  "Certificate Transparency",
		"web_http_inspection":        "HTTP Inspection",
		"web_redirect_analysis":      "Redirect Analysis",
		"web_security_headers":       "Security Headers",
		"web_cookies":                "Cookie Security",
		"web_cors":                   "CORS Policy",
		"web_html":                   "HTML Inspection",
		"web_information_disclosure": "Technology Disclosure",
	}
	if human, ok := names[comp]; ok {
		return human
	}
	parts := strings.Split(comp, "_")
	for i := range parts {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, " ")
}
