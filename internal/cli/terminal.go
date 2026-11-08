package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"bouclier/internal/risk"
)

type TerminalOptions struct {
	NoColor bool
	Verbose bool
	Quiet   bool
}

type colorPalette struct {
	enabled bool
}

func newColorPalette(noColor bool) colorPalette {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return colorPalette{enabled: false}
	}
	return colorPalette{enabled: true}
}

func (c colorPalette) wrap(code, s string) string {
	if !c.enabled || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func (c colorPalette) bold(s string) string        { return c.wrap("1", s) }
func (c colorPalette) dim(s string) string         { return c.wrap("2", s) }
func (c colorPalette) red(s string) string         { return c.wrap("31", s) }
func (c colorPalette) green(s string) string       { return c.wrap("32", s) }
func (c colorPalette) yellow(s string) string      { return c.wrap("33", s) }
func (c colorPalette) blue(s string) string        { return c.wrap("34", s) }
func (c colorPalette) magenta(s string) string     { return c.wrap("35", s) }
func (c colorPalette) cyan(s string) string        { return c.wrap("36", s) }
func (c colorPalette) boldRed(s string) string     { return c.wrap("1;31", s) }
func (c colorPalette) boldGreen(s string) string   { return c.wrap("1;32", s) }
func (c colorPalette) boldYellow(s string) string  { return c.wrap("1;33", s) }
func (c colorPalette) boldMagenta(s string) string { return c.wrap("1;35", s) }
func (c colorPalette) boldCyan(s string) string    { return c.wrap("1;36", s) }

func (c colorPalette) scoreColor(class risk.RiskClass) func(string) string {
	switch class {
	case risk.RiskCritical:
		return c.boldRed
	case risk.RiskHigh:
		return c.boldMagenta
	case risk.RiskElevated:
		return c.boldYellow
	case risk.RiskGuarded:
		return c.boldCyan
	case risk.RiskLow:
		return c.boldGreen
	default:
		return c.bold
	}
}

func (c colorPalette) severityColor(sev risk.Severity) func(string) string {
	switch sev {
	case risk.SeverityCritical:
		return c.boldRed
	case risk.SeverityHigh:
		return c.magenta
	case risk.SeverityMedium:
		return c.yellow
	case risk.SeverityLow:
		return c.cyan
	case risk.SeverityInformational:
		return c.dim
	default:
		return func(s string) string { return s }
	}
}

func (c colorPalette) coverageColor(state risk.ComponentState) func(string) string {
	switch state {
	case risk.ComponentCompleted:
		return c.green
	case risk.ComponentPartial:
		return c.yellow
	case risk.ComponentFailed:
		return c.red
	case risk.ComponentSkipped, risk.ComponentNoResults:
		return c.dim
	default:
		return c.dim
	}
}

// RenderTerminal writes the formatted terminal report to writer w.
func RenderTerminal(w io.Writer, a *risk.RiskAssessment, opts TerminalOptions) error {
	if a == nil {
		return fmt.Errorf("render terminal: assessment is nil")
	}
	text := FormatTerminal(a, opts)
	_, err := fmt.Fprint(w, text)
	return err
}

// FormatTerminal generates the human-readable text for terminal display.
func FormatTerminal(a *risk.RiskAssessment, opts TerminalOptions) string {
	if a == nil {
		return ""
	}
	cp := newColorPalette(opts.NoColor)
	var b strings.Builder

	// Header Banner
	b.WriteString("\n")
	b.WriteString(cp.boldCyan("  BOUCLIER") + "\n")
	b.WriteString(cp.bold("  Website Security Assessment") + "\n\n")

	// Target & Metadata
	target := a.Target
	if target == "" {
		target = "unknown"
	}
	b.WriteString(fmt.Sprintf("  Target:       %s\n", cp.bold(target)))
	if !a.AnalyzedAt.IsZero() {
		b.WriteString(fmt.Sprintf("  Analyzed at:  %s\n", a.AnalyzedAt.UTC().Format(time.RFC3339)))
	}
	if a.PolicyID != "" {
		b.WriteString(fmt.Sprintf("  Policy:       %s v%s\n", a.PolicyID, a.PolicyVersion))
	}
	b.WriteString("\n")

	// Risk Score & Classification
	b.WriteString(cp.bold("  Risk Score\n"))
	b.WriteString("  ----------------\n")
	scoreFn := cp.scoreColor(a.Classification)
	b.WriteString(fmt.Sprintf("  %s\n", scoreFn(fmt.Sprintf("%d / 100", a.OverallScore))))
	b.WriteString(fmt.Sprintf("  %s\n\n", scoreFn(strings.ToUpper(string(a.Classification)))))

	// Severity Counts
	b.WriteString(cp.bold("  Findings\n"))
	b.WriteString("  --------\n")
	counts := map[risk.Severity]int{
		risk.SeverityCritical:      0,
		risk.SeverityHigh:          0,
		risk.SeverityMedium:        0,
		risk.SeverityLow:           0,
		risk.SeverityInformational: 0,
	}
	for _, sc := range a.SeverityCounts {
		counts[sc.Severity] = sc.Count
	}
	b.WriteString(fmt.Sprintf("  Critical:      %s\n", cp.severityColor(risk.SeverityCritical)(fmt.Sprintf("%d", counts[risk.SeverityCritical]))))
	b.WriteString(fmt.Sprintf("  High:          %s\n", cp.severityColor(risk.SeverityHigh)(fmt.Sprintf("%d", counts[risk.SeverityHigh]))))
	b.WriteString(fmt.Sprintf("  Medium:        %s\n", cp.severityColor(risk.SeverityMedium)(fmt.Sprintf("%d", counts[risk.SeverityMedium]))))
	b.WriteString(fmt.Sprintf("  Low:           %s\n", cp.severityColor(risk.SeverityLow)(fmt.Sprintf("%d", counts[risk.SeverityLow]))))
	b.WriteString(fmt.Sprintf("  Informational: %s\n", cp.severityColor(risk.SeverityInformational)(fmt.Sprintf("%d", counts[risk.SeverityInformational]))))
	if a.UnclassifiedCount > 0 {
		b.WriteString(fmt.Sprintf("  Unclassified:  %s\n", cp.dim(fmt.Sprintf("%d", a.UnclassifiedCount))))
	}
	b.WriteString("\n")

	// Top Risk Factors
	b.WriteString(cp.bold("  Top Risk Factors\n"))
	b.WriteString("  ----------------\n")
	if len(a.TopRiskFactors) == 0 {
		b.WriteString("  No score-contributing risk factors observed.\n\n")
	} else {
		for _, rf := range a.TopRiskFactors {
			sevTag := fmt.Sprintf("[%s]", strings.ToUpper(string(rf.Finding.Severity)))
			sevFormatted := cp.severityColor(rf.Finding.Severity)(fmt.Sprintf("%-8s", sevTag))
			pts := cp.bold(fmt.Sprintf("+%-2d pts", rf.Contribution))
			b.WriteString(fmt.Sprintf("  %s %s  %s\n", sevFormatted, pts, rf.Finding.Title))
		}
		b.WriteString("\n")
	}

	// In Quiet mode, stop here with a compact overview
	if opts.Quiet {
		return b.String()
	}

	// Analysis Coverage
	b.WriteString(cp.bold("  Analysis Coverage\n"))
	b.WriteString("  -----------------\n")
	if len(a.AnalysisCoverage) == 0 {
		b.WriteString("  No component coverage reported.\n\n")
	} else {
		for _, cov := range a.AnalysisCoverage {
			name := formatComponentName(cov.Component)
			stateStr := strings.ToUpper(string(cov.State)[:1]) + string(cov.State)[1:]
			stateFormatted := cp.coverageColor(cov.State)(fmt.Sprintf("%-12s", stateStr))
			detail := ""
			if cov.Detail != "" {
				detail = " " + cp.dim("("+cov.Detail+")")
			}
			b.WriteString(fmt.Sprintf("  %-28s %s%s\n", name, stateFormatted, detail))
		}
		b.WriteString("\n")
	}

	// Detailed Findings
	b.WriteString(cp.bold(fmt.Sprintf("  Detailed Findings (%d)\n", len(a.Findings))))
	b.WriteString("  ----------------------\n")
	if len(a.Findings) == 0 {
		b.WriteString("  No findings observed in the analysis that ran.\n\n")
	} else {
		for i, f := range a.Findings {
			sevLabel := strings.ToUpper(string(f.Severity))
			if f.Classification == risk.FindingUnclassified {
				sevLabel = "UNCLASSIFIED"
			}
			header := fmt.Sprintf("  %d. [%s] %s", i+1, sevLabel, f.Title)
			b.WriteString(cp.bold(header) + "\n")
			b.WriteString(fmt.Sprintf("     Code:        %s\n", f.Code))
			if f.Category != "" {
				b.WriteString(fmt.Sprintf("     Category:    %s\n", f.Category))
			}
			if f.ScoreImpact > 0 {
				b.WriteString(fmt.Sprintf("     Impact:      %s\n", cp.bold(fmt.Sprintf("+%d points", f.ScoreImpact))))
			} else {
				b.WriteString(fmt.Sprintf("     Impact:      %s\n", cp.dim("0 points (unscored)")))
			}
			if len(f.Sources) > 0 {
				b.WriteString(fmt.Sprintf("     Source:      %s\n", strings.Join(f.Sources, ", ")))
			}
			if f.Description != "" {
				b.WriteString(fmt.Sprintf("     Description: %s\n", f.Description))
			}
			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf("     Evidence:    %s\n", cp.cyan(f.Evidence)))
			}
			remediation := f.Remediation
			if remediation == "" {
				if f.Classification == risk.FindingUnclassified {
					remediation = "Review this unclassified observation manually; it has no catalog mapping."
				} else {
					remediation = "Review destination owner documentation."
				}
			}
			b.WriteString(fmt.Sprintf("     Action:      %s\n", cp.green(remediation)))
			if opts.Verbose && f.DeduplicationKey != "" {
				b.WriteString(fmt.Sprintf("     Dedup Key:   %s\n", cp.dim(f.DeduplicationKey)))
			}
			b.WriteString("\n")
		}
	}

	// Limitations & Assessment Context
	b.WriteString(cp.bold("  Limitations & Assessment Context\n"))
	b.WriteString("  --------------------------------\n")
	if len(a.Limitations) == 0 {
		b.WriteString("  No additional assessment limitations recorded.\n\n")
	} else {
		for _, lim := range a.Limitations {
			b.WriteString(fmt.Sprintf("  - %s\n", lim))
		}
		b.WriteString("\n")
	}

	// Scoring Methodology / Disclaimer
	b.WriteString(cp.bold("  Scoring Methodology\n"))
	b.WriteString("  -------------------\n")
	b.WriteString(fmt.Sprintf("  %s\n\n", a.ScoringMethod))
	b.WriteString(cp.dim("  Scores are bounded product indicators (0-100), NOT probabilities of maliciousness.\n  Absence of findings is not a guarantee of security.\n\n"))

	return b.String()
}

func formatComponentName(name string) string {
	switch name {
	case "url_analysis":
		return "URL Analysis"
	case "domain_analysis":
		return "Domain Structure"
	case "tls_connection":
		return "TLS Connection"
	case "certificate_analysis":
		return "Certificate Analysis"
	case "ct_lookup":
		return "Certificate Transparency"
	case "web_http_inspection":
		return "HTTP Inspection"
	case "web_redirect_analysis":
		return "Redirect Analysis"
	case "web_security_headers":
		return "Security Headers"
	case "web_cookies":
		return "Cookie Security"
	case "web_cors":
		return "CORS Policy"
	case "web_html":
		return "HTML Inspection"
	case "web_information_disclosure":
		return "Technology Disclosure"
	case "registration_age":
		return "Registration Age"
	default:
		parts := strings.Split(name, "_")
		for i := range parts {
			if len(parts[i]) > 0 {
				parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
			}
		}
		return strings.Join(parts, " ")
	}
}
