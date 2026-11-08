package cli

import (
	"io"
	"os"
	"path/filepath"

	"bouclier/internal/report"
	"bouclier/internal/risk"
)

const (
	OutputFormatTerminal = "terminal"
	OutputFormatJSON     = "json"
	OutputFormatMarkdown = "markdown"
)

type OutputOptions struct {
	Format  string
	Output  string
	NoColor bool
	Verbose bool
	Quiet   bool
}

// RenderAndWrite renders the assessment in the requested format and writes it
// to the designated output file (with restricted permissions 0600) or to stdout.
func RenderAndWrite(assessment *risk.RiskAssessment, opts OutputOptions, stdout io.Writer) error {
	if assessment == nil {
		return NewExitError(ExitOutputError, "render output: assessment is nil")
	}

	var data []byte
	switch opts.Format {
	case OutputFormatTerminal:
		termOpts := TerminalOptions{
			NoColor: opts.NoColor,
			Verbose: opts.Verbose,
			Quiet:   opts.Quiet,
		}
		// If writing to a file, disable ANSI color codes
		if opts.Output != "" {
			termOpts.NoColor = true
		}
		text := FormatTerminal(assessment, termOpts)
		data = []byte(text)

	case OutputFormatJSON:
		jsonBytes, err := report.RenderJSON(assessment)
		if err != nil {
			return NewExitError(ExitOutputError, "render JSON report: %w", err)
		}
		data = append(jsonBytes, '\n')

	case OutputFormatMarkdown:
		mdText, err := report.RenderMarkdown(assessment)
		if err != nil {
			return NewExitError(ExitOutputError, "render Markdown report: %w", err)
		}
		data = []byte(mdText)

	default:
		return NewExitError(ExitInvalidUsage, "unsupported output format %q: expected terminal, json, or markdown", opts.Format)
	}

	if opts.Output != "" {
		if err := writeToFile(opts.Output, data); err != nil {
			return NewExitError(ExitOutputError, "write output file %q: %w", opts.Output, err)
		}
		return nil
	}

	if _, err := stdout.Write(data); err != nil {
		return NewExitError(ExitOutputError, "write output: %w", err)
	}
	return nil
}

func writeToFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	// Avoid exposing security reports to other local users: 0600 (owner read/write only)
	return os.WriteFile(path, data, 0600)
}
