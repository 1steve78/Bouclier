package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"bouclier/internal/config"
	"bouclier/internal/report"
	"bouclier/internal/storage"
)

type HistoryCorrelateOptions struct {
	Target string
	Limit  int
	Format string
	Output string
}

func RunHistoryCorrelate(ctx context.Context, cfg *config.Config, opts HistoryCorrelateOptions, out io.Writer) error {
	if cfg == nil {
		cfg = config.Default()
	}
	target, err := canonicalCorrelationHost(opts.Target)
	if err != nil {
		return NewExitError(ExitInvalidUsage, "%v", err)
	}
	limit := opts.Limit
	if limit < 0 {
		return NewExitError(ExitInvalidUsage, "correlation limit cannot be negative")
	}
	if limit == 0 {
		limit = 100
	}
	if limit > 500 {
		return NewExitError(ExitInvalidUsage, "correlation limit cannot exceed 500")
	}

	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open scan history database: %w", err)
	}
	defer repo.Close()

	entries := make([]report.CorrelationEntry, 0, limit)
	for offset := 0; len(entries) < limit; {
		candidates, err := repo.ListScans(ctx, storage.ListFilter{
			Target: target, Limit: 500, Offset: offset, SortBy: "started_at", SortOrder: "desc",
		})
		if err != nil {
			return NewExitError(ExitGeneralError, "query scan history for %q: %w", target, err)
		}
		if len(candidates) == 0 {
			break
		}
		for _, record := range candidates {
			host, hostErr := canonicalCorrelationHost(record.Target)
			if hostErr != nil || host != target {
				continue
			}
			entry, err := repo.GetScanEntry(ctx, record.ID)
			if err != nil {
				return NewExitError(ExitGeneralError, "load report %s for correlation: %w", record.ShortID(), err)
			}
			entries = append(entries, report.CorrelationEntry{
				ID: record.ID, StartedAt: record.StartedAt, Assessment: entry.Assessment,
			})
			if len(entries) == limit {
				break
			}
		}
		offset += len(candidates)
		if len(candidates) < 500 {
			break
		}
	}

	correlation, err := report.Correlate(target, entries)
	if err != nil {
		return NewExitError(ExitOutputError, "%v", err)
	}
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = OutputFormatTerminal
	}
	var data []byte
	switch format {
	case OutputFormatTerminal:
		data = []byte(renderCorrelationTerminal(correlation))
	case OutputFormatJSON:
		data, err = json.MarshalIndent(correlation, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	case OutputFormatMarkdown:
		data = []byte(renderCorrelationMarkdown(correlation))
	default:
		return NewExitError(ExitInvalidUsage, "unsupported correlation format %q: expected terminal, json, or markdown", opts.Format)
	}
	if err != nil {
		return NewExitError(ExitOutputError, "render report correlation: %w", err)
	}
	if opts.Output != "" {
		if err := writeToFile(opts.Output, data); err != nil {
			return NewExitError(ExitOutputError, "write correlation report %q: %w", opts.Output, err)
		}
		return nil
	}
	if _, err := out.Write(data); err != nil {
		return NewExitError(ExitOutputError, "write correlation report: %w", err)
	}
	return nil
}

func canonicalCorrelationHost(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("target URL or hostname is required")
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return "", fmt.Errorf("invalid target URL or hostname %q", target)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("target must use http or https")
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")), nil
}

func renderCorrelationTerminal(correlation report.Correlation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Report correlation for %s\n", correlation.Target)
	if len(correlation.Scans) == 0 {
		b.WriteString("No matching scan reports found.\n")
		return b.String()
	}
	b.WriteString("Risk score trend (0-100)\n")
	b.WriteString("  0         20        40        60        80       100\n")
	for _, scan := range correlation.Scans {
		score := scan.Score
		if score < 0 {
			score = 0
		} else if score > 100 {
			score = 100
		}
		filled := score * 40 / 100
		bar := strings.Repeat("#", filled) + strings.Repeat("-", 40-filled)
		fmt.Fprintf(&b, "%s |%s| %3d  %s\n",
			scan.StartedAt.UTC().Format("2006-01-02"), bar, scan.Score, scan.Classification)
	}
	b.WriteString("\nFinding changes from previous report\n")
	for i, scan := range correlation.Scans {
		if i == 0 {
			fmt.Fprintf(&b, "%s  baseline: %d finding(s)\n", scan.StartedAt.UTC().Format("2006-01-02"), scan.FindingCount)
			continue
		}
		fmt.Fprintf(&b, "%s  +%d new, -%d resolved, %d total\n",
			scan.StartedAt.UTC().Format("2006-01-02"), len(scan.NewFindings),
			len(scan.ResolvedFindings), scan.FindingCount)
	}
	return b.String()
}

func renderCorrelationMarkdown(correlation report.Correlation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Report correlation: %s\n\n", correlation.Target)
	b.WriteString("Risk scores are deterministic assessment scores, not probabilities.\n\n")
	b.WriteString("```text\n")
	b.WriteString(renderCorrelationTerminal(correlation))
	b.WriteString("```\n\n")
	b.WriteString("| Scan | Date (UTC) | Score | Class | New | Resolved |\n")
	b.WriteString("|---|---|---:|---|---:|---:|\n")
	for i, scan := range correlation.Scans {
		newCount, resolvedCount := len(scan.NewFindings), len(scan.ResolvedFindings)
		if i == 0 {
			newCount = scan.FindingCount
			resolvedCount = 0
		}
		fmt.Fprintf(&b, "| `%s` | %s | %d/100 | %s | %d | %d |\n",
			scan.ID, scan.StartedAt.UTC().Format("2006-01-02 15:04"), scan.Score,
			scan.Classification, newCount, resolvedCount)
	}
	return b.String()
}
