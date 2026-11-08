package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"bouclier/internal/config"
	"bouclier/internal/storage"
)

// HistoryListOptions contains configuration for listing scans via the CLI.
type HistoryListOptions struct {
	Limit          int
	Offset         int
	Target         string
	Classification string
	MinScore       *int
	MaxScore       *int
	Status         string
	Format         string // "terminal" or "json"
	NoColor        bool
}

// HistoryListResponse is the JSON structure returned when --format json is requested.
type HistoryListResponse struct {
	Total  int                  `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
	Items  []storage.ScanRecord `json:"items"`
}

// RunHistoryList queries scan history and outputs results in terminal or JSON format.
func RunHistoryList(ctx context.Context, cfg *config.Config, opts HistoryListOptions, out io.Writer) error {
	if cfg == nil {
		cfg = config.Default()
	}

	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open scan history database: %w", err)
	}
	defer repo.Close()

	if opts.Limit <= 0 {
		opts.Limit = 20
	}
	if opts.Limit > 500 {
		opts.Limit = 500
	}
	if opts.Offset < 0 {
		return NewExitError(ExitInvalidUsage, "offset cannot be negative")
	}

	filter := storage.ListFilter{
		Target:         opts.Target,
		Classification: opts.Classification,
		MinScore:       opts.MinScore,
		MaxScore:       opts.MaxScore,
		Status:         storage.ScanStatus(opts.Status),
		Limit:          opts.Limit,
		Offset:         opts.Offset,
		SortBy:         "started_at",
		SortOrder:      "desc",
	}

	records, err := repo.ListScans(ctx, filter)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidFilter) {
			return NewExitError(ExitInvalidUsage, "%v", err)
		}
		return NewExitError(ExitGeneralError, "query scan history: %w", err)
	}

	total, err := repo.CountScans(ctx, filter)
	if err != nil {
		return NewExitError(ExitGeneralError, "count scan history: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = OutputFormatTerminal
	}

	if format == OutputFormatJSON {
		resp := HistoryListResponse{
			Total:  total,
			Limit:  opts.Limit,
			Offset: opts.Offset,
			Items:  records,
		}
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return NewExitError(ExitOutputError, "marshal history json: %w", err)
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}

	if format != OutputFormatTerminal {
		return NewExitError(ExitInvalidUsage, "invalid format %q: expected terminal or json", opts.Format)
	}

	// Terminal table rendering
	return renderHistoryTable(records, total, opts, out)
}

func renderHistoryTable(records []storage.ScanRecord, total int, opts HistoryListOptions, out io.Writer) error {
	isMono := opts.NoColor || os.Getenv("NO_COLOR") != ""

	if len(records) == 0 {
		if total == 0 && opts.Target == "" && opts.Classification == "" && opts.MinScore == nil && opts.MaxScore == nil {
			fmt.Fprintln(out, "No scan history found. Run 'bouclier scan <url>' or 'bouclier tui' to start a scan.")
		} else {
			fmt.Fprintln(out, "No scans matched the specified filter criteria.")
		}
		return nil
	}

	fmt.Fprintf(out, "\nScan History (Total: %d)\n", total)
	fmt.Fprintln(out, strings.Repeat("-", 90))
	fmt.Fprintf(out, "  %-10s %-32s %-20s %-8s %-12s %s\n",
		"ID", "TARGET", "ANALYZED (UTC)", "SCORE", "CLASS", "STATUS")
	fmt.Fprintln(out, strings.Repeat("-", 90))

	for _, r := range records {
		timeStr := r.StartedAt.UTC().Format("2006-01-02 15:04")
		scoreStr := fmt.Sprintf("%d/100", r.OverallScore)
		classStr := strings.ToUpper(string(r.Classification))
		targetStr := r.Target
		if len(targetStr) > 30 {
			targetStr = targetStr[:27] + "..."
		}

		if !isMono {
			classStr = colorizeClass(r.Classification, classStr)
			scoreStr = colorizeScore(r.OverallScore, scoreStr)
		}

		fmt.Fprintf(out, "  %-10s %-32s %-20s %-8s %-12s %s\n",
			r.ShortID(), targetStr, timeStr, scoreStr, classStr, r.Status)
	}

	fmt.Fprintln(out, strings.Repeat("-", 90))
	start := opts.Offset + 1
	end := opts.Offset + len(records)
	fmt.Fprintf(out, "Showing %d–%d of %d scans. Use 'bouclier history show <id>' to inspect full assessment.\n\n",
		start, end, total)
	return nil
}

func colorizeClass(c any, s string) string {
	str := strings.ToLower(fmt.Sprintf("%v", c))
	switch str {
	case "critical":
		return fmt.Sprintf("\033[31m\033[1m%s\033[0m", s) // Bright Red
	case "high":
		return fmt.Sprintf("\033[31m%s\033[0m", s) // Red
	case "elevated":
		return fmt.Sprintf("\033[33m%s\033[0m", s) // Yellow
	case "guarded":
		return fmt.Sprintf("\033[34m%s\033[0m", s) // Blue
	default:
		return fmt.Sprintf("\033[32m%s\033[0m", s) // Green
	}
}

func colorizeScore(score int, s string) string {
	switch {
	case score >= 80:
		return fmt.Sprintf("\033[31m\033[1m%s\033[0m", s)
	case score >= 50:
		return fmt.Sprintf("\033[31m%s\033[0m", s)
	case score >= 20:
		return fmt.Sprintf("\033[33m%s\033[0m", s)
	case score >= 1:
		return fmt.Sprintf("\033[34m%s\033[0m", s)
	default:
		return fmt.Sprintf("\033[32m%s\033[0m", s)
	}
}

// HistoryShowOptions specifies settings for displaying a historical assessment.
type HistoryShowOptions struct {
	ID      string
	Format  string // "terminal", "json", "markdown"
	Output  string
	NoColor bool
	Verbose bool
}

// RunHistoryShow retrieves and renders a historical scan assessment.
func RunHistoryShow(ctx context.Context, cfg *config.Config, opts HistoryShowOptions, out io.Writer) error {
	if cfg == nil {
		cfg = config.Default()
	}

	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open scan history database: %w", err)
	}
	defer repo.Close()

	entry, err := repo.GetScanEntry(ctx, opts.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return NewExitError(ExitScanFailure, "scan record %q not found", opts.ID)
		}
		if errors.Is(err, storage.ErrAmbiguousID) {
			return NewExitError(ExitInvalidUsage, "%v", err)
		}
		return NewExitError(ExitGeneralError, "retrieve scan assessment: %w", err)
	}

	if entry.Assessment == nil {
		return NewExitError(ExitScanFailure, "scan record %q does not have an assessment report", opts.ID)
	}

	outOpts := OutputOptions{
		Format:  opts.Format,
		Output:  opts.Output,
		NoColor: opts.NoColor,
		Verbose: opts.Verbose,
	}
	return RenderAndWrite(entry.Assessment, outOpts, out)
}

// HistoryDeleteOptions specifies parameters for deleting a historical scan.
type HistoryDeleteOptions struct {
	ID    string
	Yes   bool
	Stdin io.Reader
}

// RunHistoryDelete deletes a scan record and its associated report.
func RunHistoryDelete(ctx context.Context, cfg *config.Config, opts HistoryDeleteOptions, out io.Writer) error {
	if cfg == nil {
		cfg = config.Default()
	}

	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open scan history database: %w", err)
	}
	defer repo.Close()

	rec, err := repo.GetScan(ctx, opts.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return NewExitError(ExitScanFailure, "scan record %q not found", opts.ID)
		}
		if errors.Is(err, storage.ErrAmbiguousID) {
			return NewExitError(ExitInvalidUsage, "%v", err)
		}
		return NewExitError(ExitGeneralError, "lookup scan: %w", err)
	}

	if !opts.Yes {
		stdin := opts.Stdin
		if stdin == nil {
			stdin = os.Stdin
		}
		fmt.Fprintf(out, "Are you sure you want to delete scan record %s (%s)? [y/N]: ", rec.ShortID(), rec.Target)
		reader := bufio.NewReader(stdin)
		response, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return NewExitError(ExitGeneralError, "read confirmation: %w", err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(out, "Deletion cancelled.")
			return nil
		}
	}

	if err := repo.DeleteScan(ctx, rec.ID); err != nil {
		return NewExitError(ExitGeneralError, "delete scan: %w", err)
	}

	fmt.Fprintf(out, "Scan record %s (%s) deleted.\n", rec.ShortID(), rec.Target)
	return nil
}
