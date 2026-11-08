package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/intel"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
)

type IntelStatusOptions struct {
	Format  string
	NoColor bool
}

type IntelSourcesOptions struct {
	Format  string
	NoColor bool
}

type IntelSourceAddOptions struct {
	ID             string
	Name           string
	ProviderType   string
	Endpoint       string
	Format         string
	AuthHeaderEnv  string
	Attribution    string
	License        string
	UpdateInterval time.Duration
	Disabled       bool
}

type IntelUpdateOptions struct {
	SourceID string
	Format   string
	NoColor  bool
}

type IntelSearchOptions struct {
	Query   string
	Limit   int
	Offset  int
	Format  string
	NoColor bool
}

type IntelImportOptions struct {
	FilePath string
	SourceID string
	Format   string
}

type IntelExportOptions struct {
	OutputPath    string
	Category      string
	MinConfidence int
}

type IntelPruneOptions struct {
	Before time.Time
	DryRun bool
}

func RunIntelStatus(ctx context.Context, cfg *config.Config, opts IntelStatusOptions, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	stats, err := repo.GetIntelStats(ctx)
	if err != nil {
		return NewExitError(ExitGeneralError, "query intel stats: %v", err)
	}

	if opts.Format == OutputFormatJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(stats)
	}

	fmt.Fprintln(out, "=== Threat Intelligence Status ===")
	fmt.Fprintf(out, "Total Indicators:      %d\n", stats.TotalIndicators)
	fmt.Fprintf(out, "Configured Sources:    %d\n", stats.TotalSources)
	fmt.Fprintf(out, "Enabled Sources:       %d\n", stats.EnabledSources)
	if stats.LastSyncTime != nil {
		fmt.Fprintf(out, "Last Synchronization:  %s (%s)\n", stats.LastSyncTime.Format(time.RFC3339), stats.LastSyncStatus)
	} else {
		fmt.Fprintln(out, "Last Synchronization:  Never")
	}
	if stats.HasSyncFailures {
		fmt.Fprintf(out, "Health Warning:        Last synchronization encountered failures: %s\n", stats.LastErrorMessage)
	} else {
		fmt.Fprintln(out, "Database Health:       Optimal")
	}
	return nil
}

func RunIntelSources(ctx context.Context, cfg *config.Config, opts IntelSourcesOptions, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	sources, err := repo.ListSources(ctx)
	if err != nil {
		return NewExitError(ExitGeneralError, "list intel sources: %v", err)
	}

	if opts.Format == OutputFormatJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(sources)
	}

	if len(sources) == 0 {
		fmt.Fprintln(out, "No threat intelligence sources configured.")
		fmt.Fprintln(out, "Use 'bouclier intel import <file>' or register a feed source.")
		return nil
	}

	fmt.Fprintln(out, "=== Configured Threat Intelligence Sources ===")
	fmt.Fprintf(out, "%-16s %-24s %-12s %-8s %-12s\n", "ID", "NAME", "TYPE", "STATUS", "LAST SYNC")
	fmt.Fprintln(out, strings.Repeat("-", 76))

	for _, s := range sources {
		statusStr := "enabled"
		if !s.Enabled {
			statusStr = "disabled"
		}
		lastSync := "never"
		run, _ := repo.GetLatestSyncRun(ctx, s.ID)
		if run != nil {
			lastSync = run.StartedAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(out, "%-16s %-24s %-12s %-8s %-12s\n", s.ID, truncate(s.Name, 24), s.ProviderType, statusStr, lastSync)
	}
	return nil
}

func RunIntelSourceAdd(ctx context.Context, cfg *config.Config, opts IntelSourceAddOptions, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	opts.ID = strings.TrimSpace(opts.ID)
	if opts.ID == "" {
		return NewExitError(ExitInvalidUsage, "source ID is required")
	}
	opts.Name = strings.TrimSpace(opts.Name)
	if opts.Name == "" {
		return NewExitError(ExitInvalidUsage, "source name is required")
	}
	opts.ProviderType = strings.TrimSpace(opts.ProviderType)
	if opts.ProviderType != "local_file" && opts.ProviderType != "https_feed" {
		return NewExitError(ExitInvalidUsage, "invalid provider type %q: must be 'local_file' or 'https_feed'", opts.ProviderType)
	}
	opts.Endpoint = strings.TrimSpace(opts.Endpoint)
	if opts.Endpoint == "" {
		return NewExitError(ExitInvalidUsage, "source endpoint is required")
	}
	if opts.ProviderType == "https_feed" && !strings.HasPrefix(strings.ToLower(opts.Endpoint), "https://") {
		return NewExitError(ExitInvalidUsage, "https_feed endpoint must use https: %q", opts.Endpoint)
	}

	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return NewExitError(ExitInvalidUsage, "unsupported format %q: must be 'json' or 'csv'", opts.Format)
	}

	interval := opts.UpdateInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	envVar := strings.TrimSpace(opts.AuthHeaderEnv)
	if envVar != "" {
		for _, r := range envVar {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '=' {
				return NewExitError(ExitInvalidUsage, "invalid environment variable name %q: must not contain whitespace or '='", envVar)
			}
		}
	}

	src := storage.IntelSource{
		ID:             opts.ID,
		Name:           opts.Name,
		ProviderType:   opts.ProviderType,
		Endpoint:       opts.Endpoint,
		Enabled:        !opts.Disabled,
		UpdateInterval: interval,
		AuthHeaderEnv:  envVar,
		Attribution:    strings.TrimSpace(opts.Attribution),
		License:        strings.TrimSpace(opts.License),
		Format:         format,
	}

	if err := repo.RegisterSource(ctx, src); err != nil {
		return NewExitError(ExitGeneralError, "register source: %v", err)
	}

	state := "enabled"
	if opts.Disabled {
		state = "disabled"
	}
	fmt.Fprintf(out, "Source %q (%s) registered successfully (%s, format: %s, interval: %v).\n",
		src.Name, src.ID, state, format, interval)
	return nil
}

func RunIntelSourceRemove(ctx context.Context, cfg *config.Config, id string, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	id = strings.TrimSpace(id)
	if id == "" {
		return NewExitError(ExitInvalidUsage, "source ID is required")
	}

	if err := repo.DeleteSource(ctx, id); err != nil {
		if strings.Contains(err.Error(), "not found") || errors.Is(err, storage.ErrNotFound) {
			return NewExitError(ExitInvalidUsage, "source ID %q not found", id)
		}
		return NewExitError(ExitGeneralError, "delete source %q: %v", id, err)
	}

	fmt.Fprintf(out, "Source %q and its associated indicators removed successfully.\n", id)
	return nil
}

func RunIntelSourceSetEnabled(ctx context.Context, cfg *config.Config, id string, enabled bool, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	id = strings.TrimSpace(id)
	if id == "" {
		return NewExitError(ExitInvalidUsage, "source ID is required")
	}

	if err := repo.SetSourceEnabled(ctx, id, enabled); err != nil {
		if strings.Contains(err.Error(), "not found") || errors.Is(err, storage.ErrNotFound) {
			return NewExitError(ExitInvalidUsage, "source ID %q not found", id)
		}
		return NewExitError(ExitGeneralError, "set source %q enabled: %v", id, err)
	}

	action := "enabled"
	if !enabled {
		action = "disabled"
	}
	fmt.Fprintf(out, "Source %q successfully %s.\n", id, action)
	return nil
}

func RunIntelUpdate(ctx context.Context, cfg *config.Config, opts IntelUpdateOptions, out io.Writer) error {
	registry := intel.NewProviderRegistry()
	registry.Register("local_file", intel.NewLocalFileProvider())
	registry.Register("https_feed", intel.NewHTTPSFeedProvider())
	return RunIntelUpdateWithRegistry(ctx, cfg, opts, out, registry)
}

func RunIntelUpdateWithRegistry(ctx context.Context, cfg *config.Config, opts IntelUpdateOptions, out io.Writer, registry *intel.ProviderRegistry) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	sources, err := repo.ListSources(ctx)
	if err != nil {
		return NewExitError(ExitGeneralError, "list sources: %v", err)
	}

	var toUpdate []storage.IntelSource
	if opts.SourceID != "" {
		found := false
		for _, s := range sources {
			if s.ID == opts.SourceID {
				if !s.Enabled {
					return NewExitError(ExitInvalidUsage, "source %q is disabled", opts.SourceID)
				}
				toUpdate = append(toUpdate, s)
				found = true
				break
			}
		}
		if !found {
			return NewExitError(ExitInvalidUsage, "source ID %q not found", opts.SourceID)
		}
	} else {
		for _, s := range sources {
			if s.Enabled {
				toUpdate = append(toUpdate, s)
			}
		}
	}

	if len(toUpdate) == 0 {
		fmt.Fprintln(out, "No enabled sources to update.")
		return nil
	}

	if registry == nil {
		registry = intel.NewProviderRegistry()
		registry.Register("local_file", intel.NewLocalFileProvider())
		registry.Register("https_feed", intel.NewHTTPSFeedProvider())
	}

	var overallErr error
	for _, src := range toUpdate {
		fmt.Fprintf(out, "Synchronizing source %q (%s)...\n", src.Name, src.ID)
		provider, ok := registry.Get(src.ProviderType)
		if !ok {
			fmt.Fprintf(out, "  [ERROR] Unknown provider type %q for source %s\n", src.ProviderType, src.ID)
			continue
		}

		started := time.Now().UTC()
		sourceCfg := intel.SourceConfig{
			ID:             src.ID,
			Name:           src.Name,
			ProviderType:   src.ProviderType,
			Endpoint:       src.Endpoint,
			Enabled:        src.Enabled,
			UpdateInterval: src.UpdateInterval,
			AuthHeaderEnv:  src.AuthHeaderEnv,
			Attribution:    src.Attribution,
			License:        src.License,
			Format:         src.Format,
		}

		res, fetchErr := provider.FetchIndicators(ctx, sourceCfg)
		completed := time.Now().UTC()
		if fetchErr != nil {
			fmt.Fprintf(out, "  [FAILED] %v\n", fetchErr)
			_ = repo.RecordSyncRun(ctx, storage.IntelSyncRun{
				SourceID:     src.ID,
				StartedAt:    started,
				CompletedAt:  completed,
				Status:       "failed",
				ErrorMessage: fetchErr.Error(),
			})
			overallErr = fetchErr
			continue
		}

		// Convert indicators to storage models
		storageInds := make([]storage.IntelIndicator, 0, len(res.Indicators))
		for _, ind := range res.Indicators {
			storageInds = append(storageInds, storage.IntelIndicator{
				ID:          ind.ID,
				SourceID:    src.ID,
				SourceName:  src.Name,
				Type:        string(ind.Type),
				Value:       ind.Value,
				Category:    ind.Category,
				Confidence:  ind.Confidence,
				Severity:    string(ind.Severity),
				FirstSeen:   ind.FirstSeen,
				LastSeen:    ind.LastSeen,
				ExpiresAt:   ind.ExpiresAt,
				IngestedAt:  ind.IngestedAt,
				SourceRef:   ind.SourceRef,
				Description: ind.Description,
				Metadata:    ind.Metadata,
			})
		}

		imported, updated, saveErr := repo.SaveIndicatorBatch(ctx, src.ID, storageInds)
		if saveErr != nil {
			fmt.Fprintf(out, "  [FAILED saving batch] %v\n", saveErr)
			_ = repo.RecordSyncRun(ctx, storage.IntelSyncRun{
				SourceID:     src.ID,
				StartedAt:    started,
				CompletedAt:  time.Now().UTC(),
				Status:       "failed",
				ErrorMessage: saveErr.Error(),
			})
			overallErr = saveErr
			continue
		}

		status := "success"
		if len(res.Errors) > 0 {
			status = "partial"
		}

		_ = repo.RecordSyncRun(ctx, storage.IntelSyncRun{
			SourceID:      src.ID,
			StartedAt:     started,
			CompletedAt:   completed,
			Status:        status,
			ImportedCount: imported,
			UpdatedCount:  updated,
			SkippedCount:  0,
			RejectedCount: len(res.Errors),
		})

		fmt.Fprintf(out, "  [SUCCESS] Imported: %d, Updated: %d, Rejected/Errors: %d (in %v)\n",
			imported, updated, len(res.Errors), completed.Sub(started).Round(time.Millisecond))
	}

	if overallErr != nil {
		return NewExitError(ExitScanFailure, "one or more threat intelligence feeds failed synchronization")
	}
	return nil
}

func RunIntelSearch(ctx context.Context, cfg *config.Config, opts IntelSearchOptions, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	if opts.Limit <= 0 {
		opts.Limit = 20
	}

	results, total, err := repo.SearchIndicators(ctx, opts.Query, opts.Limit, opts.Offset)
	if err != nil {
		return NewExitError(ExitGeneralError, "search indicators: %v", err)
	}

	if opts.Format == OutputFormatJSON {
		payload := struct {
			Query   string                   `json:"query"`
			Total   int                      `json:"total"`
			Results []storage.IntelIndicator `json:"results"`
		}{
			Query:   opts.Query,
			Total:   total,
			Results: results,
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	if len(results) == 0 {
		fmt.Fprintf(out, "No active indicators found matching %q.\n", opts.Query)
		return nil
	}

	fmt.Fprintf(out, "Found %d indicators matching %q (showing %d):\n\n", total, opts.Query, len(results))
	fmt.Fprintf(out, "%-8s %-32s %-16s %-10s %-8s\n", "TYPE", "VALUE", "CATEGORY", "SEVERITY", "CONF")
	fmt.Fprintln(out, strings.Repeat("-", 80))

	for _, ind := range results {
		fmt.Fprintf(out, "%-8s %-32s %-16s %-10s %-3d%%\n",
			ind.Type, truncate(ind.Value, 32), ind.Category, ind.Severity, ind.Confidence)
	}
	return nil
}

func RunIntelImport(ctx context.Context, cfg *config.Config, opts IntelImportOptions, out io.Writer) error {
	filePath := strings.TrimSpace(opts.FilePath)
	if filePath == "" {
		return NewExitError(ExitInvalidUsage, "import file path is required")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return NewExitError(ExitInvalidUsage, "open import file %q: %v", filePath, err)
	}
	defer file.Close()

	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	// Try reading as collaborative bundle first
	bundle, bundleErr := intel.ReadBundle(file)
	var indicators []intel.Indicator
	var recordErrors []intel.RecordError
	sourceID := opts.SourceID
	if sourceID == "" {
		sourceID = "bundle-import"
	}
	sourceName := "Collaborative Bundle Import"

	if bundleErr == nil && bundle != nil {
		indicators = bundle.Indicators
		fmt.Fprintf(out, "Importing verified intelligence bundle (%s, %d indicators)...\n",
			bundle.Manifest.SchemaVersion, len(indicators))
	} else {
		// Fallback to raw JSON/CSV feed parsing
		_, _ = file.Seek(0, io.SeekStart)
		sourceCfg := intel.SourceConfig{
			ID:      sourceID,
			Name:    sourceName,
			Format:  opts.Format,
			Enabled: true,
		}
		indicators, recordErrors, err = intel.ParseIndicators(file, opts.Format, sourceCfg)
		if err != nil {
			return NewExitError(ExitInvalidUsage, "parse import file: %v", err)
		}
		fmt.Fprintf(out, "Importing feed data (%d valid indicators, %d rejected)...\n",
			len(indicators), len(recordErrors))
	}

	// Register import source if not registered
	_ = repo.RegisterSource(ctx, storage.IntelSource{
		ID:           sourceID,
		Name:         sourceName,
		ProviderType: "local_file",
		Endpoint:     filePath,
		Enabled:      true,
		Attribution:  "Explicit user import",
	})

	storageInds := make([]storage.IntelIndicator, 0, len(indicators))
	for _, ind := range indicators {
		indSourceName := ind.SourceName
		if indSourceName == "" {
			indSourceName = sourceName
		}
		meta := make(map[string]string)
		for k, v := range ind.Metadata {
			meta[k] = v
		}
		if ind.SourceID != "" && ind.SourceID != sourceID {
			if _, exists := meta["original_source_id"]; !exists {
				meta["original_source_id"] = ind.SourceID
			}
		}
		if ind.SourceName != "" && ind.SourceName != sourceName {
			if _, exists := meta["original_source_name"]; !exists {
				meta["original_source_name"] = ind.SourceName
			}
		}

		storageInds = append(storageInds, storage.IntelIndicator{
			ID:          ind.ID,
			SourceID:    sourceID,
			SourceName:  indSourceName,
			Type:        string(ind.Type),
			Value:       ind.Value,
			Category:    ind.Category,
			Confidence:  ind.Confidence,
			Severity:    string(ind.Severity),
			FirstSeen:   ind.FirstSeen,
			LastSeen:    ind.LastSeen,
			ExpiresAt:   ind.ExpiresAt,
			IngestedAt:  ind.IngestedAt,
			SourceRef:   ind.SourceRef,
			Description: ind.Description,
			Metadata:    meta,
		})
	}

	started := time.Now().UTC()
	imported, updated, err := repo.SaveIndicatorBatch(ctx, sourceID, storageInds)
	completed := time.Now().UTC()
	if err != nil {
		return NewExitError(ExitGeneralError, "save imported indicators: %v", err)
	}

	_ = repo.RecordSyncRun(ctx, storage.IntelSyncRun{
		SourceID:      sourceID,
		StartedAt:     started,
		CompletedAt:   completed,
		Status:        "success",
		ImportedCount: imported,
		UpdatedCount:  updated,
		SkippedCount:  0,
		RejectedCount: len(recordErrors),
	})

	fmt.Fprintf(out, "Import completed successfully: %d imported, %d updated.\n", imported, updated)
	return nil
}

func RunIntelExport(ctx context.Context, cfg *config.Config, opts IntelExportOptions, out io.Writer) error {
	outputPath := strings.TrimSpace(opts.OutputPath)
	if outputPath == "" {
		return NewExitError(ExitInvalidUsage, "export output path is required")
	}

	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	// Query indicators
	indicators, _, err := repo.SearchIndicators(ctx, "", 10000, 0)
	if err != nil {
		return NewExitError(ExitGeneralError, "query indicators for export: %v", err)
	}

	intelInds := make([]intel.Indicator, 0, len(indicators))
	for _, ind := range indicators {
		intelInds = append(intelInds, intel.Indicator{
			ID:          ind.ID,
			Type:        intel.IndicatorType(ind.Type),
			Value:       ind.Value,
			SourceID:    ind.SourceID,
			SourceName:  ind.SourceName,
			Category:    ind.Category,
			Confidence:  ind.Confidence,
			Severity:    risk.Severity(ind.Severity),
			FirstSeen:   ind.FirstSeen,
			LastSeen:    ind.LastSeen,
			ExpiresAt:   ind.ExpiresAt,
			IngestedAt:  ind.IngestedAt,
			SourceRef:   ind.SourceRef,
			Description: ind.Description,
			Metadata:    ind.Metadata,
		})
	}

	exportOpts := intel.ExportOptions{
		Category:      opts.Category,
		MinConfidence: opts.MinConfidence,
	}

	bundle, err := intel.CreateBundle(intelInds, exportOpts)
	if err != nil {
		return NewExitError(ExitScanFailure, "create export bundle: %v", err)
	}

	if err := intel.WriteBundle(outputPath, bundle); err != nil {
		return NewExitError(ExitScanFailure, "write export bundle: %v", err)
	}

	fmt.Fprintf(out, "Exported %d indicators to %s (SHA-256: %s)\n",
		bundle.Manifest.IndicatorCount, outputPath, bundle.Manifest.ChecksumSHA256)
	return nil
}

func RunIntelPrune(ctx context.Context, cfg *config.Config, opts IntelPruneOptions, out io.Writer) error {
	repo, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open database %q: %v", cfg.Storage.DatabasePath, err)
	}
	defer repo.Close()

	before := opts.Before
	if before.IsZero() {
		before = time.Now().UTC()
	}

	count, err := repo.PruneExpiredIndicators(ctx, before, opts.DryRun)
	if err != nil {
		return NewExitError(ExitGeneralError, "prune expired indicators: %v", err)
	}

	if opts.DryRun {
		fmt.Fprintf(out, "[Dry Run] %d expired indicators would be pruned (cutoff: %s).\n", count, before.Format(time.RFC3339))
	} else {
		fmt.Fprintf(out, "Successfully pruned %d expired indicators (cutoff: %s).\n", count, before.Format(time.RFC3339))
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) > max && max > 3 {
		return s[:max-3] + "..."
	}
	return s
}
