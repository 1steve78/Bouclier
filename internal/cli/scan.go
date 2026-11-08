package cli

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/ct"
	"bouclier/internal/domain"
	"bouclier/internal/heuristics"
	"bouclier/internal/intel"
	"bouclier/internal/logging"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webintel"
	"github.com/google/uuid"
)

type ScanOptions struct {
	Target     string
	Format     string
	Output     string
	Config     string
	Timeout    time.Duration
	NoCT       bool
	CTScope    string
	Verbose    bool
	Quiet      bool
	NoColor    bool
	FailOnRisk *int // nil if not set, otherwise pointer to 0-100
	Storage    storage.Repository
	NoPersist  bool
	ScanID     string
}

// websiteAnalyzer is the function used to run website intelligence.
// Overridden in tests to avoid live network calls.
var websiteAnalyzer = webintel.AnalyzeWebsite

// SetWebsiteAnalyzerForTesting overrides the website analyzer for testing.
// Returns a restore function that reverts to the previous analyzer.
func SetWebsiteAnalyzerForTesting(fn func(ctx context.Context, input *heuristics.NormalizedURL, options webintel.Options) (*webintel.AnalysisResult, error)) func() {
	prev := websiteAnalyzer
	websiteAnalyzer = fn
	return func() {
		websiteAnalyzer = prev
	}
}

// ValidateScanOptions checks flag combinations and values.
func ValidateScanOptions(opts *ScanOptions) error {
	if opts == nil {
		return NewExitError(ExitInvalidUsage, "scan options is nil")
	}
	opts.Target = strings.TrimSpace(opts.Target)
	if opts.Target == "" {
		return NewExitError(ExitInvalidUsage, "target URL is required")
	}

	opts.Format = strings.ToLower(strings.TrimSpace(opts.Format))
	if opts.Format == "" {
		opts.Format = OutputFormatTerminal
	}
	if opts.Format != OutputFormatTerminal && opts.Format != OutputFormatJSON && opts.Format != OutputFormatMarkdown {
		return NewExitError(ExitInvalidUsage, "invalid --format %q: must be terminal, json, or markdown", opts.Format)
	}

	opts.CTScope = strings.ToLower(strings.TrimSpace(opts.CTScope))
	if opts.CTScope == "" {
		opts.CTScope = "exact"
	}
	if opts.CTScope != "exact" && opts.CTScope != "registrable" {
		return NewExitError(ExitInvalidUsage, "invalid --ct-scope %q: must be exact or registrable", opts.CTScope)
	}

	if opts.Verbose && opts.Quiet {
		return NewExitError(ExitInvalidUsage, "cannot use --verbose and --quiet together")
	}

	if opts.Timeout < 0 {
		return NewExitError(ExitInvalidUsage, "--timeout cannot be negative")
	}

	if opts.FailOnRisk != nil && (*opts.FailOnRisk < 0 || *opts.FailOnRisk > 100) {
		return NewExitError(ExitInvalidUsage, "--fail-on-risk must be between 0 and 100")
	}
	return nil
}

type ScanStage string

const (
	StageURLAnalysis             ScanStage = "URL Analysis"
	StageDomainIntelligence      ScanStage = "Domain Intelligence"
	StageTLSAndCertificates      ScanStage = "TLS & Certificates"
	StageCertificateTransparency ScanStage = "Certificate Transparency"
	StageHTTPSecurity            ScanStage = "HTTP Security"
	StageThreatIntelligence      ScanStage = "Threat Intelligence"
	StageRiskAggregation         ScanStage = "Risk Aggregation"
)

type StageState string

const (
	StageStatePending   StageState = "pending"
	StageStateRunning   StageState = "running"
	StageStateCompleted StageState = "completed"
	StageStatePartial   StageState = "partial"
	StageStateFailed    StageState = "failed"
	StageStateSkipped   StageState = "skipped"
)

type ScanProgressFunc func(stage ScanStage, state StageState, message string)

type ScanPipelineResult struct {
	Assessment    *risk.RiskAssessment
	ScanRecord    *storage.ScanRecord
	IsSSRFBlocked bool
	NormalizedURL *heuristics.NormalizedURL
	WebResult     *webintel.AnalysisResult
	StartedAt     time.Time
	CompletedAt   time.Time
	Duration      time.Duration
}

// ExecuteScanPipeline runs the end-to-end security assessment pipeline against the target URL.
// It reports truthful stage progression via onProgress if provided.
func ExecuteScanPipeline(ctx context.Context, cfg *config.Config, opts ScanOptions, onProgress ScanProgressFunc) (*ScanPipelineResult, error) {
	if cfg == nil {
		cfg = config.Default()
	}

	progress := func(stage ScanStage, state StageState, msg string) {
		if onProgress != nil {
			onProgress(stage, state, msg)
		}
	}

	scanStarted := time.Now().UTC()

	// 1. Target normalization and validation
	raw := opts.Target
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	normalizedURL, err := heuristics.NormalizeURL(raw)
	if err != nil {
		return nil, NewExitError(ExitScanFailure, "invalid target URL: %w", err)
	}

	// 2. Timeout configuration
	scanTimeout := 30 * time.Second
	if opts.Timeout > 0 {
		scanTimeout = opts.Timeout
	} else if cfg.Scanner.HTTPTimeout > 0 {
		scanTimeout = cfg.Scanner.HTTPTimeout * 3
		if scanTimeout < 15*time.Second {
			scanTimeout = 15 * time.Second
		}
	}
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	logger, hasLogger := logging.FromContext(scanCtx)
	if hasLogger && opts.Verbose {
		logger.Info("beginning scan", "target", normalizedURL.Normalized, "timeout", scanTimeout)
	}

	// 3. URL heuristic analysis (offline)
	progress(StageURLAnalysis, StageStateRunning, "Analyzing URL structure and heuristics...")
	urlResult, urlErr := heuristics.AnalyzeURL(normalizedURL.Normalized)
	if urlErr != nil && hasLogger && opts.Verbose {
		logger.Warn("URL analysis error", "error", urlErr)
	}
	progress(StageURLAnalysis, StageStateCompleted, "URL structure analyzed")

	// 4. Domain analysis (offline)
	progress(StageDomainIntelligence, StageStateRunning, "Analyzing domain and registrability...")
	var domainResult *domain.AnalysisResult
	domainInfo, domainInfoErr := heuristics.ExtractDomainInfo(normalizedURL)
	if domainInfoErr == nil && domainInfo != nil {
		var domainErr error
		domainResult, domainErr = domain.AnalyzeDomain(domainInfo)
		if domainErr != nil && hasLogger && opts.Verbose {
			logger.Warn("domain analysis error", "error", domainErr)
		}
	}
	progress(StageDomainIntelligence, StageStateCompleted, "Domain intelligence analyzed")

	// 5. Website assessment and TLS intelligence (network)
	if normalizedURL.Scheme == "http" {
		progress(StageTLSAndCertificates, StageStateSkipped, "TLS is not applicable to HTTP URL")
		progress(StageCertificateTransparency, StageStateSkipped, "CT is not applicable to HTTP URL")
	} else {
		progress(StageTLSAndCertificates, StageStateRunning, "Inspecting TLS certificates and handshake...")
		if opts.NoCT {
			progress(StageCertificateTransparency, StageStateSkipped, "Certificate Transparency lookups disabled")
		} else {
			progress(StageCertificateTransparency, StageStateRunning, "Querying Certificate Transparency logs...")
		}
	}
	progress(StageHTTPSecurity, StageStateRunning, "Inspecting HTTP response headers and cookies...")

	webOpts := webintel.Options{
		Config: cfg,
	}
	if opts.Timeout > 0 {
		cfgCopy := *cfg
		cfgCopy.Scanner.HTTPTimeout = opts.Timeout
		cfgCopy.Scanner.TLSHandshakeTimeout = opts.Timeout
		webOpts.Config = &cfgCopy
	}
	if !opts.NoCT {
		scope := ct.ScopeExactHostname
		if opts.CTScope == "registrable" {
			scope = ct.ScopeRegistrableDomain
		}
		webOpts.TLS.CTScope = scope
		ctProvider, ctErr := ct.NewCTLogsDevProvider(ct.CTLogsDevOptions{})
		if ctErr == nil {
			webOpts.TLS.CTProvider = ctProvider
		} else if hasLogger && opts.Verbose {
			logger.Warn("CT provider initialization failed", "error", ctErr)
		}
	}

	webResult, webErr := websiteAnalyzer(scanCtx, normalizedURL, webOpts)
	if scanCtx.Err() != nil {
		return nil, NewExitError(ExitScanFailure, "scan timed out or cancelled: %w", scanCtx.Err())
	}
	if webErr != nil && hasLogger && opts.Verbose {
		logger.Warn("website analysis operational error", "error", webErr)
	}

	// Update actual stage states based on webResult
	if normalizedURL.Scheme == "http" {
		progress(StageTLSAndCertificates, StageStateSkipped, "TLS skipped for HTTP URL")
		progress(StageCertificateTransparency, StageStateSkipped, "CT skipped for HTTP URL")
	} else if webResult != nil {
		switch webResult.TLSStatus.State {
		case webintel.StateCompleted:
			progress(StageTLSAndCertificates, StageStateCompleted, "TLS analysis completed")
		case webintel.StateFailed:
			progress(StageTLSAndCertificates, StageStateFailed, webResult.TLSStatus.Error)
		case webintel.StateSkipped:
			progress(StageTLSAndCertificates, StageStateSkipped, "TLS check skipped")
		default:
			progress(StageTLSAndCertificates, StageStatePartial, "TLS check partial")
		}

		if opts.NoCT {
			progress(StageCertificateTransparency, StageStateSkipped, "CT disabled")
		} else if webResult.TLS != nil {
			switch webResult.TLS.CTStatus.State {
			case tlsintel.StateCompleted:
				progress(StageCertificateTransparency, StageStateCompleted, "CT lookup completed")
			case tlsintel.StateFailed:
				progress(StageCertificateTransparency, StageStateFailed, webResult.TLS.CTStatus.Error)
			default:
				progress(StageCertificateTransparency, StageStateSkipped, "CT query completed")
			}
		} else {
			progress(StageCertificateTransparency, StageStateSkipped, "CT skipped")
		}
	}

	if webResult != nil {
		switch webResult.HTTPStatus.State {
		case webintel.StateCompleted:
			progress(StageHTTPSecurity, StageStateCompleted, "HTTP security assessment completed")
		case webintel.StateFailed:
			progress(StageHTTPSecurity, StageStateFailed, webResult.HTTPStatus.Error)
		case webintel.StatePartial:
			progress(StageHTTPSecurity, StageStatePartial, "HTTP security assessment partial")
		default:
			progress(StageHTTPSecurity, StageStateSkipped, "HTTP security assessment skipped")
		}
	} else {
		progress(StageHTTPSecurity, StageStateFailed, "No HTTP response received")
	}

	// 6. Threat intelligence matching
	progress(StageThreatIntelligence, StageStateRunning, "Evaluating local threat intelligence indicators...")
	var intelObservations []risk.Observation
	var intelCoverage *risk.IntelligenceCoverage

	coords := intel.ExtractCoordinates(normalizedURL, domainInfo, nil)
	matcher := intel.NewMatcher(opts.Storage)
	intelSummary, intelErr := matcher.MatchTarget(scanCtx, coords)
	if intelErr != nil || intelSummary.DatabaseUnavailable {
		progress(StageThreatIntelligence, StageStateSkipped, "Local threat intelligence unavailable")
		intelCoverage = &risk.IntelligenceCoverage{
			Ran:                 false,
			DatabaseUnavailable: true,
			Detail:              "Threat intelligence storage not connected or query error",
		}
	} else {
		intelObservations = intel.MatchesToObservations(intelSummary.Matches)
		intelCoverage = &risk.IntelligenceCoverage{
			Ran:                  intelSummary.Ran,
			SourcesConfigured:    intelSummary.ConfiguredSources,
			SourcesEnabled:       intelSummary.EnabledSources,
			LastSuccessfulSync:   intelSummary.LastSyncTime,
			IndicatorsConsidered: intelSummary.IndicatorsConsidered,
			MatchesCount:         len(intelSummary.Matches),
			DatabaseStale:        intelSummary.DatabaseStale,
			DatabaseUnavailable:  intelSummary.DatabaseUnavailable,
			Detail:               intelSummary.Detail,
		}
		if len(intelSummary.Matches) > 0 {
			progress(StageThreatIntelligence, StageStateCompleted, fmt.Sprintf("%d threat indicators matched", len(intelSummary.Matches)))
		} else {
			progress(StageThreatIntelligence, StageStateCompleted, "No threat intelligence matches")
		}
	}

	// 7. Risk aggregation
	progress(StageRiskAggregation, StageStateRunning, "Aggregating findings into unified risk score...")
	aggInput := risk.AggregationInput{
		Target:            normalizedURL.Normalized,
		AnalyzedAt:        time.Now().UTC(),
		URL:               urlResult,
		Domain:            domainResult,
		Web:               webResult,
		IntelObservations: intelObservations,
		IntelCoverage:     intelCoverage,
	}
	assessment, aggErr := risk.AggregateDefault(aggInput)
	if aggErr != nil {
		return nil, NewExitError(ExitScanFailure, "aggregate risk results: %w", aggErr)
	}
	progress(StageRiskAggregation, StageStateCompleted, "Risk assessment complete")

	isBlocked := isSSRFBlockedTarget(normalizedURL.Hostname, webResult)
	scanCompleted := time.Now().UTC()

	status := storage.StatusCompleted
	if isBlocked {
		status = storage.StatusFailed
	} else {
		for _, cov := range assessment.AnalysisCoverage {
			if cov.State == risk.ComponentFailed || cov.State == risk.ComponentPartial {
				status = storage.StatusPartial
				break
			}
		}
	}

	var scanRecord *storage.ScanRecord
	// Persistence: exactly one persistence operation per completed scan
	if opts.Storage != nil {
		rec, saveErr := PersistScanAssessment(ctx, opts.Storage, assessment, normalizedURL.Normalized, scanStarted, scanCompleted, scanCompleted.Sub(scanStarted), status)
		if saveErr != nil && opts.Verbose {
			fmt.Fprintf(os.Stderr, "warning: failed to save scan to history: %v\n", saveErr)
		} else {
			scanRecord = rec
		}
	} else if !opts.NoPersist && cfg != nil && strings.TrimSpace(cfg.Storage.DatabasePath) != "" {
		repo, err := storage.Open(cfg.Storage.DatabasePath)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "warning: cannot open history database: %v\n", err)
			}
		} else {
			defer repo.Close()
			rec, saveErr := PersistScanAssessment(ctx, repo, assessment, normalizedURL.Normalized, scanStarted, scanCompleted, scanCompleted.Sub(scanStarted), status)
			if saveErr != nil && opts.Verbose {
				fmt.Fprintf(os.Stderr, "warning: failed to save scan to history: %v\n", saveErr)
			} else {
				scanRecord = rec
			}
		}
	}

	return &ScanPipelineResult{
		Assessment:    assessment,
		ScanRecord:    scanRecord,
		IsSSRFBlocked: isBlocked,
		NormalizedURL: normalizedURL,
		WebResult:     webResult,
		StartedAt:     scanStarted,
		CompletedAt:   scanCompleted,
		Duration:      scanCompleted.Sub(scanStarted),
	}, nil
}

// RunScan executes the end-to-end scanning pipeline for target URL.
func RunScan(ctx context.Context, cfg *config.Config, opts ScanOptions, out io.Writer) error {
	if err := ValidateScanOptions(&opts); err != nil {
		return err
	}
	if cfg == nil {
		cfg = config.Default()
	}

	pipeRes, err := ExecuteScanPipeline(ctx, cfg, opts, nil)
	if err != nil {
		return err
	}
	assessment := pipeRes.Assessment

	// 7. Output rendering and presentation
	outOpts := OutputOptions{
		Format:  opts.Format,
		Output:  opts.Output,
		NoColor: opts.NoColor,
		Verbose: opts.Verbose,
		Quiet:   opts.Quiet,
	}
	if err := RenderAndWrite(assessment, outOpts, out); err != nil {
		return err
	}

	// 8. SSRF private target failure enforcement
	if pipeRes.IsSSRFBlocked {
		return NewExitError(ExitScanFailure, "scan aborted: target %q is a private, loopback, or internal address blocked by SSRF protection", pipeRes.NormalizedURL.Hostname)
	}

	// 10. Optional risk threshold enforcement
	if opts.FailOnRisk != nil && assessment.OverallScore >= *opts.FailOnRisk {
		return NewExitError(ExitRiskThresholdExceeded, "risk score %d meets or exceeds configured threshold %d", assessment.OverallScore, *opts.FailOnRisk)
	}

	return nil
}

// PersistScanAssessment persists a completed or partial scan assessment to local SQLite storage.
func PersistScanAssessment(ctx context.Context, repo storage.Repository, assessment *risk.RiskAssessment, target string, startedAt, completedAt time.Time, duration time.Duration, status storage.ScanStatus) (*storage.ScanRecord, error) {
	if repo == nil || assessment == nil {
		return nil, nil
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	if completedAt.IsZero() {
		completedAt = startedAt.Add(duration)
	}
	if duration <= 0 && !completedAt.IsZero() && !startedAt.IsZero() {
		duration = completedAt.Sub(startedAt)
	}

	record := storage.ScanRecord{
		ID:             uuid.NewString(),
		Target:         target,
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		DurationMs:     duration.Milliseconds(),
		OverallScore:   assessment.OverallScore,
		Classification: assessment.Classification,
		PolicyID:       assessment.PolicyID,
		PolicyVersion:  assessment.PolicyVersion,
		Status:         status,
		SchemaVersion:  assessment.SchemaVersion,
		CreatedAt:      time.Now().UTC(),
	}

	if err := repo.SaveScan(ctx, record, assessment); err != nil {
		return nil, err
	}
	return &record, nil
}

func isSSRFBlockedTarget(host string, webResult *webintel.AnalysisResult) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return true
		}
	}
	if isLocalHost(host) {
		return true
	}
	if webResult != nil && webResult.HTTPStatus.State == webintel.StateFailed {
		errStr := strings.ToLower(webResult.HTTPStatus.Error)
		if strings.Contains(errStr, "blocked or private addresses") ||
			strings.Contains(errStr, "local or internal domain") ||
			strings.Contains(errStr, "prohibited") ||
			strings.Contains(errStr, "ssrf") {
			return true
		}
	}
	return false
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	for _, suffix := range []string{"localhost", "local", "internal", "lan", "home", "home.arpa", "test", "invalid", "onion", "corp", "intranet", "private", "localdomain"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
