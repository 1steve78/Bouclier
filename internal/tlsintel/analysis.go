package tlsintel

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/config"
	"bouclier/internal/ct"
	"bouclier/internal/heuristics"
	"bouclier/internal/tlscheck"
)

// ComponentState describes the outcome of one pipeline stage.
type ComponentState string

const (
	StateCompleted ComponentState = "completed"
	StatePartial   ComponentState = "partial"
	StateFailed    ComponentState = "failed"
	StateSkipped   ComponentState = "skipped"
	StateNoResults ComponentState = "no_results"
)

// ComponentStatus retains a stage error for programmatic inspection. Error is
// suitable for display; Err is excluded from JSON serialization.
type ComponentStatus struct {
	State ComponentState `json:"state"`
	Error string         `json:"error,omitempty"`
	Err   error          `json:"-"`
}

// AnalysisResult contains one sequential TLS intelligence run. CT records are
// contextual issuance observations and are never folded into Findings.
type AnalysisResult struct {
	TargetHostname          string
	Connection              *tlscheck.TLSConnectionResult
	Certificate             *certanalysis.CertificateAnalysis
	CertificateTransparency []ct.CTEntry
	Findings                []certanalysis.Finding
	TLSStatus               ComponentStatus
	CertificateStatus       ComponentStatus
	CTStatus                ComponentStatus
	AnalyzedAt              time.Time
}

// AnalyzeTLS inspects TLS, analyzes any available peer certificates, then
// optionally queries CT. Fatal input errors return a nil result. Operational
// component errors are retained in their ComponentStatus and a partial result
// is returned with a nil overall error; cancellation/deadline errors are
// returned alongside any partial result so errors.Is remains useful.
//
// Exact-hostname CT scope is the default. Registrable-domain scope must be
// explicitly requested and is derived with the existing PSL-aware model.
func AnalyzeTLS(ctx context.Context, input *heuristics.NormalizedURL, options Options) (*AnalysisResult, error) {
	return analyzeTLS(ctx, input, options, tlscheck.InspectConnection, certanalysis.AnalyzeCertificates)
}

type inspectFunc func(context.Context, string, tlscheck.ConnectionConfig) (*tlscheck.TLSConnectionResult, error)
type certificateAnalysisFunc func(*tlscheck.TLSConnectionResult, certanalysis.Config) (*certanalysis.CertificateAnalysis, error)

func analyzeTLS(ctx context.Context, input *heuristics.NormalizedURL, options Options, inspect inspectFunc, analyzeCertificates certificateAnalysisFunc) (*AnalysisResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("analyze TLS intelligence: context is nil")
	}
	if input == nil {
		return nil, fmt.Errorf("analyze TLS intelligence: normalized URL is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("analyze TLS intelligence: %w", err)
	}

	parsed, err := heuristics.NormalizeURL(input.Normalized)
	if err != nil {
		return nil, fmt.Errorf("analyze TLS intelligence: validate normalized URL: %w", err)
	}
	if input.Hostname == "" || parsed.Hostname != input.Hostname || parsed.Scheme != input.Scheme || parsed.Port != input.Port {
		return nil, fmt.Errorf("analyze TLS intelligence: normalized URL hostname is empty or inconsistent")
	}
	domain, err := heuristics.ExtractDomainInfo(input)
	if err != nil {
		return nil, fmt.Errorf("analyze TLS intelligence: validate hostname: %w", err)
	}
	if options.CTScope == "" {
		options.CTScope = ct.ScopeExactHostname
	}
	if options.CTScope != ct.ScopeExactHostname && options.CTScope != ct.ScopeRegistrableDomain {
		return nil, fmt.Errorf("analyze TLS intelligence: unsupported CT query scope %q", options.CTScope)
	}
	if options.CTLimit < 0 || options.CTLimit > ct.MaxLimit {
		return nil, fmt.Errorf("analyze TLS intelligence: CT result limit must be zero or between 1 and %d", ct.MaxLimit)
	}

	connectionConfig := options.Connection
	if connectionConfig.Timeout == 0 && connectionConfig.HandshakeTimeout == 0 {
		defaults := tlscheck.ConnectionConfigFromScannerConfig(config.Default().Scanner)
		defaults.ServerName = connectionConfig.ServerName
		defaults.Port = connectionConfig.Port
		connectionConfig = defaults
	}
	if connectionConfig.Timeout <= 0 || connectionConfig.HandshakeTimeout <= 0 {
		return nil, fmt.Errorf("analyze TLS intelligence: connection and handshake timeouts must be positive")
	}
	if input.Port != "" {
		connectionConfig.Port = input.Port
	}
	if options.CurrentTime.IsZero() {
		options.CurrentTime = options.Certificate.CurrentTime
	}
	if options.CurrentTime.IsZero() {
		options.CurrentTime = time.Now().UTC()
	}
	options.CurrentTime = options.CurrentTime.UTC()
	options.Certificate.CurrentTime = options.CurrentTime

	result := &AnalysisResult{
		TargetHostname: domain.Hostname,
		Findings:       make([]certanalysis.Finding, 0),
		TLSStatus:      ComponentStatus{State: StateFailed},
		CertificateStatus: ComponentStatus{State: StateSkipped,
			Error: "certificate analysis skipped because no peer certificates are available"},
		CTStatus:   ComponentStatus{State: StateSkipped, Error: "CT lookup has not been run"},
		AnalyzedAt: options.CurrentTime,
	}

	tlsResult, tlsErr := inspect(ctx, domain.Hostname, connectionConfig)
	if tlsErr == nil && tlsResult == nil {
		tlsErr = errors.New("TLS inspection returned no result")
	}
	result.Connection = tlsResult
	if tlsErr != nil {
		setStatus(&result.TLSStatus, StateFailed, tlsErr)
	} else {
		result.TLSStatus = ComponentStatus{State: StateCompleted}
	}
	if tlsResult != nil && len(tlsResult.PeerCertificates) > 0 {
		certificateResult, certificateErr := analyzeCertificates(tlsResult, options.Certificate)
		result.Certificate = certificateResult
		if certificateErr != nil {
			setStatus(&result.CertificateStatus, StateFailed, certificateErr)
		} else {
			result.CertificateStatus = ComponentStatus{State: StateCompleted}
			result.Findings = append(result.Findings, certificateResult.Findings...)
		}
	}

	if isNilProvider(options.CTProvider) {
		result.CTStatus = ComponentStatus{State: StateSkipped, Error: "no CT provider configured"}
		return result, contextError(ctx)
	}
	if domain.IsIPAddress {
		result.CTStatus = ComponentStatus{State: StateSkipped, Error: "CT hostname queries do not support IP literals"}
		return result, contextError(ctx)
	}
	queryDomain := domain.Hostname
	if options.CTScope == ct.ScopeRegistrableDomain {
		if domain.RegistrableDomain == "" {
			result.CTStatus = ComponentStatus{State: StateSkipped, Error: "hostname has no registrable domain for CT lookup"}
			return result, contextError(ctx)
		}
		queryDomain = domain.RegistrableDomain
	}
	entries, ctErr := ct.QueryEntries(ctx, options.CTProvider, ct.Query{
		Domain: queryDomain, Scope: options.CTScope, Limit: options.CTLimit,
	})
	result.CertificateTransparency = entries
	switch {
	case errors.Is(ctErr, ct.ErrResultsTruncated):
		setStatus(&result.CTStatus, StatePartial, ctErr)
	case errors.Is(ctErr, ct.ErrNoResults):
		setStatus(&result.CTStatus, StateNoResults, ctErr)
	case ctErr != nil:
		setStatus(&result.CTStatus, StateFailed, ctErr)
	default:
		result.CTStatus = ComponentStatus{State: StateCompleted}
	}
	result.Findings = deduplicateFindings(result.Findings)
	return result, contextError(ctx)
}

func isNilProvider(provider ct.Provider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func setStatus(status *ComponentStatus, state ComponentState, err error) {
	status.State = state
	if err != nil {
		status.Error = err.Error()
		status.Err = err
	}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("analyze TLS intelligence: %w", err)
	}
	return nil
}

func deduplicateFindings(findings []certanalysis.Finding) []certanalysis.Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]certanalysis.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Code + "\x00" + finding.Evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Code != result[j].Code {
			return result[i].Code < result[j].Code
		}
		return result[i].Evidence < result[j].Evidence
	})
	return result
}
