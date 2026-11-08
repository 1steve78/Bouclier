package webintel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/heuristics"
	"bouclier/internal/tlscheck"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webcheck"
)

// ComponentState uses the same stable values as internal/tlsintel.
type ComponentState string

const (
	StateCompleted ComponentState = "completed"
	StatePartial   ComponentState = "partial"
	StateFailed    ComponentState = "failed"
	StateSkipped   ComponentState = "skipped"
	StateNoResults ComponentState = "no_results"
)

// ComponentStatus exposes a displayable error and preserves it for errors.Is.
type ComponentStatus struct {
	State ComponentState `json:"state"`
	Error string         `json:"error,omitempty"`
	Err   error          `json:"-"`
}

// AnalysisResult is an explainable report, not a score or verdict.
type AnalysisResult struct {
	RequestedURL     string
	FinalURL         string
	TLS              *tlsintel.AnalysisResult
	HTTP             *webcheck.HTTPInspectionResult
	Findings         []heuristics.Finding
	TLSStatus        ComponentStatus
	HTTPStatus       ComponentStatus
	RedirectsStatus  ComponentStatus
	HeadersStatus    ComponentStatus
	CookiesStatus    ComponentStatus
	CORSStatus       ComponentStatus
	HTMLStatus       ComponentStatus
	DisclosureStatus ComponentStatus
	AnalyzedAt       time.Time
	BodyTruncated    bool
	Complete         bool
}

type tlsAnalyzeFunc func(context.Context, *heuristics.NormalizedURL, tlsintel.Options) (*tlsintel.AnalysisResult, error)
type httpInspectFunc func(context.Context, *heuristics.NormalizedURL) (*webcheck.HTTPInspectionResult, error)

// AnalyzeWebsite runs TLS intelligence for HTTPS targets and a bounded HTTP
// inspection followed by passive response analyzers. Fatal input/setup errors
// return nil; operational component failures are kept in statuses and partial
// results. Context cancellation/deadline returns collected data with a wrapped
// context error. HTTPS inspection retains the requested URL separately from
// any redirect destination; TLS always refers to the requested hostname.
func AnalyzeWebsite(ctx context.Context, input *heuristics.NormalizedURL, options Options) (*AnalysisResult, error) {
	appConfig := options.Config
	if appConfig == nil {
		appConfig = config.Default()
	} else if err := appConfig.Validate(); err != nil {
		return nil, fmt.Errorf("analyze website: invalid configuration: %w", err)
	}
	if options.TLS.Connection.Timeout == 0 && options.TLS.Connection.HandshakeTimeout == 0 {
		connection := tlscheck.ConnectionConfigFromScannerConfig(appConfig.Scanner)
		connection.ServerName = options.TLS.Connection.ServerName
		connection.Port = options.TLS.Connection.Port
		options.TLS.Connection = connection
	}
	if options.HTTPClient == nil {
		if options.ClientOptions.Timeout == 0 {
			options.ClientOptions.Timeout = appConfig.Scanner.HTTPTimeout
		}
		if options.ClientOptions.UserAgent == "" {
			options.ClientOptions.UserAgent = appConfig.Scanner.UserAgent
		}
		if options.Config != nil && options.ClientOptions.MaxRedirects == 0 && !options.ClientOptions.DisableRedirects {
			options.ClientOptions.MaxRedirects = appConfig.Scanner.MaxRedirects
			options.ClientOptions.DisableRedirects = appConfig.Scanner.MaxRedirects == 0
		}
		client, err := webcheck.NewClient(options.ClientOptions)
		if err != nil {
			return nil, fmt.Errorf("analyze website: configure HTTP client: %w", err)
		}
		options.HTTPClient = client
	}
	return analyzeWebsite(ctx, input, options, tlsintel.AnalyzeTLS, options.HTTPClient.Inspect)
}

func analyzeWebsite(ctx context.Context, input *heuristics.NormalizedURL, options Options, analyzeTLS tlsAnalyzeFunc, inspectHTTP httpInspectFunc) (*AnalysisResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("analyze website: context is nil")
	}
	if input == nil {
		return nil, fmt.Errorf("analyze website: normalized URL is nil")
	}
	parsed, err := heuristics.NormalizeURL(input.Normalized)
	if err != nil || parsed.Hostname != input.Hostname || parsed.Scheme != input.Scheme || parsed.Port != input.Port {
		return nil, fmt.Errorf("analyze website: normalized URL is invalid or inconsistent")
	}
	if input.Port != "" && input.Port != "80" && input.Port != "443" {
		return nil, fmt.Errorf("analyze website: destination port must be 80 or 443")
	}
	if analyzeTLS == nil || inspectHTTP == nil {
		return nil, fmt.Errorf("analyze website: analysis components are unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("analyze website: %w", err)
	}

	now := options.CurrentTime
	if now.IsZero() {
		now = options.TLS.CurrentTime
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	options.CurrentTime = now
	options.TLS.CurrentTime = now
	parsedURL, _ := url.Parse(input.Normalized)
	requested := sanitizeURL(parsedURL)
	result := &AnalysisResult{
		RequestedURL: requested, FinalURL: requested,
		Findings: make([]heuristics.Finding, 0), AnalyzedAt: now,
		TLSStatus:       ComponentStatus{State: StateSkipped, Error: "TLS is not applicable to an HTTP URL"},
		HTTPStatus:      ComponentStatus{State: StateFailed},
		RedirectsStatus: ComponentStatus{State: StateSkipped},
		HeadersStatus:   ComponentStatus{State: StateSkipped}, CookiesStatus: ComponentStatus{State: StateSkipped},
		CORSStatus: ComponentStatus{State: StateSkipped}, HTMLStatus: ComponentStatus{State: StateSkipped},
		DisclosureStatus: ComponentStatus{State: StateSkipped},
	}
	if parsed.Scheme == "https" {
		tlsResult, tlsErr := analyzeTLS(ctx, input, options.TLS)
		result.TLS = tlsResult
		if tlsResult == nil && tlsErr == nil {
			tlsErr = errors.New("TLS analysis returned no result")
		}
		if tlsErr != nil {
			result.TLSStatus = status(StateFailed, tlsErr)
		} else {
			result.TLSStatus = ComponentStatus{State: ComponentState(tlsResult.TLSStatus.State)}
		}
		if err := ctx.Err(); err != nil {
			result.Complete = false
			return result, fmt.Errorf("analyze website: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("analyze website: %w", err)
	}
	httpResult, httpErr := inspectHTTP(ctx, input)
	result.HTTP = httpResult
	if httpResult != nil {
		if httpResult.RequestedURL != "" {
			result.RequestedURL = httpResult.RequestedURL
		}
		if httpResult.FinalURL != "" {
			result.FinalURL = httpResult.FinalURL
		}
		result.BodyTruncated = httpResult.BodyTruncated
	}
	if httpErr != nil {
		result.HTTPStatus = status(StateFailed, httpErr)
	} else if httpResult != nil && httpResult.BodyTruncated {
		truncatedErr := errors.New("response body was truncated at the configured limit")
		result.HTTPStatus = status(StatePartial, truncatedErr)
	} else {
		result.HTTPStatus = ComponentStatus{State: StateCompleted}
	}
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("analyze website: %w", err)
	}
	if httpResult == nil || httpResult.StatusCode == 0 {
		if httpErr == nil {
			err = errors.New("HTTP inspection returned no response")
			result.HTTPStatus = status(StateFailed, err)
		}
		result.Complete = false
		return result, nil
	}

	result.RedirectsStatus, result.Findings = runAnalyzer(result.Findings, webcheck.AnalyzeRedirects, httpResult)
	result.HeadersStatus, result.Findings = runAnalyzer(result.Findings, webcheck.AnalyzeSecurityHeaders, httpResult)
	result.CookiesStatus, result.Findings = runAnalyzer(result.Findings, webcheck.AnalyzeCookies, httpResult)
	result.CORSStatus, result.Findings = runAnalyzer(result.Findings, webcheck.AnalyzeCORS, httpResult)
	if httpResult.IsHTML {
		result.HTMLStatus, result.Findings = runAnalyzer(result.Findings, webcheck.AnalyzeHTML, httpResult)
		if httpResult.BodyTruncated && result.HTMLStatus.State == StateCompleted {
			result.HTMLStatus.State = StatePartial
		}
	} else {
		result.HTMLStatus = ComponentStatus{State: StateSkipped, Error: "response content type is not HTML"}
	}
	result.DisclosureStatus, result.Findings = runAnalyzer(result.Findings, webcheck.AnalyzeInformationDisclosure, httpResult)
	result.Findings = deduplicate(result.Findings)
	result.Complete = httpErr == nil && result.HTTPStatus.State == StateCompleted && result.TLSStatus.State != StateFailed &&
		result.RedirectsStatus.State == StateCompleted &&
		result.HeadersStatus.State == StateCompleted && result.CookiesStatus.State == StateCompleted &&
		result.CORSStatus.State == StateCompleted && result.DisclosureStatus.State == StateCompleted &&
		(result.HTMLStatus.State == StateCompleted || result.HTMLStatus.State == StateSkipped)
	return result, contextError(ctx)
}

type analyzerFunc func(*webcheck.HTTPInspectionResult) ([]heuristics.Finding, error)

func runAnalyzer(existing []heuristics.Finding, analyze analyzerFunc, input *webcheck.HTTPInspectionResult) (ComponentStatus, []heuristics.Finding) {
	findings, err := analyze(input)
	if err != nil {
		return status(StateFailed, err), existing
	}
	return ComponentStatus{State: StateCompleted}, append(existing, findings...)
}

func status(state ComponentState, err error) ComponentStatus {
	return ComponentStatus{State: state, Error: err.Error(), Err: err}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("analyze website: %w", err)
	}
	return nil
}

func sanitizeURL(value *url.URL) string {
	copy := *value
	copy.User = nil
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	copy.RawFragment = ""
	return copy.String()
}

func deduplicate(findings []heuristics.Finding) []heuristics.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]heuristics.Finding, 0, len(findings))
	for _, item := range findings {
		key := item.Code + "\x00" + item.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code == out[j].Code {
			return out[i].Evidence < out[j].Evidence
		}
		return out[i].Code < out[j].Code
	})
	return out
}
