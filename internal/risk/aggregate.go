package risk

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"bouclier/internal/domain"
	"bouclier/internal/heuristics"
	"bouclier/internal/registration"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webintel"
)

// AggregationInput references existing layer results instead of copying them.
type AggregationInput struct {
	Target            string
	AnalyzedAt        time.Time
	URL               *heuristics.AnalysisResult
	Domain            *domain.AnalysisResult
	TLS               *tlsintel.AnalysisResult
	Web               *webintel.AnalysisResult
	RegistrationAge   *registration.AgeAnalysis
	IntelObservations []Observation
	IntelCoverage     *IntelligenceCoverage
	Coverage          []ComponentCoverage
	Limitations       []string
}

// Aggregate combines existing observations, coverage, and optional
// registration-age context. Registration age is not scored because that layer
// currently exposes no finding code and explicitly assigns no risk.
func Aggregate(input AggregationInput, policy Policy) (*RiskAssessment, error) {
	target := input.Target
	if strings.TrimSpace(target) == "" {
		target = inferTarget(input)
	}
	canonical, err := canonicalTarget(target)
	if err != nil {
		return nil, err
	}
	observations := make([]Observation, 0)
	if input.URL != nil {
		for _, f := range input.URL.Findings {
			observations = append(observations, FromHeuristicFinding(f, SourceURL))
		}
	}
	if input.Domain != nil {
		for _, f := range input.Domain.Findings {
			observations = append(observations, FromHeuristicFinding(f, SourceDomain))
		}
	}
	tlsInput := input.TLS
	if tlsInput == nil && input.Web != nil {
		tlsInput = input.Web.TLS
	}
	if tlsInput != nil {
		for _, f := range tlsInput.Findings {
			observations = append(observations, Observation{Code: f.Code, Title: f.Title, Description: f.Description, Category: f.Category, Evidence: f.Evidence, Source: SourceTLS})
		}
	}
	if input.Web != nil {
		for _, f := range input.Web.Findings {
			observations = append(observations, FromHeuristicFinding(f, SourceWeb))
		}
	}
	if len(input.IntelObservations) > 0 {
		observations = append(observations, input.IntelObservations...)
	}
	registrationAge := input.RegistrationAge
	if registrationAge == nil && input.Domain != nil {
		registrationAge = input.Domain.RegistrationAge
	}
	findings, err := NormalizeFindings(observations, canonical)
	if err != nil {
		return nil, fmt.Errorf("aggregate risk findings: %w", err)
	}
	assessment, err := CalculateRisk(findings, policy)
	if err != nil {
		return nil, err
	}
	assessment.Target = canonical
	assessment.AnalyzedAt = analysisTime(input)
	assessment.AnalysisCoverage = buildCoverage(input, registrationAge)
	if input.IntelCoverage != nil {
		assessment.Intelligence = input.IntelCoverage
		intelState := ComponentCompleted
		intelDetail := fmt.Sprintf("%d matches, %d indicators evaluated", input.IntelCoverage.MatchesCount, input.IntelCoverage.IndicatorsConsidered)
		if input.IntelCoverage.DatabaseUnavailable {
			intelState = ComponentFailed
			intelDetail = "threat intelligence database unavailable"
		} else if !input.IntelCoverage.Ran {
			intelState = ComponentSkipped
			intelDetail = "threat intelligence matching skipped"
		} else if input.IntelCoverage.DatabaseStale {
			intelState = ComponentPartial
			intelDetail = "threat intelligence database is stale"
		} else if input.IntelCoverage.MatchesCount == 0 {
			intelState = ComponentNoResults
			intelDetail = "no threat intelligence matches found"
		}
		assessment.AnalysisCoverage = append(assessment.AnalysisCoverage, ComponentCoverage{
			Component: "threat-intelligence",
			State:     intelState,
			Detail:    intelDetail,
		})
	}
	assessment.RegistrationAge = cloneAge(registrationAge)
	assessment.Limitations = append([]string(nil), input.Limitations...)
	for _, coverage := range assessment.AnalysisCoverage {
		if coverage.State == ComponentSkipped || coverage.State == ComponentPartial || coverage.State == ComponentFailed || coverage.State == ComponentNoResults {
			assessment.Limitations = append(assessment.Limitations, coverage.Component+" coverage is "+string(coverage.State)+"; absence of findings is not a clean result")
		}
	}
	if assessment.AnalyzedAt.IsZero() {
		assessment.Limitations = append(assessment.Limitations, "analysis timestamp was not supplied by an input component")
	}
	assessment.Limitations = uniqueSorted(assessment.Limitations)
	return assessment, nil
}

// AggregateDefault uses the built-in versioned scoring policy.
func AggregateDefault(input AggregationInput) (*RiskAssessment, error) {
	return Aggregate(input, DefaultPolicy())
}

func inferTarget(input AggregationInput) string {
	if input.URL != nil && input.URL.NormalizedURL != nil && input.URL.NormalizedURL.Hostname != "" {
		return input.URL.NormalizedURL.Hostname
	}
	if input.Domain != nil && input.Domain.DomainInfo != nil && input.Domain.DomainInfo.Hostname != "" {
		return input.Domain.DomainInfo.Hostname
	}
	tlsInput := input.TLS
	if tlsInput == nil && input.Web != nil {
		tlsInput = input.Web.TLS
	}
	if tlsInput != nil && tlsInput.TargetHostname != "" {
		return tlsInput.TargetHostname
	}
	if input.Web != nil {
		for _, value := range []string{input.Web.RequestedURL, input.Web.FinalURL} {
			if parsed, err := heuristics.NormalizeURL(value); err == nil {
				return parsed.Hostname
			}
		}
	}
	return "unknown-target"
}

func analysisTime(input AggregationInput) time.Time {
	if !input.AnalyzedAt.IsZero() {
		return input.AnalyzedAt.UTC()
	}
	var latest time.Time
	tlsInput := input.TLS
	if tlsInput == nil && input.Web != nil {
		tlsInput = input.Web.TLS
	}
	if tlsInput != nil && tlsInput.AnalyzedAt.After(latest) {
		latest = tlsInput.AnalyzedAt
	}
	if input.Web != nil && input.Web.AnalyzedAt.After(latest) {
		latest = input.Web.AnalyzedAt
	}
	return latest.UTC()
}

func buildCoverage(input AggregationInput, registrationAge *registration.AgeAnalysis) []ComponentCoverage {
	coverage := make([]ComponentCoverage, 0, 15)
	coverage = append(coverage, presenceCoverage("url_analysis", input.URL != nil))
	coverage = append(coverage, presenceCoverage("domain_analysis", input.Domain != nil))
	tlsResult := input.TLS
	if tlsResult == nil && input.Web != nil {
		tlsResult = input.Web.TLS
	}
	if tlsResult == nil {
		coverage = append(coverage, presenceCoverage("tls_connection", false), presenceCoverage("certificate_analysis", false), presenceCoverage("ct_lookup", false))
	} else {
		coverage = append(coverage, statusCoverage("tls_connection", tlsResult.TLSStatus.State), statusCoverage("certificate_analysis", tlsResult.CertificateStatus.State), statusCoverage("ct_lookup", tlsResult.CTStatus.State))
	}
	if input.Web == nil {
		for _, name := range []string{"web_http_inspection", "web_redirect_analysis", "web_security_headers", "web_cookies", "web_cors", "web_html", "web_information_disclosure"} {
			coverage = append(coverage, presenceCoverage(name, false))
		}
	} else {
		coverage = append(coverage,
			statusCoverage("web_http_inspection", input.Web.HTTPStatus.State), statusCoverage("web_redirect_analysis", input.Web.RedirectsStatus.State),
			statusCoverage("web_security_headers", input.Web.HeadersStatus.State), statusCoverage("web_cookies", input.Web.CookiesStatus.State),
			statusCoverage("web_cors", input.Web.CORSStatus.State), statusCoverage("web_html", input.Web.HTMLStatus.State),
			statusCoverage("web_information_disclosure", input.Web.DisclosureStatus.State))
	}
	if registrationAge == nil {
		coverage = append(coverage, presenceCoverage("registration_age", false))
	} else if registrationAge.Status == registration.AgeStatusUnavailable || registrationAge.Status == registration.AgeStatusRedacted {
		coverage = append(coverage, ComponentCoverage{Component: "registration_age", State: ComponentNoResults, Detail: "creation date unavailable or redacted; no age conclusion was drawn"})
	} else {
		coverage = append(coverage, ComponentCoverage{Component: "registration_age", State: ComponentCompleted, Detail: "age is contextual and not scored"})
	}
	coverage = append(coverage, input.Coverage...)
	sort.Slice(coverage, func(i, j int) bool {
		if coverage[i].Component == coverage[j].Component {
			return coverage[i].State < coverage[j].State
		}
		return coverage[i].Component < coverage[j].Component
	})
	return coverage
}

func presenceCoverage(name string, present bool) ComponentCoverage {
	if present {
		return ComponentCoverage{Component: name, State: ComponentCompleted}
	}
	return ComponentCoverage{Component: name, State: ComponentSkipped, Detail: "no result supplied"}
}

func statusCoverage(name string, state any) ComponentCoverage {
	value := stringValue(state)
	result := ComponentState(value)
	switch result {
	case ComponentCompleted, ComponentPartial, ComponentFailed, ComponentSkipped, ComponentNoResults:
	default:
		result = ComponentFailed
	}
	detail := ""
	if result == ComponentPartial || result == ComponentFailed || result == ComponentSkipped || result == ComponentNoResults {
		detail = "component did not provide complete positive coverage"
	}
	return ComponentCoverage{Component: name, State: result, Detail: detail}
}

func stringValue(value any) string {
	if text, ok := value.(interface{ String() string }); ok {
		return text.String()
	}
	return fmt.Sprint(value)
}

func cloneAge(source *registration.AgeAnalysis) *registration.AgeAnalysis {
	if source == nil {
		return nil
	}
	copy := *source
	if source.Age != nil {
		age := *source.Age
		copy.Age = &age
	}
	return &copy
}

func uniqueSorted(values []string) []string {
	set := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !set[value] {
			set[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
