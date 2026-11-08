package mcpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/cli"
	"bouclier/internal/config"
	"bouclier/internal/ct"
	"bouclier/internal/heuristics"
	"bouclier/internal/intel"
	"bouclier/internal/model"
	"bouclier/internal/report"
	"bouclier/internal/storage"
	"bouclier/internal/tlscheck"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webcheck"
	"bouclier/internal/webintel"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxMessageURLs   = 3
	maxToolArgsBytes = 1 << 20 // 1 MiB limit for tool argument payloads
	maxMessageBytes  = 1 << 20 // 1 MiB limit for message text to hash
)

var messageURLPattern = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)

type Server struct {
	config *config.Config
	repo   storage.Repository
}

func New(cfg *config.Config, repo storage.Repository) (*mcp.Server, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configure MCP server: %w", err)
	}

	s := &Server{config: cfg, repo: repo}
	server := mcp.NewServer(&mcp.Implementation{
		Name:        "bouclier",
		Version:     cfg.Application.Version,
		Description: "Bouclier phishing and website security analysis tools",
	}, nil)
	s.addTools(server)
	return server, nil
}

type toolHandler func(context.Context, json.RawMessage) (any, error)

func (s *Server) addTools(server *mcp.Server) {
	add := func(name, description, schema string, handler toolHandler) {
		server.AddTool(&mcp.Tool{
			Name:        name,
			Description: description,
			InputSchema: json.RawMessage(schema),
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			value, err := handler(ctx, req.Params.Arguments)
			if err != nil {
				return toolError(err), nil
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return toolError(fmt.Errorf("encode tool result: %w", err)), nil
			}
			return &mcp.CallToolResult{
				Content:           []mcp.Content{&mcp.TextContent{Text: string(encoded)}},
				StructuredContent: value,
			}, nil
		})
	}

	add("check_url", "Run the Bouclier URL risk assessment pipeline.", `{"type":"object","properties":{"url":{"type":"string"},"ai":{"type":"boolean"}},"required":["url"],"additionalProperties":false}`, s.checkURL)
	add("inspect_tls", "Inspect TLS and certificate properties of a public host.", `{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer","default":443}},"required":["host"],"additionalProperties":false}`, s.inspectTLS)
	add("scan_headers", "Inspect public website response security headers without returning page content.", `{"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false}`, s.scanHeaders)
	add("lookup_threat_feeds", "Search local threat intelligence indicators for a host, IP, or URL.", `{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}`, s.lookupThreatFeeds)
	add("analyze_message", "Hash message text and assess up to three extracted HTTP(S) URLs.", `{"type":"object","properties":{"message":{"type":"string"}},"required":["message"],"additionalProperties":false}`, s.analyzeMessage)
	add("get_report", "Retrieve a report from local scan history.", `{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}`, s.getReport)
	add("verify_report", "Verify a locally stored report against its persisted SHA-256 digest.", `{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}`, s.verifyReport)
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		IsError: true,
	}
}

func decodeArgs(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		return errors.New("tool arguments are required")
	}
	if len(raw) > maxToolArgsBytes {
		return errors.New("tool arguments exceed maximum allowed size of 1 MiB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("invalid tool arguments: multiple JSON values")
		}
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	return nil
}

func safeURLLabel(target *heuristics.NormalizedURL) string {
	return target.Scheme + "://" + target.Host + "/"
}

func (s *Server) checkURL(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		URL string `json:"url"`
		AI  bool   `json:"ai"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.URL) == "" {
		return nil, errors.New("url is required")
	}
	if args.AI {
		return nil, errors.New("AI explanations are not configured")
	}
	target, err := normalizePublicURL(args.URL)
	if err != nil {
		return nil, err
	}
	result, err := cli.ExecuteScanPipeline(ctx, s.config, cli.ScanOptions{
		Target: target.Normalized, NoPersist: true,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("scan URL: %w", err)
	}
	if result == nil || result.Assessment == nil {
		return nil, errors.New("scan pipeline returned no assessment")
	}
	if result.IsSSRFBlocked {
		return nil, errors.New("URL destination is not allowed")
	}
	payload, err := report.RenderJSON(result.Assessment)
	if err != nil {
		return nil, fmt.Errorf("render scan report: %w", err)
	}
	var response any
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("decode rendered scan report: %w", err)
	}
	return response, nil
}

type tlsToolResult struct {
	Target                  string                            `json:"target"`
	Port                    string                            `json:"port"`
	Handshake               bool                              `json:"handshake_success"`
	NegotiatedTLS           string                            `json:"negotiated_tls,omitempty"`
	CipherSuite             uint16                            `json:"cipher_suite,omitempty"`
	TLSStatus               tlsintel.ComponentStatus          `json:"tls_status"`
	CertificateStatus       tlsintel.ComponentStatus          `json:"certificate_status"`
	CTStatus                tlsintel.ComponentStatus          `json:"ct_status"`
	CertificateTransparency []ct.CTEntry                      `json:"certificate_transparency"`
	Certificate             *certanalysis.CertificateAnalysis `json:"certificate,omitempty"`
	Findings                []certanalysis.Finding            `json:"findings"`
}

func (s *Server) inspectTLS(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Host) == "" {
		return nil, errors.New("host is required")
	}
	if args.Port == 0 {
		args.Port = 443
	}
	if args.Port < 1 || args.Port > 65535 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	host := strings.TrimSpace(args.Host)
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#@") {
		return nil, errors.New("host must be a hostname or IP address without a scheme, path, or credentials")
	}
	input, err := heuristics.NormalizeURL("https://" + net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(args.Port)) + "/")
	if err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}
	if err := validatePublicHostname(input.Hostname); err != nil {
		return nil, err
	}
	connection := tlscheck.ConnectionConfigFromScannerConfig(s.config.Scanner)
	connection.Port = fmt.Sprint(args.Port)
	provider, err := ct.NewCTLogsDevProvider(ct.CTLogsDevOptions{})
	if err != nil {
		return nil, fmt.Errorf("configure certificate transparency lookup: %w", err)
	}
	result, err := tlsintel.AnalyzeTLS(ctx, input, tlsintel.Options{
		Connection: connection, CTProvider: provider, CTScope: ct.ScopeExactHostname,
	})
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("inspect TLS: %w", ctx.Err())
	}
	if result == nil {
		if err != nil {
			return nil, fmt.Errorf("inspect TLS: %w", err)
		}
		return nil, errors.New("inspect TLS returned no result")
	}
	out := tlsToolResult{
		Target: result.TargetHostname, Port: fmt.Sprint(args.Port),
		TLSStatus: result.TLSStatus, Certificate: result.Certificate,
		CertificateStatus: result.CertificateStatus, CTStatus: result.CTStatus,
		CertificateTransparency: result.CertificateTransparency, Findings: result.Findings,
	}
	if result.Connection != nil {
		out.Handshake = result.Connection.HandshakeSuccess
		out.NegotiatedTLS = result.Connection.NegotiatedTLS
		out.CipherSuite = result.Connection.CipherSuite
	}
	return out, nil
}

type headersToolResult struct {
	Target        string                   `json:"target"`
	FinalURL      string                   `json:"final_url"`
	StatusCode    int                      `json:"status_code,omitempty"`
	HeaderNames   []string                 `json:"header_names"`
	Findings      []heuristics.Finding     `json:"findings"`
	TLSStatus     webintel.ComponentStatus `json:"tls_status"`
	HTTPStatus    webintel.ComponentStatus `json:"http_status"`
	HeadersStatus webintel.ComponentStatus `json:"headers_status"`
}

func (s *Server) scanHeaders(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		URL string `json:"url"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	target, err := normalizePublicURL(args.URL)
	if err != nil {
		return nil, err
	}
	result, err := webintel.AnalyzeWebsite(ctx, target, webintel.Options{Config: s.config})
	if err != nil {
		return nil, fmt.Errorf("inspect website headers: %w", err)
	}
	if result == nil {
		return nil, errors.New("website analysis returned no result")
	}
	if result.HTTPStatus.Err != nil && errors.Is(result.HTTPStatus.Err, webcheck.ErrUnsafeTarget) {
		return nil, errors.New("URL destination is not allowed")
	}
	out := headersToolResult{
		Target: result.RequestedURL, FinalURL: result.FinalURL,
		Findings: result.Findings, TLSStatus: result.TLSStatus,
		HTTPStatus: result.HTTPStatus, HeadersStatus: result.HeadersStatus,
		HeaderNames: []string{},
	}
	if result.HTTP != nil {
		out.StatusCode = result.HTTP.StatusCode
		for name := range result.HTTP.Headers {
			out.HeaderNames = append(out.HeaderNames, name)
		}
		sort.Strings(out.HeaderNames)
	}
	return out, nil
}

func (s *Server) lookupThreatFeeds(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Value string `json:"value"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Value) == "" {
		return nil, errors.New("value is required")
	}
	if s.repo == nil {
		return nil, errors.New("local threat intelligence storage is unavailable")
	}
	value := strings.TrimSpace(args.Value)
	target, err := normalizeLookupValue(value)
	if err != nil {
		return nil, err
	}
	domainInfo, err := heuristics.ExtractDomainInfo(target)
	if err != nil {
		return nil, fmt.Errorf("extract lookup domain: %w", err)
	}
	ips := []string(nil)
	if address, parseErr := netip.ParseAddr(target.Hostname); parseErr == nil {
		ips = append(ips, address.String())
	}
	summary, err := intel.NewMatcher(s.repo).MatchTarget(ctx, intel.ExtractCoordinates(target, domainInfo, ips))
	if err != nil {
		return nil, fmt.Errorf("lookup threat indicators: %w", err)
	}
	summary.Target = target.Scheme + "://" + target.Host + "/"
	return summary, nil
}

type messageToolResult struct {
	Report     model.Report `json:"report"`
	URLReports []any        `json:"url_reports"`
}

func (s *Server) analyzeMessage(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Message string `json:"message"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.Message) == "" {
		return nil, errors.New("message is required")
	}
	if len(args.Message) > maxMessageBytes {
		return nil, errors.New("message exceeds maximum allowed size of 1 MiB")
	}
	digest := sha256.Sum256([]byte(args.Message))
	now := time.Now().UTC()
	msgReport := model.Report{
		SchemaVersion: 1, ID: uuid.NewString(), Kind: model.ReportKindMessage,
		Target:    model.ReportTarget{MessageSHA256: hex.EncodeToString(digest[:])},
		RiskLevel: model.RiskLevelLowRisk, Score: 0,
		Findings: []model.Finding{}, Indicators: []model.Indicator{},
		Checks:        []model.Check{{Module: model.ModuleMessage, Status: model.CheckStatusCompleted, Detail: "Message text was hashed; up to three HTTP(S) URLs were extracted for analysis."}},
		RedirectChain: []model.RedirectChainEntry{}, ScannedAt: now.Format("2006-01-02T15:04:05Z"),
		EngineVersion: s.config.Application.Version, Precautions: []string{"A low message score does not establish that the message is safe."},
		Limitations: []string{"Message text is not retained in the report.", "Only the first three distinct HTTP(S) URLs are analyzed."},
	}
	hash, err := model.HashReport(msgReport)
	if err != nil {
		return nil, fmt.Errorf("hash message report: %w", err)
	}
	msgReport.ReportHash = hash
	if err := msgReport.Validate(); err != nil {
		return nil, fmt.Errorf("validate message report: %w", err)
	}

	reports := make([]any, 0, maxMessageURLs)
	seen := make(map[string]struct{})
	for _, rawURL := range messageURLPattern.FindAllString(args.Message, -1) {
		rawURL = strings.TrimRight(rawURL, ".,;:!?)]}")
		key := strings.ToLower(rawURL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		target, normalizeErr := normalizePublicURL(rawURL)
		if normalizeErr != nil {
			reports = append(reports, map[string]any{"url_index": len(reports) + 1, "error": normalizeErr.Error()})
			if len(reports) == maxMessageURLs {
				break
			}
			continue
		}
		result, scanErr := cli.ExecuteScanPipeline(ctx, s.config, cli.ScanOptions{
			Target: target.Normalized, NoPersist: true,
		}, nil)
		if scanErr != nil {
			reports = append(reports, map[string]any{"url": safeURLLabel(target), "error": scanErr.Error()})
		} else if result == nil || result.Assessment == nil {
			reports = append(reports, map[string]any{"url": safeURLLabel(target), "error": "scan pipeline returned no assessment"})
		} else if result.IsSSRFBlocked {
			reports = append(reports, map[string]any{"url": safeURLLabel(target), "error": "URL destination is not allowed"})
		} else {
			payload, renderErr := report.RenderJSON(result.Assessment)
			if renderErr != nil {
				reports = append(reports, map[string]any{"url": safeURLLabel(target), "error": fmt.Errorf("render scan report: %w", renderErr).Error()})
			} else {
				var rendered any
				if err := json.Unmarshal(payload, &rendered); err != nil {
					reports = append(reports, map[string]any{"url": safeURLLabel(target), "error": fmt.Errorf("decode rendered scan report: %w", err).Error()})
				} else {
					reports = append(reports, map[string]any{"url": safeURLLabel(target), "report": rendered})
				}
			}
		}
		if len(reports) == maxMessageURLs {
			break
		}
	}
	return messageToolResult{Report: msgReport, URLReports: reports}, nil
}

func (s *Server) getReport(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		ID string `json:"id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.ID) == "" {
		return nil, errors.New("id is required")
	}
	if s.repo == nil {
		return nil, errors.New("local scan history is unavailable")
	}
	report, err := s.repo.GetScanReport(ctx, strings.TrimSpace(args.ID))
	if err != nil {
		return nil, fmt.Errorf("get report: %w", err)
	}
	var payload any
	if err := json.Unmarshal([]byte(report.ReportJSON), &payload); err != nil {
		return nil, fmt.Errorf("decode stored report: %w", err)
	}
	return payload, nil
}

type verifyReportResult struct {
	ID             string `json:"id"`
	Verified       bool   `json:"verified"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256"`
	Detail         string `json:"detail"`
}

func (s *Server) verifyReport(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		ID string `json:"id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.ID) == "" {
		return nil, errors.New("id is required")
	}
	if s.repo == nil {
		return nil, errors.New("local scan history is unavailable")
	}
	report, err := s.repo.GetScanReport(ctx, strings.TrimSpace(args.ID))
	if err != nil {
		return nil, fmt.Errorf("load report for verification: %w", err)
	}
	actual := sha256.Sum256([]byte(report.ReportJSON))
	actualHash := "0x" + hex.EncodeToString(actual[:])
	result := verifyReportResult{
		ID: report.ScanID, ActualSHA256: actualHash,
		ExpectedSHA256: report.ReportHash,
	}
	if report.ReportHash == "" {
		result.Detail = "This report predates stored integrity digests and cannot be verified."
		return result, nil
	}
	result.Verified = subtle.ConstantTimeCompare([]byte(actualHash), []byte(report.ReportHash)) == 1
	if result.Verified {
		result.Detail = "Stored report matches its persisted SHA-256 digest."
	} else {
		result.Detail = "Stored report does not match its persisted SHA-256 digest."
	}
	return result, nil
}

func normalizePublicURL(raw string) (*heuristics.NormalizedURL, error) {
	target, err := heuristics.NormalizeURL(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if target.HasUserInfo {
		return nil, errors.New("URL credentials are not allowed")
	}
	if err := webcheck.ValidateTarget(target); err != nil {
		if errors.Is(err, webcheck.ErrUnsafeTarget) {
			return nil, errors.New("URL destination is not allowed")
		}
		return nil, fmt.Errorf("invalid URL destination: %w", err)
	}
	return target, nil
}

func validatePublicHostname(host string) error {
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
			return errors.New("host must resolve to a public IP address")
		}
		return nil
	}
	target, err := heuristics.NormalizeURL("https://" + host + "/")
	if err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}
	if err := webcheck.ValidateTarget(target); err != nil {
		if errors.Is(err, webcheck.ErrUnsafeTarget) {
			return errors.New("host is local or internal and is not allowed")
		}
		return fmt.Errorf("invalid host: %w", err)
	}
	return nil
}

func normalizeLookupValue(value string) (*heuristics.NormalizedURL, error) {
	if target, err := heuristics.NormalizeURL(value); err == nil {
		if target.HasUserInfo {
			return nil, errors.New("lookup URL credentials are not allowed")
		}
		return target, nil
	}
	if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return heuristics.NormalizeURL("https://" + net.JoinHostPort(address.String(), "443") + "/")
	}
	return heuristics.NormalizeURL("https://" + value + "/")
}
