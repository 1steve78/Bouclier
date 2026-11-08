package ct

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ctLogsDevBaseURL          = "https://api.ctlogs.dev"
	defaultCTRequestTimeout   = 10 * time.Second
	maxCTRequestTimeout       = 2 * time.Minute
	defaultCTMaxCertificates  = 100
	maxCTMaxCertificates      = 1000
	defaultCTMaxPages         = 10
	maxCTMaxPages             = 100
	defaultCTMaxResponseBytes = 4 << 20
	maxCTMaxResponseBytes     = 16 << 20
)

// ctLogsDevRequestGate enforces the service's one-request-at-a-time capacity
// across all provider instances in this process.
var ctLogsDevRequestGate = make(chan struct{}, 1)

// CTLogsDevOptions configures bounded retrieval. HTTPClient is copied and its
// redirect policy is replaced so requests cannot leave the trusted API origin.
type CTLogsDevOptions struct {
	HTTPClient           *http.Client
	RequestTimeout       time.Duration
	APIKey               string
	MaxCertificates      int
	MaxPages             int
	MaxResponseBodyBytes int64
}

// CTLogsDevProvider adapts ctlogs.dev's JSON API to Provider. Its production
// origin is fixed; it makes requests sequentially and does not retry.
type CTLogsDevProvider struct {
	client               *http.Client
	timeout              time.Duration
	apiKey               string
	maxCertificates      int
	maxPages             int
	maxResponseBodyBytes int64
	baseURL              *url.URL
}

// NewCTLogsDevProvider creates a provider fixed to https://api.ctlogs.dev.
// Zero-valued limits select documented safe defaults; nonzero values are
// bounded to prevent unbounded network and memory use.
func NewCTLogsDevProvider(options CTLogsDevOptions) (*CTLogsDevProvider, error) {
	return newCTLogsDevProvider(options, ctLogsDevBaseURL)
}

// newCTLogsDevProvider allows package tests to use an httptest server without
// exposing a configurable production API base URL.
func newCTLogsDevProvider(options CTLogsDevOptions, base string) (*CTLogsDevProvider, error) {
	if options.RequestTimeout == 0 {
		options.RequestTimeout = defaultCTRequestTimeout
	}
	if options.MaxCertificates == 0 {
		options.MaxCertificates = defaultCTMaxCertificates
	}
	if options.MaxPages == 0 {
		options.MaxPages = defaultCTMaxPages
	}
	if options.MaxResponseBodyBytes == 0 {
		options.MaxResponseBodyBytes = defaultCTMaxResponseBytes
	}
	if options.RequestTimeout < time.Millisecond || options.RequestTimeout > maxCTRequestTimeout {
		return nil, fmt.Errorf("create ctlogs.dev provider: request timeout must be between 1ms and %s", maxCTRequestTimeout)
	}
	if options.MaxCertificates < 1 || options.MaxCertificates > maxCTMaxCertificates {
		return nil, fmt.Errorf("create ctlogs.dev provider: maximum certificates must be between 1 and %d", maxCTMaxCertificates)
	}
	if options.MaxPages < 1 || options.MaxPages > maxCTMaxPages {
		return nil, fmt.Errorf("create ctlogs.dev provider: maximum pages must be between 1 and %d", maxCTMaxPages)
	}
	if options.APIKey == "" && options.MaxPages > 10 {
		return nil, fmt.Errorf("create ctlogs.dev provider: anonymous API use is limited to 10 pages")
	}
	if options.MaxResponseBodyBytes < 1 || options.MaxResponseBodyBytes > maxCTMaxResponseBytes {
		return nil, fmt.Errorf("create ctlogs.dev provider: response limit must be between 1 and %d bytes", maxCTMaxResponseBytes)
	}
	if strings.ContainsAny(options.APIKey, "\r\n\t ") {
		return nil, fmt.Errorf("create ctlogs.dev provider: API key contains invalid whitespace")
	}
	baseURL, err := url.Parse(base)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "https" && baseURL.Scheme != "http") || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("create ctlogs.dev provider: invalid internal API origin")
	}
	baseClient := options.HTTPClient
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	clientCopy := *baseClient
	client := &clientCopy
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &CTLogsDevProvider{
		client: client, timeout: options.RequestTimeout, apiKey: options.APIKey,
		maxCertificates: options.MaxCertificates, maxPages: options.MaxPages,
		maxResponseBodyBytes: options.MaxResponseBodyBytes, baseURL: baseURL,
	}, nil
}

// Search retrieves certificate detail records and maps each API sighting to a
// CTEntry. QueryEntries remains responsible for normalization and final scope
// filtering. Partial entries are returned with ErrResultsTruncated whenever a
// provider cap or the API's history window prevents an exhaustive response.
func (p *CTLogsDevProvider) Search(ctx context.Context, query Query) ([]CTEntry, error) {
	if p == nil || p.client == nil || p.baseURL == nil {
		return nil, fmt.Errorf("ctlogs.dev search: %w", ErrProviderUnavailable)
	}
	if ctx == nil {
		return nil, fmt.Errorf("ctlogs.dev search: %w: context is nil", ErrUnsupportedQuery)
	}
	normalized, err := NormalizeQuery(query)
	if err != nil {
		return nil, err
	}
	searchPath := "/v1/domain/" + url.PathEscape(normalized.Domain)
	if normalized.Scope == ScopeRegistrableDomain {
		searchPath = "/v1/subdomains/" + url.PathEscape(normalized.Domain)
	}
	entries := make([]CTEntry, 0)
	seenIDs := make(map[string]struct{})
	cursors := make(map[string]struct{})
	cursor := ""
	certificateLookups := 0
	historyTruncated := false

	for page := 0; page < p.maxPages; page++ {
		endpoint, buildErr := p.endpoint(searchPath, cursor)
		if buildErr != nil {
			return nil, fmt.Errorf("ctlogs.dev search: build request: %w", buildErr)
		}
		var response searchResponse
		status, requestErr := p.getJSON(ctx, endpoint, &response, true)
		if requestErr != nil {
			if errors.Is(requestErr, ErrNoResults) && len(entries) > 0 {
				return nil, fmt.Errorf("ctlogs.dev pagination: %w", ErrInvalidResponse)
			}
			return entries, requestErr
		}
		if status != http.StatusOK || response.Rows == nil || response.HasNext == nil || response.NextCursor == nil {
			return nil, fmt.Errorf("ctlogs.dev search: %w: required pagination fields are missing", ErrInvalidResponse)
		}
		historyTruncated = historyTruncated || response.HistoryTruncated
		for _, row := range response.Rows {
			id := row.ID
			if !validCertificateID(id) {
				return nil, fmt.Errorf("ctlogs.dev search: %w: invalid certificate identifier", ErrInvalidResponse)
			}
			if _, duplicate := seenIDs[id]; duplicate {
				continue
			}
			if certificateLookups >= p.maxCertificates {
				return entries, fmt.Errorf("ctlogs.dev search: %w: certificate detail lookup cap reached", ErrResultsTruncated)
			}
			if len(entries) >= normalized.Limit {
				if historyTruncated {
					return entries, fmt.Errorf("ctlogs.dev search: %w: API history window is truncated", ErrResultsTruncated)
				}
				return entries, nil
			}
			seenIDs[id] = struct{}{}
			certificateLookups++
			detail, detailErr := p.fetchCertificate(ctx, id)
			if detailErr != nil {
				return entries, detailErr
			}
			mapped, mapErr := mapCertificateDetail(detail)
			if mapErr != nil {
				return nil, mapErr
			}
			entries = append(entries, mapped...)
			if len(entries) >= normalized.Limit {
				if historyTruncated {
					return entries, fmt.Errorf("ctlogs.dev search: %w: API history window is truncated", ErrResultsTruncated)
				}
				return entries, nil
			}
		}
		if historyTruncated {
			return entries, fmt.Errorf("ctlogs.dev search: %w: API history window is truncated", ErrResultsTruncated)
		}
		if !*response.HasNext {
			if len(entries) == 0 {
				return nil, ErrNoResults
			}
			return entries, nil
		}
		if certificateLookups >= p.maxCertificates {
			return entries, fmt.Errorf("ctlogs.dev search: %w: certificate detail lookup cap reached", ErrResultsTruncated)
		}
		if *response.NextCursor == "" {
			return nil, fmt.Errorf("ctlogs.dev pagination: %w: next cursor is empty", ErrInvalidResponse)
		}
		if _, exists := cursors[*response.NextCursor]; exists {
			return nil, fmt.Errorf("ctlogs.dev pagination: %w: repeated opaque cursor", ErrInvalidResponse)
		}
		cursors[*response.NextCursor] = struct{}{}
		cursor = *response.NextCursor
	}
	return entries, fmt.Errorf("ctlogs.dev pagination: %w: maximum page count reached", ErrResultsTruncated)
}

type searchResponse struct {
	Rows             []searchRow `json:"rows"`
	HasNext          *bool       `json:"has_next"`
	NextCursor       *string     `json:"next_cursor"`
	HistoryTruncated bool        `json:"history_truncated"`
}

type searchRow struct {
	ID string `json:"id"`
}

type certificateResponse struct {
	ID            string        `json:"id"`
	SubjectDN     string        `json:"subject_dn"`
	SubjectCN     string        `json:"subject_cn"`
	IssuerDN      string        `json:"issuer_dn"`
	DNSNames      []string      `json:"san_dns"`
	NotBefore     string        `json:"not_before"`
	NotAfter      string        `json:"not_after"`
	SerialHex     string        `json:"serial_hex"`
	FinalSHA256   string        `json:"final_sha256"`
	PrecertSHA256 string        `json:"precert_sha256"`
	Sightings     []rawSighting `json:"sightings"`
}

type rawSighting struct {
	LogID    string  `json:"log_id"`
	LogURL   string  `json:"log_url"`
	EntryIdx *uint64 `json:"entry_idx"`
	SCTTS    string  `json:"sct_ts"`
}

func (p *CTLogsDevProvider) fetchCertificate(ctx context.Context, id string) (certificateResponse, error) {
	if !validCertificateID(id) {
		return certificateResponse{}, fmt.Errorf("ctlogs.dev certificate: %w: invalid certificate identifier", ErrInvalidResponse)
	}
	endpoint, err := p.endpoint("/v1/cert/"+url.PathEscape(id), "")
	if err != nil {
		return certificateResponse{}, fmt.Errorf("ctlogs.dev certificate: build request: %w", err)
	}
	var response certificateResponse
	_, err = p.getJSON(ctx, endpoint, &response, false)
	if err != nil {
		return certificateResponse{}, fmt.Errorf("ctlogs.dev certificate detail: %w", err)
	}
	if !validCertificateID(response.ID) || response.ID != id {
		return certificateResponse{}, fmt.Errorf("ctlogs.dev certificate detail: %w: response identifier does not match request", ErrInvalidResponse)
	}
	return response, nil
}

func mapCertificateDetail(detail certificateResponse) ([]CTEntry, error) {
	subject := strings.TrimSpace(detail.SubjectDN)
	if subject == "" {
		subject = strings.TrimSpace(detail.SubjectCN)
	}
	issuer := strings.TrimSpace(detail.IssuerDN)
	fingerprint, fingerprintOK := selectFingerprint(detail.FinalSHA256, detail.PrecertSHA256)
	if subject == "" || issuer == "" || len(detail.DNSNames) == 0 || detail.SerialHex == "" || !fingerprintOK || len(detail.Sightings) == 0 {
		return nil, fmt.Errorf("ctlogs.dev certificate detail: %w: required certificate metadata or sightings are missing", ErrInvalidResponse)
	}
	if _, err := time.Parse(time.RFC3339Nano, detail.NotBefore); err != nil {
		return nil, fmt.Errorf("ctlogs.dev certificate detail: %w: invalid not_before timestamp", ErrInvalidResponse)
	}
	notBefore, _ := time.Parse(time.RFC3339Nano, detail.NotBefore)
	notAfter, err := time.Parse(time.RFC3339Nano, detail.NotAfter)
	if err != nil || !notAfter.After(notBefore) {
		return nil, fmt.Errorf("ctlogs.dev certificate detail: %w: invalid not_after timestamp", ErrInvalidResponse)
	}
	entries := make([]CTEntry, 0, len(detail.Sightings))
	for index, sighting := range detail.Sightings {
		if sighting.EntryIdx == nil || strings.TrimSpace(sighting.LogURL) == "" || strings.TrimSpace(sighting.SCTTS) == "" {
			return nil, fmt.Errorf("ctlogs.dev certificate sighting %d: %w: required fields are missing", index+1, ErrInvalidResponse)
		}
		logIDBytes, decodeErr := hex.DecodeString(strings.TrimSpace(sighting.LogID))
		if decodeErr != nil || len(logIDBytes) != 32 {
			return nil, fmt.Errorf("ctlogs.dev certificate sighting %d: %w: log ID must be 32-byte hexadecimal", index+1, ErrInvalidResponse)
		}
		timestamp, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(sighting.SCTTS))
		if parseErr != nil {
			return nil, fmt.Errorf("ctlogs.dev certificate sighting %d: %w: invalid SCT timestamp", index+1, ErrInvalidResponse)
		}
		entries = append(entries, CTEntry{
			LogID: encodeLogID(logIDBytes), LogURL: strings.TrimSpace(sighting.LogURL),
			EntryTimestamp: timestamp.UTC(), LeafIndex: *sighting.EntryIdx,
			Certificate: CertificateSummary{
				Subject: subject, Issuer: issuer, DNSNames: append([]string(nil), detail.DNSNames...),
				NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC(),
				SerialNumber: detail.SerialHex, FingerprintSHA256: fingerprint,
			},
		})
	}
	return entries, nil
}

func encodeLogID(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func selectFingerprint(final, precertificate string) (string, bool) {
	for _, candidate := range []string{strings.TrimSpace(final), strings.TrimSpace(precertificate)} {
		decoded, err := hex.DecodeString(candidate)
		if err == nil && len(decoded) == 32 {
			return candidate, true
		}
	}
	return "", false
}

func (p *CTLogsDevProvider) endpoint(path, cursor string) (*url.URL, error) {
	u := *p.baseURL
	escapedPath := path
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, err
	}
	u.Path = decodedPath
	u.RawPath = escapedPath
	u.RawQuery = ""
	if cursor != "" {
		query := url.Values{}
		query.Set("after", cursor)
		u.RawQuery = query.Encode()
	}
	return &u, nil
}

func (p *CTLogsDevProvider) getJSON(ctx context.Context, endpoint *url.URL, target any, search bool) (int, error) {
	deadline := time.Now().Add(p.timeout)
	if err := acquireCTLogsDevRequestSlot(ctx, deadline); err != nil {
		return 0, fmt.Errorf("wait for CT request slot: %w", err)
	}
	defer releaseCTLogsDevRequestSlot()
	requestCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", ErrInvalidResponse)
	}
	request.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	response, err := p.client.Do(request)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return 0, fmt.Errorf("request canceled or timed out: %w", ctxErr)
		}
		return 0, fmt.Errorf("request failed: %w", ErrProviderUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, statusError(response.StatusCode, search)
	}
	body, err := readBounded(response.Body, p.maxResponseBodyBytes)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return response.StatusCode, fmt.Errorf("read response body: %w", ctxErr)
		}
		return response.StatusCode, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return response.StatusCode, fmt.Errorf("decode JSON response: %w", ErrInvalidResponse)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return response.StatusCode, fmt.Errorf("decode JSON response: %w: trailing data", ErrInvalidResponse)
	}
	return response.StatusCode, nil
}

func statusError(status int, search bool) error {
	switch {
	case status == http.StatusNotFound && search:
		return fmt.Errorf("HTTP %d: %w", status, ErrNoResults)
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("HTTP %d: %w", status, ErrRateLimited)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("HTTP %d: %w", status, ErrAuthentication)
	case status >= 500:
		return fmt.Errorf("HTTP %d: %w", status, ErrProviderUnavailable)
	case status == http.StatusBadRequest && search:
		return fmt.Errorf("HTTP %d: %w", status, ErrUnsupportedQuery)
	default:
		return fmt.Errorf("unexpected HTTP status %d: %w", status, ErrInvalidResponse)
	}
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", ErrProviderUnavailable)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body exceeds configured limit: %w", ErrInvalidResponse)
	}
	return body, nil
}

func acquireCTLogsDevRequestSlot(ctx context.Context, deadline time.Time) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case ctLogsDevRequestGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func releaseCTLogsDevRequestSlot() {
	<-ctLogsDevRequestGate
}

func validCertificateID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') || char == '-' {
			continue
		}
		return false
	}
	return true
}
