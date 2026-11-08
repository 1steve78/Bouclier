package ct

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testCertID1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCertID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testLogHex1 = "0101010101010101010101010101010101010101010101010101010101010101"
	testLogHex2 = "0202020202020202020202020202020202020202020202020202020202020202"
)

func TestCTLogsDevProviderRetrievesAndMapsEntries(t *testing.T) {
	var certRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/domain/login.example.com":
			if r.URL.RawQuery != "" {
				t.Errorf("unexpected search query %q", r.URL.RawQuery)
			}
			writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}, map[string]string{"id": testCertID2}}, "has_next": false, "next_cursor": "", "history_truncated": false})
		case "/v1/cert/" + testCertID1:
			certRequests.Add(1)
			writeJSON(t, w, testDetail(testCertID1, testLogHex1, testLogHex2, "", ""))
		case "/v1/cert/" + testCertID2:
			certRequests.Add(1)
			writeJSON(t, w, testDetail(testCertID2, testLogHex1, "", "", strings.Repeat("b", 64)))
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	provider := testProvider(t, server, CTLogsDevOptions{})
	entries, err := QueryEntries(context.Background(), provider, Query{Domain: "LOGIN.EXAMPLE.COM.", Scope: ScopeExactHostname, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || certRequests.Load() != 2 {
		t.Fatalf("entries=%d detail requests=%d", len(entries), certRequests.Load())
	}
	if entries[0].LogID != encodeLogID(mustDecodeHex(t, testLogHex1)) || entries[0].LeafIndex != 7 {
		t.Fatalf("log ID conversion or leaf index incorrect: %+v", entries[0])
	}
	hasPrecertFallback := false
	for _, entry := range entries {
		if entry.Certificate.FingerprintSHA256 == strings.Repeat("b", 64) {
			hasPrecertFallback = true
		}
	}
	if entries[0].Certificate.FingerprintSHA256 != strings.Repeat("a", 64) || !hasPrecertFallback {
		t.Fatalf("fingerprint selection incorrect: %+v", entries)
	}
	cert := entries[0].Certificate
	if cert.Subject != "CN=login.example.com,O=Example" || cert.Issuer != "CN=Test Issuer" || cert.SerialNumber != "A" || len(cert.DNSNames) != 2 || !entries[0].EntryTimestamp.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("certificate fields not mapped/normalized: %+v entry=%+v", cert, entries[0])
	}
}

func TestCTLogsDevProviderUsesRegistrableEndpointAndOpaqueCursor(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/v1/subdomains/example.com" && !r.URL.Query().Has("after") {
			writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}}, "has_next": true, "next_cursor": "cursor/with?opaque&chars", "history_truncated": false})
			return
		}
		if r.URL.Path == "/v1/subdomains/example.com" && r.URL.Query().Has("after") {
			if got := r.URL.Query().Get("after"); got != "cursor/with?opaque&chars" {
				t.Errorf("cursor changed: %q", got)
			}
			writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID2}}, "has_next": false, "next_cursor": "", "history_truncated": false})
			return
		}
		if r.URL.Path == "/v1/cert/"+testCertID1 || r.URL.Path == "/v1/cert/"+testCertID2 {
			id := strings.TrimPrefix(r.URL.Path, "/v1/cert/")
			writeJSON(t, w, testDetail(id, testLogHex1, "", "", ""))
			return
		}
		t.Errorf("unexpected path %q", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()
	provider := testProvider(t, server, CTLogsDevOptions{})
	entries, err := QueryEntries(context.Background(), provider, Query{Domain: "example.com", Scope: ScopeRegistrableDomain, Limit: 5})
	if err != nil || len(entries) != 2 || calls != 4 {
		t.Fatalf("entries=%d calls=%d err=%v", len(entries), calls, err)
	}
}

func TestCTLogsDevProviderEnforcesQueryLimitAndRetrievalCaps(t *testing.T) {
	t.Run("query limit", func(t *testing.T) {
		var details atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/domain/login.example.com" {
				writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}, map[string]string{"id": testCertID2}}, "has_next": true, "next_cursor": "next", "history_truncated": false})
				return
			}
			details.Add(1)
			id := strings.TrimPrefix(r.URL.Path, "/v1/cert/")
			writeJSON(t, w, testDetail(id, testLogHex1, "", "", ""))
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{})
		entries, err := QueryEntries(context.Background(), provider, Query{Domain: "login.example.com", Scope: ScopeExactHostname, Limit: 1})
		if err != nil || len(entries) != 1 || details.Load() != 1 {
			t.Fatalf("entries=%d detail requests=%d err=%v", len(entries), details.Load(), err)
		}
	})
	t.Run("certificate cap signals truncation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/domain/login.example.com" {
				writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}, map[string]string{"id": testCertID2}}, "has_next": false, "next_cursor": "", "history_truncated": false})
				return
			}
			writeJSON(t, w, testDetail(testCertID1, testLogHex1, "", "", ""))
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{MaxCertificates: 1})
		entries, err := QueryEntries(context.Background(), provider, Query{Domain: "login.example.com", Scope: ScopeExactHostname, Limit: 5})
		if !errors.Is(err, ErrResultsTruncated) || len(entries) != 1 {
			t.Fatalf("partial entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("history window signals truncation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/domain/login.example.com" {
				writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}}, "has_next": false, "next_cursor": "", "history_truncated": true})
				return
			}
			writeJSON(t, w, testDetail(testCertID1, testLogHex1, "", "", ""))
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{})
		entries, err := QueryEntries(context.Background(), provider, Query{Domain: "login.example.com", Scope: ScopeExactHostname, Limit: 5})
		if !errors.Is(err, ErrResultsTruncated) || len(entries) != 1 {
			t.Fatalf("history-truncated entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("page cap signals truncation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/domain/login.example.com" {
				writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}}, "has_next": true, "next_cursor": "next", "history_truncated": false})
				return
			}
			writeJSON(t, w, testDetail(testCertID1, testLogHex1, "", "", ""))
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{MaxPages: 1})
		entries, err := QueryEntries(context.Background(), provider, Query{Domain: "login.example.com", Scope: ScopeExactHostname, Limit: 5})
		if !errors.Is(err, ErrResultsTruncated) || len(entries) != 1 {
			t.Fatalf("page-capped entries=%d err=%v", len(entries), err)
		}
	})
}

func TestCTLogsDevProviderMapsHTTPFailures(t *testing.T) {
	tests := []struct {
		status int
		want   error
	}{
		{http.StatusBadRequest, ErrUnsupportedQuery},
		{http.StatusUnauthorized, ErrAuthentication},
		{http.StatusForbidden, ErrAuthentication},
		{http.StatusNotFound, ErrNoResults},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusServiceUnavailable, ErrProviderUnavailable},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tt.status) }))
			defer server.Close()
			provider := testProvider(t, server, CTLogsDevOptions{})
			_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
			if !errors.Is(err, tt.want) {
				t.Fatalf("error=%v, want %v", err, tt.want)
			}
		})
	}
}

func TestCTLogsDevProviderRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"invalid JSON", `{not json`},
		{"missing pagination", `{"rows":[]}`},
		{"malicious certificate ID", `{"rows":[{"id":"abc/../../evil?x"}],"has_next":false,"next_cursor":""}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tt.body)) }))
			defer server.Close()
			provider := testProvider(t, server, CTLogsDevOptions{})
			_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error=%v, want ErrInvalidResponse", err)
			}
		})
	}
	for _, test := range []struct {
		name      string
		logID     string
		finger    string
		precert   string
		notAfter  string
		sightings any
	}{
		{name: "invalid log hex", logID: "zz"},
		{name: "wrong log ID length", logID: "aabb"},
		{name: "missing fingerprint", logID: testLogHex1, finger: "", precert: ""},
		{name: "invalid fingerprints", logID: testLogHex1, finger: strings.Repeat("z", 64), precert: strings.Repeat("y", 64)},
		{name: "invalid timestamp", logID: testLogHex1, finger: strings.Repeat("a", 64), notAfter: "yesterday"},
		{name: "missing issuer", logID: testLogHex1, finger: strings.Repeat("a", 64)},
		{name: "missing SANs", logID: testLogHex1, finger: strings.Repeat("a", 64)},
		{name: "missing sightings", logID: testLogHex1, finger: strings.Repeat("a", 64), sightings: []any{}},
		{name: "malformed sighting timestamp", logID: testLogHex1, finger: strings.Repeat("a", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := testCertID1
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/domain/example.com" {
					writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": id}}, "has_next": false, "next_cursor": ""})
					return
				}
				payload := testDetail(id, test.logID, "", test.finger, "")
				if test.name == "missing fingerprint" {
					payload["final_sha256"] = ""
					payload["precert_sha256"] = ""
				}
				if test.precert != "" {
					payload["precert_sha256"] = test.precert
				}
				if test.notAfter != "" {
					payload["not_after"] = test.notAfter
				}
				if test.name == "missing issuer" {
					payload["issuer_dn"] = ""
				}
				if test.name == "missing SANs" {
					payload["san_dns"] = []string{}
				}
				if test.sightings != nil {
					payload["sightings"] = test.sightings
				}
				if test.name == "malformed sighting timestamp" {
					payload["sightings"] = []any{map[string]any{"entry_idx": uint64(1), "log_id": testLogHex1, "log_url": "https://log.example/", "sct_ts": "not-a-time"}}
				}
				writeJSON(t, w, payload)
			}))
			defer server.Close()
			provider := testProvider(t, server, CTLogsDevOptions{})
			_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error=%v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestCTLogsDevProviderAuthTimeoutBodyLimitAndRedirect(t *testing.T) {
	t.Run("API key header only", func(t *testing.T) {
		const secret = "ct-key-secret-value"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+secret || r.URL.Query().Has("key") {
				t.Errorf("API key was not isolated to Authorization header")
			}
			writeJSON(t, w, map[string]any{"rows": []any{}, "has_next": false, "next_cursor": ""})
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{APIKey: secret})
		_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Fatalf("secret leaked in error: %v", err)
		}
	})
	t.Run("context cancellation", func(t *testing.T) {
		started := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := provider.Search(ctx, Query{Domain: "example.com", Scope: ScopeExactHostname})
			done <- err
		}()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{RequestTimeout: 20 * time.Millisecond})
		_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout error=%v", err)
		}
	})
	t.Run("response body limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 100))) }))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{MaxResponseBodyBytes: 10})
		_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("body limit error=%v", err)
		}
	})
	t.Run("redirect is not followed", func(t *testing.T) {
		var externalCalls atomic.Int32
		external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { externalCalls.Add(1) }))
		defer external.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, external.URL+"/steal", http.StatusFound)
		}))
		defer server.Close()
		provider := testProvider(t, server, CTLogsDevOptions{})
		_, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
		if !errors.Is(err, ErrInvalidResponse) || externalCalls.Load() != 0 {
			t.Fatalf("redirect error=%v external calls=%d", err, externalCalls.Load())
		}
	})
}

func TestCTLogsDevRequestGateCancellationAndRelease(t *testing.T) {
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseFirst) })
	var requests, active, maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		if requests.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
		}
		writeJSON(t, w, map[string]any{"rows": []any{}, "has_next": false, "next_cursor": ""})
	}))
	defer server.Close()
	providerA := testProvider(t, server, CTLogsDevOptions{})
	providerB := testProvider(t, server, CTLogsDevOptions{})

	firstDone := make(chan error, 1)
	go func() {
		_, err := providerA.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
		firstDone <- err
	}()
	<-firstEntered // Provider A is inside HTTP while owning the process-wide slot.

	ctx, cancel := context.WithCancel(context.Background())
	observed := &doneObservedContext{Context: ctx, observed: make(chan struct{})}
	secondDone := make(chan error, 1)
	go func() {
		_, err := providerB.Search(observed, Query{Domain: "example.com", Scope: ScopeExactHostname})
		secondDone <- err
	}()
	<-observed.observed
	cancel()
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting request error=%v, want context.Canceled", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("cancelled waiter issued HTTP request; requests=%d", got)
	}

	releaseOnce.Do(func() { close(releaseFirst) })
	if err := <-firstDone; !errors.Is(err, ErrNoResults) {
		t.Fatalf("first provider completion error=%v, want ErrNoResults", err)
	}
	if _, err := providerB.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname}); !errors.Is(err, ErrNoResults) {
		t.Fatalf("subsequent request could not acquire released slot: %v", err)
	}
	if requests.Load() != 2 || maximum.Load() != 1 {
		t.Fatalf("requests=%d max simultaneous HTTP requests=%d", requests.Load(), maximum.Load())
	}
}

type doneObservedContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *doneObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestCTLogsDevRequestSlotCancellationIsContextAware(t *testing.T) {
	if err := acquireCTLogsDevRequestSlot(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			releaseCTLogsDevRequestSlot()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	observed := &doneObservedContext{Context: ctx, observed: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- acquireCTLogsDevRequestSlot(observed, time.Now().Add(time.Minute)) }()
	<-observed.observed // The second acquisition has entered the wait select.
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter error=%v, want context.Canceled", err)
	}
	releaseCTLogsDevRequestSlot()
	locked = false
	if err := acquireCTLogsDevRequestSlot(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("subsequent acquisition failed: %v", err)
	}
	releaseCTLogsDevRequestSlot()
}

func TestCTLogsDevProviderOptionsAndFixedProductionOrigin(t *testing.T) {
	for _, options := range []CTLogsDevOptions{{RequestTimeout: -time.Second}, {MaxCertificates: maxCTMaxCertificates + 1}, {MaxPages: maxCTMaxPages + 1}, {MaxResponseBodyBytes: maxCTMaxResponseBytes + 1}, {APIKey: "bad\nkey"}} {
		if _, err := NewCTLogsDevProvider(options); err == nil {
			t.Errorf("invalid options accepted: %+v", options)
		}
	}
	provider, err := NewCTLogsDevProvider(CTLogsDevOptions{})
	if err != nil || provider.baseURL.String() != ctLogsDevBaseURL {
		t.Fatalf("production origin=%v err=%v", provider.baseURL, err)
	}
}

func TestCTLogsDevProviderNeverFollowsResponseURLsOrAcceptsInjectedDomains(t *testing.T) {
	var externalCalls atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { externalCalls.Add(1) }))
	defer external.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/domain/example.com" {
			writeJSON(t, w, map[string]any{"rows": []any{map[string]string{"id": testCertID1}}, "has_next": false, "next_cursor": ""})
			return
		}
		payload := testDetail(testCertID1, testLogHex1, "", "", "")
		sightings := payload["sightings"].([]any)
		sightings[0].(map[string]any)["log_url"] = external.URL + "/log"
		payload["pem_url"] = external.URL + "/certificate.pem"
		payload["der_url"] = external.URL + "/certificate.der"
		writeJSON(t, w, payload)
	}))
	defer server.Close()
	provider := testProvider(t, server, CTLogsDevOptions{})
	entries, err := provider.Search(context.Background(), Query{Domain: "example.com", Scope: ScopeExactHostname})
	if err != nil || len(entries) != 1 || externalCalls.Load() != 0 {
		t.Fatalf("entries=%d external calls=%d err=%v", len(entries), externalCalls.Load(), err)
	}
	var apiCalls atomic.Int32
	guarded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { apiCalls.Add(1) }))
	defer guarded.Close()
	provider = testProvider(t, guarded, CTLogsDevOptions{})
	if _, err := provider.Search(context.Background(), Query{Domain: "example.com/evil?x=1", Scope: ScopeExactHostname}); !errors.Is(err, ErrUnsupportedQuery) || apiCalls.Load() != 0 {
		t.Fatalf("domain injection error=%v API calls=%d", err, apiCalls.Load())
	}
}

func testProvider(t *testing.T, server *httptest.Server, options CTLogsDevOptions) *CTLogsDevProvider {
	t.Helper()
	if options.HTTPClient == nil {
		options.HTTPClient = server.Client()
	}
	provider, err := newCTLogsDevProvider(options, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func testDetail(id, firstLog, secondLog, finalFingerprint, precertFingerprint string) map[string]any {
	if finalFingerprint == "" && precertFingerprint == "" {
		finalFingerprint = strings.Repeat("a", 64)
	}
	if firstLog == "" {
		firstLog = testLogHex1
	}
	if secondLog != "" {
		// Distinct log IDs use distinct leaf indexes to model separate SCTs.
	}
	firstIndex := uint64(7)
	if id == testCertID2 {
		firstIndex = 9
	}
	firstID := firstLog
	sightings := []any{map[string]any{"entry_idx": firstIndex, "log_id": firstID, "log_url": "https://log-one.example/ct/", "sct_ts": "2026-01-02T03:04:05Z"}}
	if secondLog != "" {
		sightings = append(sightings, map[string]any{"entry_idx": firstIndex + 1, "log_id": secondLog, "log_url": "https://log-two.example/ct/", "sct_ts": "2026-01-03T03:04:05.123Z"})
	}
	return map[string]any{
		"id": id, "subject_dn": "CN=login.example.com,O=Example", "subject_cn": "login.example.com",
		"issuer_dn": "CN=Test Issuer", "san_dns": []string{"login.example.com", "www.example.com"},
		"not_before": "2025-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z",
		"serial_hex": "000a", "final_sha256": finalFingerprint, "precert_sha256": precertFingerprint,
		"sightings": sightings,
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
