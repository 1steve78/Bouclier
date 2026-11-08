package intel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bouclier/internal/risk"
)

func TestParseJSONIndicators(t *testing.T) {
	jsonPayload := `[
		{
			"type": "domain",
			"value": "Evil-Phish.com",
			"category": "phishing",
			"confidence": 95,
			"severity": "critical",
			"description": "Active banking credential harvester"
		},
		{
			"type": "url",
			"value": "https://badsite.org/login.php",
			"category": "credential-theft",
			"confidence": 90,
			"severity": "high"
		},
		{
			"type": "ipv4",
			"value": "198.51.100.42",
			"category": "c2",
			"confidence": 75,
			"severity": "medium"
		},
		{
			"type": "domain",
			"value": "not-valid-no-tld",
			"category": "malware"
		}
	]`

	cfg := SourceConfig{
		ID:   "test-source",
		Name: "Test Feed",
	}

	inds, errs, err := ParseIndicators(strings.NewReader(jsonPayload), "json", cfg)
	if err != nil {
		t.Fatalf("unexpected error parsing JSON: %v", err)
	}

	if len(inds) != 3 {
		t.Errorf("expected 3 valid indicators, got %d", len(inds))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 record error for malformed domain, got %d", len(errs))
	}

	if inds[0].Value != "evil-phish.com" {
		t.Errorf("expected normalized value evil-phish.com, got %q", inds[0].Value)
	}
	if inds[0].Severity != risk.SeverityCritical {
		t.Errorf("expected severity critical, got %q", inds[0].Severity)
	}
}

func TestParseCSVIndicators(t *testing.T) {
	csvPayload := `type,value,category,confidence,severity,description
domain,phishing-test.co.uk,phishing,88,high,UK targeted phish
url,https://fake-login.com/auth,phishing,92,critical,OAuth harvest
ipv4,203.0.113.10,c2,70,medium,Command and control node
invalid_type,something,test,50,low,Invalid type row
`

	cfg := SourceConfig{
		ID:   "csv-source",
		Name: "CSV Test Feed",
	}

	inds, errs, err := ParseIndicators(strings.NewReader(csvPayload), "csv", cfg)
	if err != nil {
		t.Fatalf("unexpected error parsing CSV: %v", err)
	}

	if len(inds) != 3 {
		t.Errorf("expected 3 valid indicators, got %d", len(inds))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error for invalid type, got %d", len(errs))
	}
}

func TestDeduplicateIndicators(t *testing.T) {
	inds := []Indicator{
		{
			Type:       TypeDomain,
			Value:      "duplicate.com",
			Confidence: 50,
			Severity:   risk.SeverityMedium,
		},
		{
			Type:       TypeDomain,
			Value:      "duplicate.com",
			Confidence: 90, // Higher confidence should win
			Severity:   risk.SeverityCritical,
		},
		{
			Type:       TypeDomain,
			Value:      "other.com",
			Confidence: 80,
			Severity:   risk.SeverityHigh,
		},
	}

	deduped := DeduplicateIndicators(inds)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped indicators, got %d", len(deduped))
	}
	if deduped[0].Confidence != 90 || deduped[0].Severity != risk.SeverityCritical {
		t.Errorf("expected higher confidence record retained, got confidence=%d, severity=%s", deduped[0].Confidence, deduped[0].Severity)
	}
}

func TestLocalFileProvider(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "intel.json")

	content := `[
		{"type": "domain", "value": "local-evil.com", "category": "malware", "confidence": 85, "severity": "high"}
	]`
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	provider := NewLocalFileProvider()
	cfg := SourceConfig{
		ID:           "local-1",
		Name:         "Local Test File",
		ProviderType: "local_file",
		Endpoint:     filePath,
		Enabled:      true,
		Format:       "json",
	}

	res, err := provider.FetchIndicators(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error fetching from local file: %v", err)
	}
	if res.ValidCount != 1 {
		t.Errorf("expected 1 valid indicator, got %d", res.ValidCount)
	}
	if res.Indicators[0].Value != "local-evil.com" {
		t.Errorf("expected local-evil.com, got %s", res.Indicators[0].Value)
	}
}

type mockResolver struct {
	ips []netip.Addr
	err error
}

func (m *mockResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return m.ips, m.err
}

func TestHTTPSFeedSSRFProtection(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		mockIPs   []netip.Addr
		expectErr string
	}{
		{
			name:      "reject non-https scheme",
			endpoint:  "http://example.com/feed.json",
			expectErr: "remote feed endpoint must use https",
		},
		{
			name:      "reject loopback ip literal",
			endpoint:  "https://127.0.0.1/feed.json",
			expectErr: "is private or restricted",
		},
		{
			name:      "reject private ip literal 10.x",
			endpoint:  "https://10.0.1.5/feed.json",
			expectErr: "is private or restricted",
		},
		{
			name:      "reject private ip literal 192.168.x",
			endpoint:  "https://192.168.1.100/feed.json",
			expectErr: "is private or restricted",
		},
		{
			name:      "reject domain resolving to loopback",
			endpoint:  "https://attacker-domain.com/feed.json",
			mockIPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			expectErr: "dns resolved private/restricted address",
		},
		{
			name:      "reject domain resolving to private 172.16.x",
			endpoint:  "https://internal-server.corp/feed.json",
			mockIPs:   []netip.Addr{netip.MustParseAddr("172.16.0.1")},
			expectErr: "dns resolved private/restricted address",
		},
		{
			name:      "reject carrier-grade nat IP literal",
			endpoint:  "https://100.64.0.1/feed.json",
			expectErr: "private or restricted",
		},
		{
			name:      "reject documentation prefix IP literal",
			endpoint:  "https://198.51.100.1/feed.json",
			expectErr: "private or restricted",
		},
		{
			name:      "reject prohibited service port 22",
			endpoint:  "https://8.8.8.8:22/feed.json",
			expectErr: "prohibited feed port 22",
		},
		{
			name:      "reject domain resolving to carrier-grade nat",
			endpoint:  "https://cgnat.test/feed.json",
			mockIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.5")},
			expectErr: "dns resolved private/restricted address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := &HTTPSFeedProvider{
				Resolver: &mockResolver{ips: tc.mockIPs},
				Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, fmt.Errorf("should not dial blocked address")
				},
			}

			cfg := SourceConfig{
				ID:           "test-source",
				Name:         "Test SSRF",
				ProviderType: "https_feed",
				Endpoint:     tc.endpoint,
				Enabled:      true,
			}

			_, err := provider.FetchIndicators(context.Background(), cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("expected error containing %q, got: %v", tc.expectErr, err)
			}
		})
	}
}

func TestHTTPSFeedAuthHeaderEnvResolution(t *testing.T) {
	provider := NewHTTPSFeedProvider()

	// 1. Missing environment variable produces safe error
	cfgMissing := SourceConfig{
		ID:            "missing-env-feed",
		Name:          "Missing Env Feed",
		ProviderType:  "https_feed",
		Endpoint:      "https://example.com/feed.json",
		Enabled:       true,
		AuthHeaderEnv: "NON_EXISTENT_VAR_BOUCLIER_XYZ_123",
	}

	_, err := provider.FetchIndicators(context.Background(), cfgMissing)
	if err == nil {
		t.Fatalf("expected error for missing environment variable, got nil")
	}
	if !strings.Contains(err.Error(), `authentication environment variable "NON_EXISTENT_VAR_BOUCLIER_XYZ_123" is not set or empty`) {
		t.Errorf("unexpected error message: %v", err)
	}

	// 2. Empty environment variable produces safe error
	t.Setenv("EMPTY_VAR_BOUCLIER", "   ")
	cfgEmpty := SourceConfig{
		ID:            "empty-env-feed",
		Name:          "Empty Env Feed",
		ProviderType:  "https_feed",
		Endpoint:      "https://example.com/feed.json",
		Enabled:       true,
		AuthHeaderEnv: "EMPTY_VAR_BOUCLIER",
	}
	_, err = provider.FetchIndicators(context.Background(), cfgEmpty)
	if err == nil {
		t.Fatalf("expected error for empty environment variable, got nil")
	}
	if !strings.Contains(err.Error(), `authentication environment variable "EMPTY_VAR_BOUCLIER" is not set or empty`) {
		t.Errorf("unexpected error message: %v", err)
	}
}
