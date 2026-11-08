package intel

import (
	"testing"
	"time"

	"bouclier/internal/risk"
)

func TestNormalizeIndicatorDomain(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"valid domain", "Example.COM", "example.com", false},
		{"subdomain", "sub.phish.test.co.uk", "sub.phish.test.co.uk", false},
		{"trailing dot", "evil.org.", "evil.org", false},
		{"idna international domain", "münchen.de", "xn--mnchen-3ya.de", false},
		{"empty domain", "", "", true},
		{"spaces in domain", "bad domain.com", "", true},
		{"url with scheme rejected", "http://evil.com", "", true},
		{"path rejected", "evil.com/login", "", true},
		{"port rejected", "evil.com:8080", "", true},
		{"userinfo rejected", "admin@evil.com", "", true},
		{"ip literal rejected as domain", "192.0.2.1", "", true},
		{"single label rejected", "localhost", "", true},
		{"invalid public suffix", "evil.invalidtldxyznonexistent", "", true},
		{"hyphen at start of label", "-bad.com", "", true},
		{"hyphen at end of label", "bad-.com", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeIndicator(TypeDomain, tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NormalizeIndicator(TypeDomain, %q) err = %v, wantErr = %v", tc.raw, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("NormalizeIndicator(TypeDomain, %q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeIndicatorURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"valid https url", "HTTPS://EXAMPLE.COM/login?user=test#fragment", "https://example.com/login?user=test#fragment", false},
		{"default port stripped", "http://example.com:80/path", "http://example.com/path", false},
		{"non-default port kept", "http://example.com:8080/path", "http://example.com:8080/path", false},
		{"empty url", "", "", true},
		{"invalid scheme", "ftp://evil.com", "", true},
		{"control characters", "http://evil.com/\x00path", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeIndicator(TypeURL, tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NormalizeIndicator(TypeURL, %q) err = %v, wantErr = %v", tc.raw, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("NormalizeIndicator(TypeURL, %q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeIndicatorIP(t *testing.T) {
	tests := []struct {
		name    string
		indType IndicatorType
		raw     string
		want    string
		wantErr bool
	}{
		{"valid ipv4", TypeIPv4, "192.0.2.1", "192.0.2.1", false},
		{"ipv4 with spaces trimmed", TypeIPv4, "  198.51.100.25  ", "198.51.100.25", false},
		{"ipv4 out of range", TypeIPv4, "256.0.0.1", "", true},
		{"ipv6 passed as ipv4", TypeIPv4, "2001:db8::1", "", true},
		{"valid ipv6", TypeIPv6, "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", false},
		{"bracketed ipv6", TypeIPv6, "[2001:db8::1]", "2001:db8::1", false},
		{"ipv4 passed as ipv6", TypeIPv6, "192.0.2.1", "", true},
		{"invalid ip text", TypeIPv6, "not-an-ip", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeIndicator(tc.indType, tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NormalizeIndicator(%v, %q) err = %v, wantErr = %v", tc.indType, tc.raw, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("NormalizeIndicator(%v, %q) = %q, want %q", tc.indType, tc.raw, got, tc.want)
			}
		})
	}
}

func TestIndicatorValidation(t *testing.T) {
	now := time.Now().UTC()
	firstSeen := now.Add(-24 * time.Hour)
	lastSeen := now.Add(-1 * time.Hour)
	expires := now.Add(48 * time.Hour)

	validInd := &Indicator{
		Type:       TypeDomain,
		Value:      "Phish-Example.Com",
		SourceID:   "source-1",
		SourceName: "ThreatFeed Alpha",
		Category:   "phishing",
		Confidence: 85,
		Severity:   risk.SeverityHigh,
		FirstSeen:  &firstSeen,
		LastSeen:   &lastSeen,
		ExpiresAt:  &expires,
	}

	if err := validInd.Validate(); err != nil {
		t.Fatalf("expected valid indicator, got: %v", err)
	}

	if validInd.Value != "phish-example.com" {
		t.Errorf("expected normalized value, got %q", validInd.Value)
	}
	if validInd.ID == "" {
		t.Errorf("expected generated deterministic ID")
	}

	// Determinism check
	expectedID := DeterministicID("source-1", TypeDomain, "phish-example.com")
	if validInd.ID != expectedID {
		t.Errorf("expected ID %q, got %q", expectedID, validInd.ID)
	}

	// Invalid confidence
	invalidConf := *validInd
	invalidConf.Confidence = 105
	if err := invalidConf.Validate(); err == nil {
		t.Errorf("expected error for confidence > 100")
	}

	// Invalid severity
	invalidSev := *validInd
	invalidSev.Severity = "extreme"
	if err := invalidSev.Validate(); err == nil {
		t.Errorf("expected error for invalid severity")
	}

	// Invalid timestamps: last_seen before first_seen
	invalidTimes := *validInd
	wrongLast := firstSeen.Add(-1 * time.Hour)
	invalidTimes.LastSeen = &wrongLast
	if err := invalidTimes.Validate(); err == nil {
		t.Errorf("expected error for last_seen before first_seen")
	}
}

func TestIndicatorExpiration(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	indPast := &Indicator{ExpiresAt: &past}
	indFuture := &Indicator{ExpiresAt: &future}
	indNoExpiry := &Indicator{ExpiresAt: nil}

	if !indPast.IsExpired(now) {
		t.Errorf("expected past indicator to be expired")
	}
	if indFuture.IsExpired(now) {
		t.Errorf("expected future indicator to NOT be expired")
	}
	if indNoExpiry.IsExpired(now) {
		t.Errorf("expected nil expires_at indicator to NOT be expired")
	}
}
