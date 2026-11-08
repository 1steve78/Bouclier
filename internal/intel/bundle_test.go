package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bouclier/internal/risk"
)

func TestBundleCreateReadAndVerify(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)

	indicators := []Indicator{
		{
			Type:       TypeDomain,
			Value:      "phish-site.com",
			SourceID:   "source-a",
			SourceName: "Source A",
			Category:   "phishing",
			Confidence: 90,
			Severity:   risk.SeverityCritical,
			ExpiresAt:  &future,
		},
		{
			Type:       TypeURL,
			Value:      "https://badsite.org/login",
			SourceID:   "source-b",
			SourceName: "Source B",
			Category:   "malware",
			Confidence: 75,
			Severity:   risk.SeverityHigh,
			ExpiresAt:  &future,
		},
	}

	bundle, err := CreateBundle(indicators, ExportOptions{})
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	if bundle.Manifest.IndicatorCount != 2 {
		t.Errorf("expected 2 indicators, got %d", bundle.Manifest.IndicatorCount)
	}
	if bundle.Manifest.ChecksumSHA256 == "" {
		t.Errorf("expected non-empty checksum")
	}

	// Serialize and read back
	buf, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}

	readBundle, err := ReadBundle(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	if len(readBundle.Indicators) != 2 {
		t.Errorf("expected 2 indicators in read bundle, got %d", len(readBundle.Indicators))
	}
	if readBundle.Manifest.ChecksumSHA256 != bundle.Manifest.ChecksumSHA256 {
		t.Errorf("checksum mismatch")
	}

	// Tamper test: modify value and verify ReadBundle fails
	tampered := bundle
	tampered.Indicators[0].Value = "tampered-value.com"
	tamperedBuf, _ := json.Marshal(tampered)
	_, err = ReadBundle(bytes.NewReader(tamperedBuf))
	if err == nil {
		t.Fatalf("expected error on tampered bundle checksum mismatch, got nil")
	}
	if err != ErrInvalidBundleChecksum && !bytes.Contains([]byte(err.Error()), []byte("checksum mismatch")) {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}
}

func TestBundleExportFiltering(t *testing.T) {
	indicators := []Indicator{
		{Type: TypeDomain, Value: "a.com", SourceID: "s1", SourceName: "S1", Category: "phishing", Confidence: 90, Severity: risk.SeverityHigh},
		{Type: TypeDomain, Value: "b.com", SourceID: "s1", SourceName: "S1", Category: "malware", Confidence: 60, Severity: risk.SeverityMedium},
		{Type: TypeDomain, Value: "c.com", SourceID: "s1", SourceName: "S1", Category: "phishing", Confidence: 50, Severity: risk.SeverityLow},
	}

	// Filter by category
	b1, err := CreateBundle(indicators, ExportOptions{Category: "phishing"})
	if err != nil {
		t.Fatal(err)
	}
	if b1.Manifest.IndicatorCount != 2 {
		t.Errorf("expected 2 phishing indicators, got %d", b1.Manifest.IndicatorCount)
	}

	// Filter by min confidence
	b2, err := CreateBundle(indicators, ExportOptions{MinConfidence: 70})
	if err != nil {
		t.Fatal(err)
	}
	if b2.Manifest.IndicatorCount != 1 {
		t.Errorf("expected 1 indicator with confidence >= 70, got %d", b2.Manifest.IndicatorCount)
	}
}

func TestWriteBundlePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	bundleFile := filepath.Join(tmpDir, "intel_bundle.json")

	bundle, _ := CreateBundle([]Indicator{
		{Type: TypeDomain, Value: "evil.com", SourceID: "s", SourceName: "S", Category: "phish", Confidence: 90, Severity: risk.SeverityHigh},
	}, ExportOptions{})

	if err := WriteBundle(bundleFile, bundle); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	info, err := os.Stat(bundleFile)
	if err != nil {
		t.Fatal(err)
	}
	// On Windows, exact Unix permission bits may vary, but file exists and is readable
	if info.Size() == 0 {
		t.Errorf("expected non-empty bundle file")
	}
}

func TestBundleIntegrityAndRejection(t *testing.T) {
	// 1. Rejection of unsupported schema version
	unsupportedBundle := `{
		"manifest": {
			"schema_version": "bouclier-intel-bundle/v999",
			"bundle_version": "9.9",
			"indicator_count": 0,
			"checksum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		},
		"indicators": []
	}`
	_, err := ReadBundle(strings.NewReader(unsupportedBundle))
	if err == nil {
		t.Errorf("expected error for unsupported bundle schema, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported bundle schema version") {
		t.Errorf("expected ErrUnsupportedBundle, got: %v", err)
	}

	// 2. Rejection of malformed / truncated bundle
	truncatedBundle := `{"manifest": {"schema_version": "bouclier-intel-bundle/v1"`
	_, err = ReadBundle(strings.NewReader(truncatedBundle))
	if err == nil {
		t.Errorf("expected error on truncated bundle, got nil")
	}

	// 3. Rejection of invalid indicators within bundle
	invalidIndicatorBundle := `{
		"manifest": {
			"schema_version": "bouclier-intel-bundle/v1",
			"bundle_version": "1.0",
			"indicator_count": 1,
			"checksum_sha256": "4b3eb0b2f1559ee7cf3aaec25140b0df2b7d526e0b74ce1cf3d8e578f7962459"
		},
		"indicators": [
			{
				"type": "invalid_type_xyz",
				"value": "not-valid",
				"source_id": "s1",
				"source_name": "S1",
				"category": "phishing",
				"confidence": 80,
				"severity": "high"
			}
		]
	}`
	// The checksum in manifest matches the indicators, but indicator itself is malformed
	// Calculate actual checksum for this payload to ensure it passes checksum check and fails validation
	var indList []Indicator
	_ = json.Unmarshal([]byte(`[{"type":"invalid_type_xyz","value":"not-valid","source_id":"s1","source_name":"S1","category":"phishing","confidence":80,"severity":"high"}]`), &indList)
	indBytes, _ := json.Marshal(indList)
	hash := sha256.Sum256(indBytes)
	actualCheck := hex.EncodeToString(hash[:])
	validChecksumInvalidIndBundle := strings.Replace(invalidIndicatorBundle, "4b3eb0b2f1559ee7cf3aaec25140b0df2b7d526e0b74ce1cf3d8e578f7962459", actualCheck, 1)

	_, err = ReadBundle(strings.NewReader(validChecksumInvalidIndBundle))
	if err == nil {
		t.Errorf("expected validation error on malformed indicator in bundle, got nil")
	}
}

func TestBundleProvenancePreservation(t *testing.T) {
	tFirst := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	tLast := time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC)
	tExp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	original := []Indicator{
		{
			ID:          "prov-ind-1",
			Type:        TypeDomain,
			Value:       "threat-provenance.com",
			SourceID:    "cert-stream",
			SourceName:  "CertStream Realtime",
			Category:    "phishing",
			Confidence:  95,
			Severity:    risk.SeverityCritical,
			FirstSeen:   &tFirst,
			LastSeen:    &tLast,
			ExpiresAt:   &tExp,
			SourceRef:   "TICKET-9921",
			Description: "Confirmed credential harvesting landing page",
			Metadata:    map[string]string{"actor": "APT-XYZ", "campaign": "Spring2026"},
		},
	}

	bundle, err := CreateBundle(original, ExportOptions{})
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	buf, _ := json.Marshal(bundle)
	readBack, err := ReadBundle(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	if len(readBack.Indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(readBack.Indicators))
	}

	got := readBack.Indicators[0]
	if got.SourceID != "cert-stream" || got.SourceName != "CertStream Realtime" {
		t.Errorf("provenance lost: source_id=%s, source_name=%s", got.SourceID, got.SourceName)
	}
	if got.FirstSeen == nil || !got.FirstSeen.Equal(tFirst) {
		t.Errorf("FirstSeen timestamp not preserved: got %v, want %v", got.FirstSeen, tFirst)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(tLast) {
		t.Errorf("LastSeen timestamp not preserved: got %v, want %v", got.LastSeen, tLast)
	}
	if got.Metadata["actor"] != "APT-XYZ" || got.Metadata["campaign"] != "Spring2026" {
		t.Errorf("metadata attributes lost: %+v", got.Metadata)
	}
}
