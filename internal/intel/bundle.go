package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	BundleSchemaVersion = "bouclier-intel-bundle/v1"
	BundleFormatVersion = "1.0"
)

var (
	ErrInvalidBundleChecksum = errors.New("bundle integrity checksum mismatch")
	ErrUnsupportedBundle     = errors.New("unsupported bundle schema version")
)

// BundleManifest contains metadata and cryptographic integrity proof for an exported bundle.
type BundleManifest struct {
	SchemaVersion  string    `json:"schema_version"`
	BundleVersion  string    `json:"bundle_version"`
	CreatedAt      time.Time `json:"created_at"`
	Generator      string    `json:"generator"`
	IndicatorCount int       `json:"indicator_count"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
}

// Bundle represents an explicit collaborative intelligence export.
type Bundle struct {
	Manifest   BundleManifest `json:"manifest"`
	Indicators []Indicator    `json:"indicators"`
}

// ExportOptions specifies optional filtering criteria when exporting a bundle.
type ExportOptions struct {
	Category      string
	MinConfidence int
}

// CreateBundle builds a validated, sorted, and checksummed intelligence bundle.
func CreateBundle(indicators []Indicator, opts ExportOptions) (*Bundle, error) {
	filtered := make([]Indicator, 0, len(indicators))
	for _, ind := range indicators {
		if opts.Category != "" && !stringsEqualFold(ind.Category, opts.Category) {
			continue
		}
		if opts.MinConfidence > 0 && ind.Confidence < opts.MinConfidence {
			continue
		}

		// Ensure sensitive/unredacted data is NOT present in bundle
		clean := ind
		// Remove any potential userinfo in URLs if present
		if clean.Type == TypeURL {
			norm, err := NormalizeIndicator(TypeURL, clean.Value)
			if err == nil {
				clean.Value = norm
			}
		}
		filtered = append(filtered, clean)
	}

	// Deterministic ordering: type ASC, value ASC, source ID ASC
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Type != filtered[j].Type {
			return filtered[i].Type < filtered[j].Type
		}
		if filtered[i].Value != filtered[j].Value {
			return filtered[i].Value < filtered[j].Value
		}
		return filtered[i].SourceID < filtered[j].SourceID
	})

	// Calculate deterministic SHA-256 checksum of indicators
	indBytes, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("marshal indicators for checksum: %w", err)
	}
	hash := sha256.Sum256(indBytes)
	checksum := hex.EncodeToString(hash[:])

	bundle := &Bundle{
		Manifest: BundleManifest{
			SchemaVersion:  BundleSchemaVersion,
			BundleVersion:  BundleFormatVersion,
			CreatedAt:      time.Now().UTC(),
			Generator:      "Bouclier CLI",
			IndicatorCount: len(filtered),
			ChecksumSHA256: checksum,
		},
		Indicators: filtered,
	}

	return bundle, nil
}

// WriteBundle writes the bundle as formatted JSON with secure 0600 file permissions.
func WriteBundle(path string, bundle *Bundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle is nil")
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write bundle file %q: %w", path, err)
	}
	return nil
}

// ReadBundle reads, unmarshals, and cryptographically verifies an intelligence bundle from an io.Reader.
func ReadBundle(r io.Reader) (*Bundle, error) {
	bounded := io.LimitReader(r, MaxFeedSizeBytes+1)
	data, err := io.ReadAll(bounded)
	if err != nil {
		return nil, fmt.Errorf("read bundle data: %w", err)
	}
	if len(data) > MaxFeedSizeBytes {
		return nil, fmt.Errorf("bundle exceeds maximum allowed size of %d bytes", MaxFeedSizeBytes)
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}

	if len(bundle.Indicators) > MaxFeedRecords {
		return nil, fmt.Errorf("bundle exceeds maximum indicator limit of %d items", MaxFeedRecords)
	}

	if bundle.Manifest.SchemaVersion != BundleSchemaVersion {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrUnsupportedBundle, BundleSchemaVersion, bundle.Manifest.SchemaVersion)
	}

	// Verify checksum
	indBytes, err := json.Marshal(bundle.Indicators)
	if err != nil {
		return nil, fmt.Errorf("marshal indicators for verification: %w", err)
	}
	hash := sha256.Sum256(indBytes)
	actualChecksum := hex.EncodeToString(hash[:])

	if actualChecksum != bundle.Manifest.ChecksumSHA256 {
		return nil, fmt.Errorf("%w: manifest has %s, calculated %s", ErrInvalidBundleChecksum, bundle.Manifest.ChecksumSHA256, actualChecksum)
	}

	// Validate each indicator
	for i := range bundle.Indicators {
		if err := bundle.Indicators[i].Validate(); err != nil {
			return nil, fmt.Errorf("invalid indicator at index %d: %w", i, err)
		}
	}

	return &bundle, nil
}

func stringsEqualFold(s1, s2 string) bool {
	return strings.EqualFold(s1, s2)
}
