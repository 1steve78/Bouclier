package intel

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"bouclier/internal/risk"
)

const (
	MaxFeedSizeBytes = 10 * 1024 * 1024 // 10 MiB bounded response size
	MaxFeedRecords   = 50000            // Maximum indicators per feed to prevent memory exhaustion
)

var (
	ErrFeedTooLarge       = errors.New("feed payload exceeds maximum allowed size")
	ErrTooManyFeedRecords = errors.New("feed exceeds maximum indicator record count")
)

// ParseIndicators parses an input stream of JSON or CSV into validated indicators.
func ParseIndicators(reader io.Reader, format string, cfg SourceConfig) ([]Indicator, []RecordError, error) {
	bounded := io.LimitReader(reader, MaxFeedSizeBytes+1)
	data, err := io.ReadAll(bounded)
	if err != nil {
		return nil, nil, fmt.Errorf("read feed data: %w", err)
	}
	if len(data) > MaxFeedSizeBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes (limit: %d bytes)", ErrFeedTooLarge, len(data), MaxFeedSizeBytes)
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		// Detect from content
		trimmed := strings.TrimSpace(string(data))
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			format = "json"
		} else {
			format = "csv"
		}
	}

	switch format {
	case "json":
		return parseJSONIndicators(data, cfg)
	case "csv":
		return parseCSVIndicators(data, cfg)
	default:
		return nil, nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
}

type jsonIndicatorRecord struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	Category    string            `json:"category"`
	Confidence  int               `json:"confidence"`
	Severity    string            `json:"severity"`
	FirstSeen   *string           `json:"first_seen,omitempty"`
	LastSeen    *string           `json:"last_seen,omitempty"`
	ExpiresAt   *string           `json:"expires_at,omitempty"`
	SourceRef   string            `json:"source_ref,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type jsonFeedWrapper struct {
	Indicators []jsonIndicatorRecord `json:"indicators"`
}

func parseJSONIndicators(data []byte, cfg SourceConfig) ([]Indicator, []RecordError, error) {
	var records []jsonIndicatorRecord

	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, nil, fmt.Errorf("parse JSON indicator array: %w", err)
		}
	} else {
		var wrapper jsonFeedWrapper
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return nil, nil, fmt.Errorf("parse JSON indicator object: %w", err)
		}
		records = wrapper.Indicators
	}

	if len(records) > MaxFeedRecords {
		return nil, nil, fmt.Errorf("%w: %d records (limit: %d)", ErrTooManyFeedRecords, len(records), MaxFeedRecords)
	}

	var indicators []Indicator
	var recordErrors []RecordError

	for idx, rec := range records {
		ind, err := convertJSONRecord(rec, cfg, idx)
		if err != nil {
			recordErrors = append(recordErrors, RecordError{
				Index:   idx,
				Raw:     rec.Value,
				Message: err.Error(),
			})
			continue
		}
		indicators = append(indicators, *ind)
	}

	deduped := DeduplicateIndicators(indicators)
	return deduped, recordErrors, nil
}

func convertJSONRecord(rec jsonIndicatorRecord, cfg SourceConfig, idx int) (*Indicator, error) {
	indType := IndicatorType(strings.ToLower(strings.TrimSpace(rec.Type)))
	if !ValidIndicatorType(indType) {
		return nil, fmt.Errorf("invalid indicator type %q at index %d", rec.Type, idx)
	}

	normVal, err := NormalizeIndicator(indType, rec.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid indicator value %q: %w", rec.Value, err)
	}

	sev := risk.Severity(strings.ToLower(strings.TrimSpace(rec.Severity)))
	if sev == "" {
		sev = risk.SeverityHigh // default
	}

	cat := strings.TrimSpace(rec.Category)
	if cat == "" {
		cat = "threat-intelligence"
	}

	conf := rec.Confidence
	if conf == 0 {
		conf = 80 // default confidence
	}

	parseTime := func(s *string) *time.Time {
		if s == nil || strings.TrimSpace(*s) == "" {
			return nil
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, *s); err == nil {
				t = t.UTC()
				return &t
			}
		}
		return nil
	}

	firstSeen := parseTime(rec.FirstSeen)
	lastSeen := parseTime(rec.LastSeen)
	expiresAt := parseTime(rec.ExpiresAt)

	ind := &Indicator{
		ID:          rec.ID,
		Type:        indType,
		Value:       normVal,
		SourceID:    cfg.ID,
		SourceName:  cfg.Name,
		Category:    cat,
		Confidence:  conf,
		Severity:    sev,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		ExpiresAt:   expiresAt,
		IngestedAt:  time.Now().UTC(),
		SourceRef:   rec.SourceRef,
		Description: rec.Description,
		Metadata:    rec.Metadata,
	}

	if err := ind.Validate(); err != nil {
		return nil, err
	}
	return ind, nil
}

func parseCSVIndicators(data []byte, cfg SourceConfig) ([]Indicator, []RecordError, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1 // variable fields

	headers, err := r.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("read CSV headers: %w", err)
	}

	headerMap := make(map[string]int)
	for i, h := range headers {
		headerMap[strings.ToLower(strings.TrimSpace(h))] = i
	}

	valIdx, hasVal := headerMap["value"]
	if !hasVal {
		valIdx, hasVal = headerMap["indicator"]
	}
	typeIdx, hasType := headerMap["type"]
	if !hasVal || !hasType {
		return nil, nil, fmt.Errorf("CSV must have 'type' and 'value' (or 'indicator') columns")
	}

	catIdx, hasCat := headerMap["category"]
	confIdx, hasConf := headerMap["confidence"]
	sevIdx, hasSev := headerMap["severity"]
	descIdx, hasDesc := headerMap["description"]
	refIdx, hasRef := headerMap["source_ref"]
	firstIdx, hasFirst := headerMap["first_seen"]
	lastIdx, hasLast := headerMap["last_seen"]
	expIdx, hasExp := headerMap["expires_at"]

	var indicators []Indicator
	var recordErrors []RecordError

	rowNum := 0
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		rowNum++
		if rowNum > MaxFeedRecords {
			return nil, nil, fmt.Errorf("%w: %d rows (limit: %d)", ErrTooManyFeedRecords, rowNum, MaxFeedRecords)
		}
		if err != nil {
			recordErrors = append(recordErrors, RecordError{
				Index:   rowNum,
				Message: fmt.Sprintf("malformed CSV row: %v", err),
			})
			continue
		}

		if len(row) <= valIdx || len(row) <= typeIdx {
			recordErrors = append(recordErrors, RecordError{
				Index:   rowNum,
				Message: "missing required columns in row",
			})
			continue
		}

		rawVal := strings.TrimSpace(row[valIdx])
		rawType := strings.TrimSpace(row[typeIdx])

		if rawVal == "" || rawType == "" {
			recordErrors = append(recordErrors, RecordError{
				Index:   rowNum,
				Message: "empty type or value",
			})
			continue
		}

		indType := IndicatorType(strings.ToLower(rawType))
		normVal, normErr := NormalizeIndicator(indType, rawVal)
		if normErr != nil {
			recordErrors = append(recordErrors, RecordError{
				Index:   rowNum,
				Raw:     rawVal,
				Message: normErr.Error(),
			})
			continue
		}

		category := "threat-intelligence"
		if hasCat && len(row) > catIdx && strings.TrimSpace(row[catIdx]) != "" {
			category = strings.TrimSpace(row[catIdx])
		}

		conf := 80
		if hasConf && len(row) > confIdx && strings.TrimSpace(row[confIdx]) != "" {
			if parsedConf, err := strconv.Atoi(strings.TrimSpace(row[confIdx])); err == nil {
				conf = parsedConf
			}
		}

		sev := risk.SeverityHigh
		if hasSev && len(row) > sevIdx && strings.TrimSpace(row[sevIdx]) != "" {
			sev = risk.Severity(strings.ToLower(strings.TrimSpace(row[sevIdx])))
		}

		desc := ""
		if hasDesc && len(row) > descIdx {
			desc = strings.TrimSpace(row[descIdx])
		}

		sourceRef := ""
		if hasRef && len(row) > refIdx {
			sourceRef = strings.TrimSpace(row[refIdx])
		}

		parseTime := func(idx int, has bool) *time.Time {
			if !has || len(row) <= idx {
				return nil
			}
			s := strings.TrimSpace(row[idx])
			if s == "" {
				return nil
			}
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
				if t, err := time.Parse(layout, s); err == nil {
					t = t.UTC()
					return &t
				}
			}
			return nil
		}

		ind := Indicator{
			ID:          DeterministicID(cfg.ID, indType, normVal),
			Type:        indType,
			Value:       normVal,
			SourceID:    cfg.ID,
			SourceName:  cfg.Name,
			Category:    category,
			Confidence:  conf,
			Severity:    sev,
			FirstSeen:   parseTime(firstIdx, hasFirst),
			LastSeen:    parseTime(lastIdx, hasLast),
			ExpiresAt:   parseTime(expIdx, hasExp),
			IngestedAt:  time.Now().UTC(),
			SourceRef:   sourceRef,
			Description: desc,
		}

		if valErr := ind.Validate(); valErr != nil {
			recordErrors = append(recordErrors, RecordError{
				Index:   rowNum,
				Raw:     rawVal,
				Message: valErr.Error(),
			})
			continue
		}

		indicators = append(indicators, ind)
	}

	deduped := DeduplicateIndicators(indicators)
	return deduped, recordErrors, nil
}

// DeduplicateIndicators deterministically deduplicates a slice of indicators by (Type, Value),
// retaining the record with highest confidence, breaking ties by latest LastSeen or IngestedAt.
func DeduplicateIndicators(inds []Indicator) []Indicator {
	type key struct {
		typ IndicatorType
		val string
	}
	best := make(map[key]Indicator)
	var order []key

	for _, ind := range inds {
		k := key{typ: ind.Type, val: ind.Value}
		existing, ok := best[k]
		if !ok {
			best[k] = ind
			order = append(order, k)
			continue
		}

		// Keep highest confidence
		if ind.Confidence > existing.Confidence {
			best[k] = ind
		} else if ind.Confidence == existing.Confidence {
			// Compare LastSeen
			if ind.LastSeen != nil && (existing.LastSeen == nil || ind.LastSeen.After(*existing.LastSeen)) {
				best[k] = ind
			}
		}
	}

	result := make([]Indicator, 0, len(order))
	for _, k := range order {
		result = append(result, best[k])
	}
	return result
}
