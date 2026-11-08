package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"bouclier/internal/report"
	"bouclier/internal/risk"
	"github.com/google/uuid"
)

// Ensure *DB implements Repository.
var _ Repository = (*DB)(nil)

// SaveScan persists a scan record and its serialized report.
func (d *DB) SaveScan(ctx context.Context, record ScanRecord, assessment *risk.RiskAssessment) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if record.ID == "" {
		record.ID = uuid.NewString()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if record.StartedAt.IsZero() {
		record.StartedAt = record.CreatedAt
	}
	if record.CompletedAt.IsZero() {
		record.CompletedAt = record.CreatedAt
	}
	if record.Status == "" {
		record.Status = StatusCompleted
	}
	if record.SchemaVersion == "" {
		record.SchemaVersion = "bouclier-risk/v1"
	}

	var reportBytes []byte
	var err error
	if assessment != nil {
		reportBytes, err = report.RenderJSON(assessment)
		if err != nil {
			return fmt.Errorf("serialize assessment report: %w", err)
		}
	} else {
		reportBytes = []byte("{}")
	}
	reportDigest := sha256.Sum256(reportBytes)
	reportHash := "0x" + hex.EncodeToString(reportDigest[:])

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save transaction: %w", err)
	}
	defer tx.Rollback()

	insertScanSQL := `
INSERT INTO scans (
    id, target, started_at, completed_at, duration_ms,
    overall_score, classification, policy_id, policy_version,
    status, schema_version, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	startedAtStr := record.StartedAt.UTC().Format(time.RFC3339Nano)
	completedAtStr := record.CompletedAt.UTC().Format(time.RFC3339Nano)
	createdAtStr := record.CreatedAt.UTC().Format(time.RFC3339Nano)

	_, err = tx.ExecContext(
		ctx,
		insertScanSQL,
		record.ID,
		record.Target,
		startedAtStr,
		completedAtStr,
		record.DurationMs,
		record.OverallScore,
		string(record.Classification),
		record.PolicyID,
		record.PolicyVersion,
		string(record.Status),
		record.SchemaVersion,
		createdAtStr,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return fmt.Errorf("%w: %s", ErrDuplicateScan, record.ID)
		}
		return fmt.Errorf("insert scan record: %w", err)
	}

	insertReportSQL := `
	INSERT INTO scan_reports (scan_id, report_json, created_at, report_hash)
	VALUES (?, ?, ?, ?);`

	_, err = tx.ExecContext(ctx, insertReportSQL, record.ID, string(reportBytes), createdAtStr, reportHash)
	if err != nil {
		return fmt.Errorf("insert scan report: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit save transaction: %w", err)
	}
	return nil
}

// GetScan retrieves a scan record by full ID or unique short prefix.
func (d *DB) GetScan(ctx context.Context, idOrPrefix string) (*ScanRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	fullID, err := d.resolveID(ctx, idOrPrefix)
	if err != nil {
		return nil, err
	}

	query := `
SELECT id, target, started_at, completed_at, duration_ms,
       overall_score, classification, policy_id, policy_version,
       status, schema_version, created_at
FROM scans
WHERE id = ?`

	row := d.db.QueryRowContext(ctx, query, fullID)
	rec, err := scanRecordFromRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query scan record: %w", err)
	}
	return rec, nil
}

// GetScanReport retrieves the serialized report and deserialized assessment.
func (d *DB) GetScanReport(ctx context.Context, idOrPrefix string) (*ScanReport, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	fullID, err := d.resolveID(ctx, idOrPrefix)
	if err != nil {
		return nil, err
	}

	query := `SELECT scan_id, report_json, created_at, report_hash FROM scan_reports WHERE scan_id = ?`
	var scanID, reportJSON, createdAtStr, reportHash string
	err = d.db.QueryRowContext(ctx, query, fullID).Scan(&scanID, &reportJSON, &createdAtStr, &reportHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query scan report: %w", err)
	}

	createdAt, _ := time.Parse(time.RFC3339Nano, createdAtStr)
	report := &ScanReport{
		ScanID:     scanID,
		ReportJSON: reportJSON,
		ReportHash: reportHash,
		CreatedAt:  createdAt,
	}

	if strings.TrimSpace(reportJSON) != "" && reportJSON != "{}" {
		var assessment risk.RiskAssessment
		if unmarshalErr := json.Unmarshal([]byte(reportJSON), &assessment); unmarshalErr == nil {
			report.Assessment = &assessment
		}
	}

	return report, nil
}

// GetScanEntry retrieves both metadata record and unmarshaled assessment in a single call.
func (d *DB) GetScanEntry(ctx context.Context, idOrPrefix string) (*ScanEntry, error) {
	rec, err := d.GetScan(ctx, idOrPrefix)
	if err != nil {
		return nil, err
	}
	rep, err := d.GetScanReport(ctx, rec.ID)
	if err != nil {
		return nil, err
	}
	return &ScanEntry{
		Record:     *rec,
		Assessment: rep.Assessment,
	}, nil
}

func (d *DB) SaveReportAnchor(ctx context.Context, anchor ReportAnchor) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return ErrDatabaseClosed
	}
	if strings.TrimSpace(anchor.ScanID) == "" || strings.TrimSpace(anchor.ChainID) == "" ||
		strings.TrimSpace(anchor.ContractAddress) == "" || strings.TrimSpace(anchor.ReportHash) == "" {
		return errors.New("save report anchor: scan ID, chain ID, contract address, and report hash are required")
	}
	if anchor.RiskLevel < 1 || anchor.RiskLevel > 3 {
		return errors.New("save report anchor: risk level must be between 1 and 3")
	}
	if anchor.AnchoredAt.IsZero() {
		anchor.AnchoredAt = time.Now().UTC()
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.ExecContext(ctx, `
INSERT INTO scan_report_anchors (
    scan_id, chain_id, contract_address, transaction_hash, report_hash, risk_level, anchored_at
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(scan_id) DO UPDATE SET
    chain_id = excluded.chain_id,
    contract_address = excluded.contract_address,
    transaction_hash = excluded.transaction_hash,
    report_hash = excluded.report_hash,
    risk_level = excluded.risk_level,
    anchored_at = excluded.anchored_at;`,
		anchor.ScanID, anchor.ChainID, anchor.ContractAddress, anchor.TransactionHash,
		anchor.ReportHash, anchor.RiskLevel, anchor.AnchoredAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("save report anchor: %w", err)
	}
	return nil
}

func (d *DB) GetReportAnchor(ctx context.Context, idOrPrefix string) (*ReportAnchor, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return nil, ErrDatabaseClosed
	}
	scanID, err := d.resolveID(ctx, idOrPrefix)
	if err != nil {
		return nil, err
	}
	var anchor ReportAnchor
	var anchoredAt string
	err = d.db.QueryRowContext(ctx, `
SELECT scan_id, chain_id, contract_address, transaction_hash, report_hash, risk_level, anchored_at
FROM scan_report_anchors WHERE scan_id = ?`, scanID).Scan(
		&anchor.ScanID, &anchor.ChainID, &anchor.ContractAddress, &anchor.TransactionHash,
		&anchor.ReportHash, &anchor.RiskLevel, &anchoredAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get report anchor: %w", err)
	}
	anchor.AnchoredAt, err = time.Parse(time.RFC3339Nano, anchoredAt)
	if err != nil {
		return nil, fmt.Errorf("parse report anchor timestamp: %w", err)
	}
	return &anchor, nil
}

// ListScans queries records according to filter specifications.
func (d *DB) ListScans(ctx context.Context, filter ListFilter) ([]ScanRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	if err := validateFilter(&filter); err != nil {
		return nil, err
	}

	baseQuery := `
SELECT id, target, started_at, completed_at, duration_ms,
       overall_score, classification, policy_id, policy_version,
       status, schema_version, created_at
FROM scans`

	whereClause, args := buildWhereClause(filter)

	orderCol := "started_at"
	if filter.SortBy == "overall_score" {
		orderCol = "overall_score"
	} else if filter.SortBy == "duration_ms" {
		orderCol = "duration_ms"
	} else if filter.SortBy == "target" {
		orderCol = "target"
	}

	orderDir := "DESC"
	if strings.ToUpper(filter.SortOrder) == "ASC" {
		orderDir = "ASC"
	}

	query := fmt.Sprintf("%s %s ORDER BY %s %s LIMIT ? OFFSET ?", baseQuery, whereClause, orderCol, orderDir)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	records := make([]ScanRecord, 0)
	for rows.Next() {
		rec, err := scanRecordFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("scan record row: %w", err)
		}
		records = append(records, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan rows: %w", err)
	}
	return records, nil
}

// CountScans returns the total number of scans matching the filter.
func (d *DB) CountScans(ctx context.Context, filter ListFilter) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return 0, ErrDatabaseClosed
	}

	whereClause, args := buildWhereClause(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM scans %s", whereClause)

	var count int
	if err := d.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count scans: %w", err)
	}
	return count, nil
}

// DeleteScan removes a scan and its associated report.
func (d *DB) DeleteScan(ctx context.Context, idOrPrefix string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	fullID, err := d.resolveID(ctx, idOrPrefix)
	if err != nil {
		return err
	}

	res, err := d.db.ExecContext(ctx, `DELETE FROM scans WHERE id = ?`, fullID)
	if err != nil {
		return fmt.Errorf("delete scan %q: %w", fullID, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check delete affected rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) resolveID(ctx context.Context, idOrPrefix string) (string, error) {
	idOrPrefix = strings.TrimSpace(idOrPrefix)
	if idOrPrefix == "" {
		return "", ErrNotFound
	}

	// Try exact match first
	var exactID string
	err := d.db.QueryRowContext(ctx, `SELECT id FROM scans WHERE id = ?`, idOrPrefix).Scan(&exactID)
	if err == nil {
		return exactID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("lookup scan id: %w", err)
	}

	// If exact match failed, try prefix match (up to 3 to detect ambiguity)
	query := `SELECT id FROM scans WHERE id LIKE ? LIMIT 3`
	rows, err := d.db.QueryContext(ctx, query, idOrPrefix+"%")
	if err != nil {
		return "", fmt.Errorf("lookup scan prefix: %w", err)
	}
	defer rows.Close()

	var matches []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err == nil {
			matches = append(matches, m)
		}
	}

	if len(matches) == 0 {
		return "", ErrNotFound
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("%w: %q matches multiple scan records", ErrAmbiguousID, idOrPrefix)
	}
	return matches[0], nil
}

func validateFilter(filter *ListFilter) error {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}
	if filter.Offset < 0 {
		return fmt.Errorf("%w: offset cannot be negative", ErrInvalidFilter)
	}
	if filter.MinScore != nil && (*filter.MinScore < 0 || *filter.MinScore > 100) {
		return fmt.Errorf("%w: min_score must be between 0 and 100", ErrInvalidFilter)
	}
	if filter.MaxScore != nil && (*filter.MaxScore < 0 || *filter.MaxScore > 100) {
		return fmt.Errorf("%w: max_score must be between 0 and 100", ErrInvalidFilter)
	}
	if filter.MinScore != nil && filter.MaxScore != nil && *filter.MinScore > *filter.MaxScore {
		return fmt.Errorf("%w: min_score cannot exceed max_score", ErrInvalidFilter)
	}
	return nil
}

func buildWhereClause(filter ListFilter) (string, []any) {
	var clauses []string
	var args []any

	if target := strings.TrimSpace(filter.Target); target != "" {
		clauses = append(clauses, "target LIKE ?")
		args = append(args, "%"+target+"%")
	}
	if class := strings.TrimSpace(filter.Classification); class != "" {
		clauses = append(clauses, "LOWER(classification) = LOWER(?)")
		args = append(args, class)
	}
	if status := strings.TrimSpace(string(filter.Status)); status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if filter.MinScore != nil {
		clauses = append(clauses, "overall_score >= ?")
		args = append(args, *filter.MinScore)
	}
	if filter.MaxScore != nil {
		clauses = append(clauses, "overall_score <= ?")
		args = append(args, *filter.MaxScore)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecordFromRow(r rowScanner) (*ScanRecord, error) {
	var rec ScanRecord
	var startedAtStr, completedAtStr, createdAtStr, classStr, statusStr string

	err := r.Scan(
		&rec.ID,
		&rec.Target,
		&startedAtStr,
		&completedAtStr,
		&rec.DurationMs,
		&rec.OverallScore,
		&classStr,
		&rec.PolicyID,
		&rec.PolicyVersion,
		&statusStr,
		&rec.SchemaVersion,
		&createdAtStr,
	)
	if err != nil {
		return nil, err
	}

	rec.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAtStr)
	rec.CompletedAt, _ = time.Parse(time.RFC3339Nano, completedAtStr)
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtStr)
	rec.Classification = risk.RiskClass(classStr)
	rec.Status = ScanStatus(statusStr)

	return &rec, nil
}

func scanRecordFromRows(rows *sql.Rows) (*ScanRecord, error) {
	return scanRecordFromRow(rows)
}
