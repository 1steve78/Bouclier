package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RegisterSource creates or updates a configured threat intelligence source.
func (d *DB) RegisterSource(ctx context.Context, src IntelSource) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	src.ID = strings.TrimSpace(src.ID)
	if src.ID == "" {
		return errors.New("source id is required")
	}
	src.Name = strings.TrimSpace(src.Name)
	if src.Name == "" {
		return errors.New("source name is required")
	}
	src.ProviderType = strings.TrimSpace(src.ProviderType)
	if src.ProviderType == "" {
		return errors.New("provider_type is required")
	}
	src.Endpoint = strings.TrimSpace(src.Endpoint)
	if src.Endpoint == "" {
		return errors.New("endpoint is required")
	}

	now := time.Now().UTC()
	if src.CreatedAt.IsZero() {
		src.CreatedAt = now
	}
	src.UpdatedAt = now

	intervalSec := int(src.UpdateInterval.Seconds())
	if intervalSec <= 0 {
		intervalSec = 86400 // 24 hours default
	}

	format := strings.ToLower(strings.TrimSpace(src.Format))
	if format == "" {
		format = "json"
	}

	query := `
INSERT INTO intel_sources (
    id, name, provider_type, endpoint, enabled,
    update_interval_seconds, auth_header_env, attribution, license, format, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    name = excluded.name,
    provider_type = excluded.provider_type,
    endpoint = excluded.endpoint,
    enabled = excluded.enabled,
    update_interval_seconds = excluded.update_interval_seconds,
    auth_header_env = excluded.auth_header_env,
    attribution = excluded.attribution,
    license = excluded.license,
    format = excluded.format,
    updated_at = excluded.updated_at;
`
	enabledInt := 0
	if src.Enabled {
		enabledInt = 1
	}

	_, err := d.db.ExecContext(ctx, query,
		src.ID, src.Name, src.ProviderType, src.Endpoint, enabledInt,
		intervalSec, strings.TrimSpace(src.AuthHeaderEnv), src.Attribution, src.License, format,
		src.CreatedAt.Format(time.RFC3339Nano),
		src.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("register intel source: %w", err)
	}
	return nil
}

// UpdateSource updates an existing threat intelligence source.
func (d *DB) UpdateSource(ctx context.Context, src IntelSource) error {
	return d.RegisterSource(ctx, src)
}

// GetSource retrieves a single source by ID.
func (d *DB) GetSource(ctx context.Context, id string) (*IntelSource, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	id = strings.TrimSpace(id)
	query := `
SELECT id, name, provider_type, endpoint, enabled,
       update_interval_seconds, auth_header_env, attribution, license, format, created_at, updated_at
FROM intel_sources
WHERE id = ?;
`
	var s IntelSource
	var enabledInt int
	var intervalSec int
	var authHeaderEnv string
	var createdAtStr, updatedAtStr string

	row := d.db.QueryRowContext(ctx, query, id)
	err := row.Scan(
		&s.ID, &s.Name, &s.ProviderType, &s.Endpoint, &enabledInt,
		&intervalSec, &authHeaderEnv, &s.Attribution, &s.License, &s.Format,
		&createdAtStr, &updatedAtStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get intel source %q: %w", id, err)
	}

	s.Enabled = (enabledInt == 1)
	s.UpdateInterval = time.Duration(intervalSec) * time.Second
	s.AuthHeaderEnv = authHeaderEnv
	s.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtStr)
	s.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAtStr)
	return &s, nil
}

// ListSources returns all configured threat intelligence sources.
func (d *DB) ListSources(ctx context.Context) ([]IntelSource, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	query := `
SELECT id, name, provider_type, endpoint, enabled,
       update_interval_seconds, auth_header_env, attribution, license, format, created_at, updated_at
FROM intel_sources
ORDER BY name ASC;
`
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list intel sources: %w", err)
	}
	defer rows.Close()

	var sources []IntelSource
	for rows.Next() {
		var s IntelSource
		var enabledInt int
		var intervalSec int
		var authHeaderEnv string
		var createdAtStr, updatedAtStr string

		if err := rows.Scan(
			&s.ID, &s.Name, &s.ProviderType, &s.Endpoint, &enabledInt,
			&intervalSec, &authHeaderEnv, &s.Attribution, &s.License, &s.Format,
			&createdAtStr, &updatedAtStr,
		); err != nil {
			return nil, fmt.Errorf("scan intel source row: %w", err)
		}

		s.Enabled = (enabledInt == 1)
		s.UpdateInterval = time.Duration(intervalSec) * time.Second
		s.AuthHeaderEnv = authHeaderEnv
		s.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtStr)
		s.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAtStr)
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate intel sources: %w", err)
	}
	return sources, nil
}

// SetSourceEnabled toggles the enabled flag for a source.
func (d *DB) SetSourceEnabled(ctx context.Context, id string, enabled bool) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	enabledInt := 0
	if enabled {
		enabledInt = 1
	}

	query := `UPDATE intel_sources SET enabled = ?, updated_at = ? WHERE id = ?;`
	res, err := d.db.ExecContext(ctx, query, enabledInt, time.Now().UTC().Format(time.RFC3339Nano), strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("set source enabled: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSource deletes a source and all associated indicators cascade-deleted.
func (d *DB) DeleteSource(ctx context.Context, id string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := `DELETE FROM intel_sources WHERE id = ?;`
	res, err := d.db.ExecContext(ctx, query, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("delete source %q: %w", id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveIndicatorBatch atomically upserts indicators for a source.
func (d *DB) SaveIndicatorBatch(ctx context.Context, sourceID string, indicators []IntelIndicator) (int, int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return 0, 0, ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if len(indicators) == 0 {
		return 0, 0, nil
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin indicator batch tx: %w", err)
	}
	defer tx.Rollback()

	checkStmt, err := tx.PrepareContext(ctx, `SELECT id FROM intel_indicators WHERE source_id = ? AND indicator_type = ? AND value = ?;`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare check indicator stmt: %w", err)
	}
	defer checkStmt.Close()

	insertStmt, err := tx.PrepareContext(ctx, `
INSERT INTO intel_indicators (
    id, source_id, source_name, indicator_type, value,
    category, confidence, severity, first_seen, last_seen,
    expires_at, ingested_at, source_ref, description, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare insert indicator stmt: %w", err)
	}
	defer insertStmt.Close()

	updateStmt, err := tx.PrepareContext(ctx, `
UPDATE intel_indicators SET
    source_name = ?,
    category = ?,
    confidence = ?,
    severity = ?,
    first_seen = ?,
    last_seen = ?,
    expires_at = ?,
    ingested_at = ?,
    source_ref = ?,
    description = ?,
    metadata_json = ?
WHERE id = ?;
`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare update indicator stmt: %w", err)
	}
	defer updateStmt.Close()

	imported := 0
	updated := 0

	for _, ind := range indicators {
		if ind.ID == "" {
			ind.ID = uuid.NewString()
		}
		if ind.IngestedAt.IsZero() {
			ind.IngestedAt = time.Now().UTC()
		}

		var firstSeenStr, lastSeenStr, expiresAtStr *string
		if ind.FirstSeen != nil {
			s := ind.FirstSeen.Format(time.RFC3339Nano)
			firstSeenStr = &s
		}
		if ind.LastSeen != nil {
			s := ind.LastSeen.Format(time.RFC3339Nano)
			lastSeenStr = &s
		}
		if ind.ExpiresAt != nil {
			s := ind.ExpiresAt.Format(time.RFC3339Nano)
			expiresAtStr = &s
		}

		metaJSON := "{}"
		if ind.Metadata != nil {
			if b, mErr := json.Marshal(ind.Metadata); mErr == nil {
				metaJSON = string(b)
			}
		}

		var existingID string
		err := checkStmt.QueryRowContext(ctx, sourceID, ind.Type, ind.Value).Scan(&existingID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, 0, fmt.Errorf("check existing indicator: %w", err)
		}

		if errors.Is(err, sql.ErrNoRows) {
			// Insert
			_, insErr := insertStmt.ExecContext(ctx,
				ind.ID, sourceID, ind.SourceName, ind.Type, ind.Value,
				ind.Category, ind.Confidence, ind.Severity,
				firstSeenStr, lastSeenStr, expiresAtStr,
				ind.IngestedAt.Format(time.RFC3339Nano),
				ind.SourceRef, ind.Description, metaJSON,
			)
			if insErr != nil {
				return 0, 0, fmt.Errorf("insert indicator: %w", insErr)
			}
			imported++
		} else {
			// Update
			_, updErr := updateStmt.ExecContext(ctx,
				ind.SourceName, ind.Category, ind.Confidence, ind.Severity,
				firstSeenStr, lastSeenStr, expiresAtStr,
				ind.IngestedAt.Format(time.RFC3339Nano),
				ind.SourceRef, ind.Description, metaJSON,
				existingID,
			)
			if updErr != nil {
				return 0, 0, fmt.Errorf("update indicator: %w", updErr)
			}
			updated++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit indicator batch: %w", err)
	}
	return imported, updated, nil
}

// LookupIndicators finds unexpired indicators matching any of the specified (type, value) criteria.
func (d *DB) LookupIndicators(ctx context.Context, queries []IndicatorQuery) ([]IntelIndicator, error) {
	return d.LookupIndicatorsAt(ctx, queries, time.Now().UTC())
}

// LookupIndicatorsAt finds unexpired indicators matching any of the specified (type, value) criteria at a reference time.
func (d *DB) LookupIndicatorsAt(ctx context.Context, queries []IndicatorQuery, at time.Time) ([]IntelIndicator, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	if len(queries) == 0 {
		return []IntelIndicator{}, nil
	}

	nowStr := at.UTC().Format(time.RFC3339Nano)
	clauses := make([]string, 0, len(queries))
	args := []interface{}{nowStr}

	for _, q := range queries {
		typ := strings.TrimSpace(q.Type)
		val := strings.TrimSpace(q.Value)
		if typ == "" || val == "" {
			continue
		}
		clauses = append(clauses, "(indicator_type = ? AND value = ?)")
		args = append(args, typ, val)
	}

	if len(clauses) == 0 {
		return []IntelIndicator{}, nil
	}

	query := fmt.Sprintf(`
SELECT id, source_id, source_name, indicator_type, value,
       category, confidence, severity, first_seen, last_seen,
       expires_at, ingested_at, source_ref, description, metadata_json
FROM intel_indicators
WHERE (expires_at IS NULL OR expires_at > ?)
  AND (%s)
ORDER BY confidence DESC, last_seen DESC;
`, strings.Join(clauses, " OR "))

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("lookup indicators: %w", err)
	}
	defer rows.Close()

	var results []IntelIndicator
	for rows.Next() {
		ind, err := scanIndicatorRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *ind)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate indicators: %w", err)
	}
	return results, nil
}

// SearchIndicators searches indicators by query string across value, description, or category.
func (d *DB) SearchIndicators(ctx context.Context, query string, limit int, offset int) ([]IntelIndicator, int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, 0, ErrDatabaseClosed
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	query = strings.TrimSpace(query)
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)

	var countQuery string
	var selectQuery string
	var countArgs []interface{}
	var selectArgs []interface{}

	if query == "" {
		countQuery = `SELECT COUNT(*) FROM intel_indicators WHERE (expires_at IS NULL OR expires_at > ?);`
		countArgs = []interface{}{nowStr}

		selectQuery = `
SELECT id, source_id, source_name, indicator_type, value,
       category, confidence, severity, first_seen, last_seen,
       expires_at, ingested_at, source_ref, description, metadata_json
FROM intel_indicators
WHERE (expires_at IS NULL OR expires_at > ?)
ORDER BY confidence DESC, ingested_at DESC
LIMIT ? OFFSET ?;
`
		selectArgs = []interface{}{nowStr, limit, offset}
	} else {
		likeTerm := "%" + query + "%"
		countQuery = `
SELECT COUNT(*) FROM intel_indicators
WHERE (expires_at IS NULL OR expires_at > ?)
  AND (value LIKE ? OR category LIKE ? OR description LIKE ?);
`
		countArgs = []interface{}{nowStr, likeTerm, likeTerm, likeTerm}

		selectQuery = `
SELECT id, source_id, source_name, indicator_type, value,
       category, confidence, severity, first_seen, last_seen,
       expires_at, ingested_at, source_ref, description, metadata_json
FROM intel_indicators
WHERE (expires_at IS NULL OR expires_at > ?)
  AND (value LIKE ? OR category LIKE ? OR description LIKE ?)
ORDER BY confidence DESC, ingested_at DESC
LIMIT ? OFFSET ?;
`
		selectArgs = []interface{}{nowStr, likeTerm, likeTerm, likeTerm, limit, offset}
	}

	var total int
	if err := d.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count matching indicators: %w", err)
	}

	rows, err := d.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("search indicators: %w", err)
	}
	defer rows.Close()

	var results []IntelIndicator
	for rows.Next() {
		ind, err := scanIndicatorRow(rows)
		if err != nil {
			return nil, 0, err
		}
		results = append(results, *ind)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate search results: %w", err)
	}
	return results, total, nil
}

// PruneExpiredIndicators deletes indicators whose expires_at is before the given timestamp.
func (d *DB) PruneExpiredIndicators(ctx context.Context, before time.Time, dryRun bool) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return 0, ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if before.IsZero() {
		before = time.Now().UTC()
	}
	beforeStr := before.Format(time.RFC3339Nano)

	if dryRun {
		var count int
		err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM intel_indicators WHERE expires_at IS NOT NULL AND expires_at < ?;`, beforeStr).Scan(&count)
		if err != nil {
			return 0, fmt.Errorf("count expired indicators: %w", err)
		}
		return count, nil
	}

	res, err := d.db.ExecContext(ctx, `DELETE FROM intel_indicators WHERE expires_at IS NOT NULL AND expires_at < ?;`, beforeStr)
	if err != nil {
		return 0, fmt.Errorf("delete expired indicators: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(rows), nil
}

// RecordSyncRun persists the result of a threat intelligence feed synchronization.
func (d *DB) RecordSyncRun(ctx context.Context, run IntelSyncRun) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDatabaseClosed
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if run.ID == "" {
		run.ID = uuid.NewString()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}

	query := `
INSERT INTO intel_sync_runs (
    id, source_id, started_at, completed_at, status,
    imported_count, updated_count, skipped_count, rejected_count,
    error_message, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`
	_, err := d.db.ExecContext(ctx, query,
		run.ID, run.SourceID,
		run.StartedAt.Format(time.RFC3339Nano),
		run.CompletedAt.Format(time.RFC3339Nano),
		run.Status, run.ImportedCount, run.UpdatedCount, run.SkippedCount, run.RejectedCount,
		run.ErrorMessage, run.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("record sync run: %w", err)
	}
	return nil
}

// GetLatestSyncRun retrieves the most recent sync run for a source, or nil if none exists.
func (d *DB) GetLatestSyncRun(ctx context.Context, sourceID string) (*IntelSyncRun, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	query := `
SELECT id, source_id, started_at, completed_at, status,
       imported_count, updated_count, skipped_count, rejected_count,
       error_message, created_at
FROM intel_sync_runs
WHERE source_id = ?
ORDER BY started_at DESC
LIMIT 1;
`
	var r IntelSyncRun
	var startedStr, completedStr, createdStr string

	err := d.db.QueryRowContext(ctx, query, strings.TrimSpace(sourceID)).Scan(
		&r.ID, &r.SourceID, &startedStr, &completedStr, &r.Status,
		&r.ImportedCount, &r.UpdatedCount, &r.SkippedCount, &r.RejectedCount,
		&r.ErrorMessage, &createdStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest sync run: %w", err)
	}

	r.StartedAt, _ = time.Parse(time.RFC3339Nano, startedStr)
	r.CompletedAt, _ = time.Parse(time.RFC3339Nano, completedStr)
	r.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdStr)
	r.Duration = r.CompletedAt.Sub(r.StartedAt)
	return &r, nil
}

// GetIntelStats returns high-level metrics for the local threat intelligence store.
func (d *DB) GetIntelStats(ctx context.Context) (*IntelStats, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}

	stats := &IntelStats{}

	// Total indicators
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM intel_indicators;`).Scan(&stats.TotalIndicators); err != nil {
		return nil, fmt.Errorf("count indicators: %w", err)
	}

	// Sources count
	row := d.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0) FROM intel_sources;`)
	if err := row.Scan(&stats.TotalSources, &stats.EnabledSources); err != nil {
		return nil, fmt.Errorf("count sources: %w", err)
	}

	// Latest sync run
	var startedStr, statusStr, errMsg string
	err := d.db.QueryRowContext(ctx, `SELECT started_at, status, error_message FROM intel_sync_runs ORDER BY started_at DESC LIMIT 1;`).Scan(&startedStr, &statusStr, &errMsg)
	if err == nil {
		t, pErr := time.Parse(time.RFC3339Nano, startedStr)
		if pErr == nil {
			stats.LastSyncTime = &t
		}
		stats.LastSyncStatus = statusStr
		if statusStr == "failed" {
			stats.HasSyncFailures = true
			stats.LastErrorMessage = errMsg
		}
	}

	return stats, nil
}

func scanIndicatorRow(scanner interface{ Scan(...interface{}) error }) (*IntelIndicator, error) {
	var ind IntelIndicator
	var firstSeenStr, lastSeenStr, expiresAtStr sql.NullString
	var ingestedStr string
	var metaJSON string

	err := scanner.Scan(
		&ind.ID, &ind.SourceID, &ind.SourceName, &ind.Type, &ind.Value,
		&ind.Category, &ind.Confidence, &ind.Severity,
		&firstSeenStr, &lastSeenStr, &expiresAtStr,
		&ingestedStr, &ind.SourceRef, &ind.Description, &metaJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("scan indicator row: %w", err)
	}

	if firstSeenStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, firstSeenStr.String); err == nil {
			ind.FirstSeen = &t
		}
	}
	if lastSeenStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, lastSeenStr.String); err == nil {
			ind.LastSeen = &t
		}
	}
	if expiresAtStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, expiresAtStr.String); err == nil {
			ind.ExpiresAt = &t
		}
	}
	ind.IngestedAt, _ = time.Parse(time.RFC3339Nano, ingestedStr)

	if metaJSON != "" && metaJSON != "{}" {
		_ = json.Unmarshal([]byte(metaJSON), &ind.Metadata)
	}
	return &ind, nil
}
