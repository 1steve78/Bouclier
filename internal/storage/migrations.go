package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// runMigrations ensures the schema_migrations table exists and applies pending migrations sequentially.
func runMigrations(ctx context.Context, db *sql.DB) error {
	initSQL := `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);`
	if _, err := db.ExecContext(ctx, initSQL); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	var currentVersion int
	row := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("read schema_migrations version: %w", err)
	}

	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}

		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("apply migration v%d (%s): %w", m.Version, m.Description, err)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("execute migration sql: %w", err)
	}

	appliedAt := time.Now().UTC().Format(time.RFC3339Nano)
	insertSQL := `INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)`
	if _, err := tx.ExecContext(ctx, insertSQL, m.Version, appliedAt, m.Description); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration tx: %w", err)
	}
	return nil
}
