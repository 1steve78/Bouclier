package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DB represents a managed SQLite database instance.
type DB struct {
	db      *sql.DB
	path    string
	closed  bool
	mu      sync.RWMutex
	writeMu sync.Mutex
}

// Open initializes and migrates the SQLite database at path.
// If path begins with '~', it expands to the current user's home directory.
// If path is ":memory:", an in-memory database is created.
func Open(path string) (*DB, error) {
	resolvedPath, err := ResolvePath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path %q: %w", path, err)
	}

	if resolvedPath != ":memory:" && !strings.HasPrefix(resolvedPath, "file:") {
		dir := filepath.Dir(resolvedPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, fmt.Errorf("create database directory %q: %w", dir, err)
			}
		}
	}

	// Build SQLite DSN with pragmas
	dsn := buildDSN(resolvedPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if resolvedPath == ":memory:" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(2)
		db.SetConnMaxLifetime(1 * time.Hour)
	}

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	// Run versioned migrations
	if err := runMigrations(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("run sqlite migrations: %w", err)
	}

	return &DB{
		db:   db,
		path: resolvedPath,
	}, nil
}

// ResolvePath resolves tilde ('~') prefixes and returns a normalized filesystem path.
func ResolvePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ":memory:", nil
	}
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return path, nil
	}

	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") || path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine user home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}

	return filepath.Clean(path), nil
}

func buildDSN(resolvedPath string) string {
	pragmas := []string{
		"_pragma=foreign_keys(1)",
		"_pragma=busy_timeout(5000)",
	}
	if resolvedPath != ":memory:" {
		pragmas = append(pragmas,
			"_pragma=journal_mode(WAL)",
			"_pragma=synchronous(NORMAL)",
		)
	}

	sep := "?"
	if strings.Contains(resolvedPath, "?") {
		sep = "&"
	}
	return resolvedPath + sep + strings.Join(pragmas, "&")
}

// Close gracefully closes the database connection.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// Path returns the resolved path of the database.
func (d *DB) Path() string {
	return d.path
}

// SQLDB returns the underlying *sql.DB instance for testing or transactions.
func (d *DB) SQLDB() (*sql.DB, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return nil, ErrDatabaseClosed
	}
	return d.db, nil
}
