package storage

import "errors"

var (
	// ErrNotFound indicates the requested scan record or report does not exist.
	ErrNotFound = errors.New("scan record not found")

	// ErrDuplicateScan indicates a record with the same ID already exists.
	ErrDuplicateScan = errors.New("scan record already exists")

	// ErrInvalidFilter indicates an invalid search or pagination parameter.
	ErrInvalidFilter = errors.New("invalid list filter")

	// ErrDatabaseClosed indicates an operation was attempted on a closed database.
	ErrDatabaseClosed = errors.New("database connection is closed")

	// ErrAmbiguousID indicates a prefix matched multiple scan records.
	ErrAmbiguousID = errors.New("ambiguous scan id prefix matches multiple records")
)
