package cli

import (
	"errors"
	"fmt"
)

const (
	ExitSuccess               = 0
	ExitGeneralError          = 1
	ExitInvalidUsage          = 2
	ExitScanFailure           = 3
	ExitOutputError           = 4
	ExitRiskThresholdExceeded = 5
)

// ExitError represents an error with a specific CLI exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// NewExitError constructs an ExitError with the given code and formatted message.
func NewExitError(code int, format string, args ...any) *ExitError {
	return &ExitError{
		Code: code,
		Err:  fmt.Errorf(format, args...),
	}
}

// ExitCode extracts the exit code from an error. Returns ExitSuccess if err is
// nil, exitErr.Code if err is an *ExitError, or ExitInvalidUsage for command
// syntax / usage errors from Cobra.
func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return ExitInvalidUsage
}
