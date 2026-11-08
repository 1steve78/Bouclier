// Package tlsintel composes TLS connection, certificate, and CT analysis.
package tlsintel

import (
	"time"

	"bouclier/internal/certanalysis"
	"bouclier/internal/ct"
	"bouclier/internal/tlscheck"
)

// Options configures each stage of TLS intelligence. An empty CT scope uses
// exact-hostname scope. A nil CT provider disables CT lookup.
type Options struct {
	Connection  tlscheck.ConnectionConfig
	Certificate certanalysis.Config
	CTProvider  ct.Provider
	CTScope     ct.QueryScope
	CTLimit     int
	CurrentTime time.Time
}
