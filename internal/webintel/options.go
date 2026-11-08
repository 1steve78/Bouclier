// Package webintel orchestrates TLS intelligence and passive HTTP assessment.
package webintel

import (
	"time"

	"bouclier/internal/config"
	"bouclier/internal/tlsintel"
	"bouclier/internal/webcheck"
)

// Options configures the reusable assessment pipeline. A supplied HTTP client
// is reused; otherwise ClientOptions are used to create a bounded client.
type Options struct {
	Config        *config.Config
	HTTPClient    *webcheck.Client
	ClientOptions webcheck.ClientOptions
	TLS           tlsintel.Options
	CurrentTime   time.Time
}
