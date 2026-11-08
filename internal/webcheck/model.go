// Package webcheck performs bounded HTTP inspection and passive response analysis.
package webcheck

import (
	"net/http"
	"time"
)

// Redirect records one followed redirect. URLs are sanitized and omit query data.
type Redirect struct {
	Source      string
	Destination string
	StatusCode  int
	CrossOrigin bool
	Downgrade   bool
}

// CookieInfo contains selected Set-Cookie attributes and never includes value.
type CookieInfo struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite string
	Expires  time.Time
	MaxAge   int
}

// HTTPInspectionResult contains response metadata and, for HTML, a bounded body.
type HTTPInspectionResult struct {
	RequestedURL            string
	FinalURL                string
	StatusCode              int
	Protocol                string
	Headers                 http.Header
	ContentType             string
	ContentLength           int64
	BytesRead               int64
	RedirectChain           []Redirect
	RedirectCount           int
	UsedHTTPS               bool
	FinalHTTPS              bool
	BodyTruncated           bool
	HTML                    []byte
	IsHTML                  bool
	Duration                time.Duration
	CrossOriginRedirect     bool
	HTTPSDowngrade          bool
	ExternalResourceOrigins []string
	CookieAttributes        []CookieInfo
	cookies                 []*http.Cookie
}
