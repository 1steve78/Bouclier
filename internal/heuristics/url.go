package heuristics

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var errMalformedURL = errors.New("malformed URL syntax")

// NormalizedURL contains the parsed URL components used by future analysis.
// Original preserves the input. Host is the normalized authority and omits a
// default port; Port retains an explicitly supplied port, including a default.
// Path, Query, and Fragment retain their escaped forms.
type NormalizedURL struct {
	Original         string
	OriginalHostname string
	Normalized       string
	Scheme           string
	Host             string
	Hostname         string
	Port             string
	Path             string
	Query            string
	Fragment         string
	IsHTTPS          bool
	HasUserInfo      bool
	IsIPAddress      bool
}

// NormalizeURL parses and normalizes an absolute HTTP or HTTPS URL. It does
// not resolve names or make network requests.
func NormalizeURL(raw string) (*NormalizedURL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("validate URL: input is empty")
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return nil, fmt.Errorf("validate URL: control characters are not allowed")
		}
		if unicode.IsSpace(r) {
			return nil, fmt.Errorf("validate URL: whitespace is not allowed")
		}
	}
	if strings.ContainsRune(raw, '\\') {
		return nil, fmt.Errorf("validate URL: backslashes are not allowed")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		// url.Parse errors can include the full input, which may contain secrets.
		var urlErr *url.Error
		if errors.As(err, &urlErr) && strings.Contains(urlErr.Err.Error(), "invalid port") {
			return nil, fmt.Errorf("validate port: port must contain only decimal digits")
		}
		return nil, fmt.Errorf("parse URL: %w", errMalformedURL)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("validate URL scheme: unsupported scheme %q", scheme)
	}
	if scheme == "" || parsed.Opaque != "" || !parsed.IsAbs() {
		return nil, fmt.Errorf("validate URL: an absolute URL with an authority is required")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("validate URL: hostname is required")
	}

	hostname, port, isIP, isBracketed, err := parseAuthority(parsed.Host)
	if err != nil {
		return nil, err
	}
	originalHostname := hostname
	portNumber := 0
	if port != "" {
		portNumber, err = validatePort(port)
		if err != nil {
			return nil, err
		}
		port = strconv.Itoa(portNumber)
	}
	if isBracketed {
		ip := net.ParseIP(hostname)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("validate hostname: bracketed host must be an IPv6 address")
		}
		hostname = ip.String()
		isIP = true
	} else if ip := net.ParseIP(hostname); ip != nil && ip.To4() != nil {
		hostname = ip.To4().String()
		isIP = true
	} else {
		hostname, err = normalizeDNSHostname(hostname)
		if err != nil {
			return nil, err
		}
	}

	canonicalPort := port
	if (scheme == "http" && portNumber == 80) || (scheme == "https" && portNumber == 443) {
		canonicalPort = ""
	}
	authority := hostname
	if isIP && strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if canonicalPort != "" {
		authority = net.JoinHostPort(hostname, canonicalPort)
	}

	parsed.Scheme = scheme
	parsed.Host = authority
	if parsed.Path == "" {
		parsed.Path = "/"
		parsed.RawPath = ""
	}

	return &NormalizedURL{
		Original:         raw,
		OriginalHostname: originalHostname,
		Normalized:       parsed.String(),
		Scheme:           scheme,
		Host:             authority,
		Hostname:         hostname,
		Port:             port,
		Path:             parsed.EscapedPath(),
		Query:            parsed.RawQuery,
		Fragment:         parsed.EscapedFragment(),
		IsHTTPS:          scheme == "https",
		HasUserInfo:      parsed.User != nil,
		IsIPAddress:      isIP,
	}, nil
}

func parseAuthority(authority string) (hostname, port string, isIP, bracketed bool, err error) {
	if strings.HasPrefix(authority, "[") {
		closeBracket := strings.IndexByte(authority, ']')
		if closeBracket < 0 || closeBracket == 1 {
			return "", "", false, false, fmt.Errorf("validate authority: malformed IPv6 bracket syntax")
		}
		hostname = authority[1:closeBracket]
		rest := authority[closeBracket+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 || strings.Contains(rest[1:], ":") {
				return "", "", false, false, fmt.Errorf("validate authority: malformed port or bracket syntax")
			}
			port = rest[1:]
		}
		if strings.Contains(hostname, "%") {
			return "", "", false, false, fmt.Errorf("validate hostname: IPv6 zone identifiers are not supported")
		}
		ip := net.ParseIP(hostname)
		if ip == nil || ip.To4() != nil {
			return "", "", false, false, fmt.Errorf("validate hostname: bracketed host must be an IPv6 address")
		}
		return hostname, port, true, true, nil
	}
	if strings.ContainsAny(authority, "[]") {
		return "", "", false, false, fmt.Errorf("validate authority: malformed bracket syntax")
	}
	if strings.Count(authority, ":") > 1 {
		return "", "", false, false, fmt.Errorf("validate authority: IPv6 addresses must be bracketed")
	}
	if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
		hostname, port = authority[:colon], authority[colon+1:]
		if port == "" {
			return "", "", false, false, fmt.Errorf("validate port: port cannot be empty")
		}
	} else {
		hostname = authority
	}
	if hostname == "" {
		return "", "", false, false, fmt.Errorf("validate URL: hostname is required")
	}
	return hostname, port, false, false, nil
}

func validatePort(port string) (int, error) {
	for _, r := range port {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("validate port: port must contain only decimal digits")
		}
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return 0, fmt.Errorf("validate port: port must be between 1 and 65535")
	}
	return value, nil
}

func normalizeDNSHostname(hostname string) (string, error) {
	if strings.HasSuffix(hostname, ".") {
		hostname = strings.TrimSuffix(hostname, ".")
	}
	if strings.ContainsAny(hostname, "[]:%") {
		return "", fmt.Errorf("validate hostname: hostname syntax is invalid")
	}
	asciiHostname, err := normalizeIDNAHostname(hostname)
	if err != nil {
		return "", fmt.Errorf("validate hostname: invalid IDNA hostname: %w", err)
	}
	hostname = asciiHostname
	if len(hostname) == 0 || len(hostname) > 253 {
		return "", fmt.Errorf("validate hostname: hostname length is invalid")
	}
	if looksLikeInvalidIPv4(hostname) {
		return "", fmt.Errorf("validate hostname: invalid IPv4 address")
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("validate hostname: hostname label length is invalid")
		}
		if !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return "", fmt.Errorf("validate hostname: hostname labels must start and end with a letter or digit")
		}
		for i := 0; i < len(label); i++ {
			if !isASCIIAlphaNumeric(label[i]) && label[i] != '-' {
				return "", fmt.Errorf("validate hostname: hostname syntax is invalid")
			}
		}
	}
	return hostname, nil
}

// normalizeIDNAHostname applies the documented lookup profile and verifies
// that any resulting A-labels decode and round-trip under the same profile.
func normalizeIDNAHostname(hostname string) (string, error) {
	if !utf8.ValidString(hostname) {
		return "", fmt.Errorf("hostname is not valid UTF-8")
	}
	asciiHostname, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		return "", err
	}
	asciiHostname = strings.ToLower(strings.TrimSuffix(asciiHostname, "."))
	unicodeHostname, err := idna.Lookup.ToUnicode(asciiHostname)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(unicodeHostname, unicode.ReplacementChar) {
		return "", fmt.Errorf("IDNA hostname contains an invalid A-label")
	}
	for _, r := range unicodeHostname {
		if unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d' {
			return "", fmt.Errorf("IDNA hostname contains a disallowed format character")
		}
	}
	registeredForm, err := idna.Registration.ToASCII(unicodeHostname)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(asciiHostname, registeredForm) {
		return "", fmt.Errorf("IDNA hostname is not valid under the registration profile")
	}
	roundTrip, err := idna.Lookup.ToASCII(unicodeHostname)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(asciiHostname, roundTrip) {
		return "", fmt.Errorf("IDNA hostname does not round-trip consistently")
	}
	return asciiHostname, nil
}

func looksLikeInvalidIPv4(hostname string) bool {
	if !strings.Contains(hostname, ".") {
		return false
	}
	for _, r := range hostname {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
