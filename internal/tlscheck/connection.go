// Package tlscheck performs bounded TLS inspection without exposing CLI or TUI
// concerns. Every connection is pinned to an IP address validated before dial.
package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"bouclier/internal/config"
	"golang.org/x/net/idna"
)

// ConnectionConfig bounds connect and TLS handshake work. A blank Port uses
// 443; a blank ServerName uses the canonical input hostname.
type ConnectionConfig struct {
	Timeout          time.Duration
	HandshakeTimeout time.Duration
	ServerName       string
	Port             string
}

// DefaultConnectionConfig uses the application's existing scanner timeouts.
func DefaultConnectionConfig() ConnectionConfig {
	return ConnectionConfigFromScannerConfig(config.Default().Scanner)
}

// ConnectionConfigFromScannerConfig maps the existing application timeout
// settings to this component; it introduces no duplicate timeout defaults.
func ConnectionConfigFromScannerConfig(scanner config.ScannerConfig) ConnectionConfig {
	return ConnectionConfig{
		Timeout:          scanner.HTTPTimeout,
		HandshakeTimeout: scanner.TLSHandshakeTimeout,
		Port:             "443",
	}
}

// TLSConnectionResult contains negotiated TLS metadata and the peer chain.
// TargetHostname is the normalized connection name, while ServerName is the
// effective TLS verification/SNI identity. HandshakeSuccess reports handshake
// completion; VerifiedChains reports only chains accepted by normal TLS
// verification. It intentionally contains no private keys or URL data.
type TLSConnectionResult struct {
	// TargetHostname is the normalized hostname used for DNS resolution and
	// destination validation. Address is its validated, pinned IP and port.
	TargetHostname string
	// ServerName is the effective TLS identity used for SNI and certificate
	// hostname verification. It may differ from TargetHostname by explicit
	// caller request; it never changes resolution or the pinned destination.
	ServerName       string
	Address          string
	NegotiatedTLS    string
	CipherSuite      uint16
	PeerCertificates []*x509.Certificate
	VerifiedChains   [][]*x509.Certificate
	HandshakeSuccess bool
}

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type inspectDependencies struct {
	resolver resolver
	dial     dialContextFunc
	roots    *x509.CertPool
}

// InspectConnection resolves and validates the target, connects only to one
// of the validated addresses, and performs a normally verified TLS handshake.
// It never resolves the hostname again during dialing.
//
// On a handshake error, InspectConnection returns peer certificate metadata
// with the error when certificates were received. In that case the result has
// HandshakeSuccess=false; certificates from a verification failure are
// untrusted and VerifiedChains remains empty. If no certificate was received,
// it returns a nil result with the error. A non-nil result with an error never
// represents a successful handshake.
func InspectConnection(ctx context.Context, hostname string, cfg ConnectionConfig) (*TLSConnectionResult, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	return inspectConnection(ctx, hostname, cfg, inspectDependencies{
		resolver: net.DefaultResolver,
		dial:     dialer.DialContext,
	})
}

func inspectConnection(ctx context.Context, hostname string, cfg ConnectionConfig, deps inspectDependencies) (*TLSConnectionResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("inspect TLS connection: context is nil")
	}
	if cfg.Timeout <= 0 || cfg.HandshakeTimeout <= 0 {
		return nil, fmt.Errorf("inspect TLS connection: connection and handshake timeouts must be positive")
	}
	port := cfg.Port
	if port == "" {
		port = "443"
	}
	if err := validatePort(port); err != nil {
		return nil, fmt.Errorf("inspect TLS connection: %w", err)
	}
	portNumber, _ := strconv.Atoi(port)
	port = strconv.Itoa(portNumber)
	target, isIP, err := normalizeTarget(hostname)
	if err != nil {
		return nil, fmt.Errorf("inspect TLS connection: validate target: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("inspect TLS connection: %w", err)
	}
	if deps.dial == nil {
		return nil, fmt.Errorf("inspect TLS connection: dialer is unavailable")
	}

	serverName := target
	if cfg.ServerName != "" {
		serverName, _, err = normalizeTarget(cfg.ServerName)
		if err != nil {
			return nil, fmt.Errorf("inspect TLS connection: invalid TLS server name")
		}
	}

	operationCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	addresses := make([]netip.Addr, 0, 1)
	if isIP {
		addr, parseErr := netip.ParseAddr(target)
		if parseErr != nil || !isAllowedAddress(addr) {
			return nil, fmt.Errorf("inspect TLS connection: destination address is not permitted")
		}
		addresses = append(addresses, addr)
	} else {
		if isLocalHostname(target) {
			return nil, fmt.Errorf("inspect TLS connection: local or internal hostnames are not permitted")
		}
		if deps.resolver == nil {
			return nil, fmt.Errorf("inspect TLS connection: DNS resolver is unavailable")
		}
		resolved, lookupErr := deps.resolver.LookupNetIP(operationCtx, "ip", target)
		if lookupErr != nil {
			return nil, fmt.Errorf("inspect TLS connection: resolve target: %w", lookupErr)
		}
		if len(resolved) == 0 {
			return nil, fmt.Errorf("inspect TLS connection: target resolved to no addresses")
		}
		for _, address := range resolved {
			address = address.Unmap()
			if !isAllowedAddress(address) {
				return nil, fmt.Errorf("inspect TLS connection: DNS response contains a prohibited address")
			}
			addresses = appendUniqueAddress(addresses, address)
		}
	}

	var lastDialErr error
	for _, address := range addresses {
		if err := operationCtx.Err(); err != nil {
			return nil, fmt.Errorf("inspect TLS connection: %w", err)
		}
		endpoint := net.JoinHostPort(address.String(), port)
		rawConn, dialErr := deps.dial(operationCtx, "tcp", endpoint)
		if dialErr != nil {
			lastDialErr = dialErr
			continue
		}
		result, handshakeErr := performTLSHandshake(operationCtx, rawConn, target, serverName, endpoint, cfg.HandshakeTimeout, deps.roots)
		if handshakeErr != nil {
			return result, fmt.Errorf("inspect TLS connection: TLS handshake failed: %w", handshakeErr)
		}
		return result, nil
	}
	if err := operationCtx.Err(); err != nil {
		return nil, fmt.Errorf("inspect TLS connection: %w", err)
	}
	if lastDialErr == nil {
		return nil, fmt.Errorf("inspect TLS connection: unable to connect to validated addresses")
	}
	return nil, fmt.Errorf("inspect TLS connection: connect to validated address: %w", lastDialErr)
}

func performTLSHandshake(ctx context.Context, rawConn net.Conn, targetHostname, serverName, address string, timeout time.Duration, roots *x509.CertPool) (*TLSConnectionResult, error) {
	defer rawConn.Close()
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		state := tlsConn.ConnectionState()
		var verificationError *tls.CertificateVerificationError
		if errors.As(err, &verificationError) {
			state.PeerCertificates = verificationError.UnverifiedCertificates
			state.VerifiedChains = nil
		}
		if len(state.PeerCertificates) == 0 {
			return nil, err
		}
		return connectionResult(targetHostname, serverName, address, state, false), err
	}
	state := tlsConn.ConnectionState()
	return connectionResult(targetHostname, serverName, address, state, true), nil
}

func connectionResult(targetHostname, serverName, address string, state tls.ConnectionState, handshakeSuccess bool) *TLSConnectionResult {
	peerCertificates := append([]*x509.Certificate(nil), state.PeerCertificates...)
	var verifiedChains [][]*x509.Certificate
	if len(state.VerifiedChains) > 0 {
		verifiedChains = make([][]*x509.Certificate, len(state.VerifiedChains))
		for i, chain := range state.VerifiedChains {
			verifiedChains[i] = append([]*x509.Certificate(nil), chain...)
		}
	}
	return &TLSConnectionResult{
		TargetHostname:   targetHostname,
		ServerName:       serverName,
		Address:          address,
		NegotiatedTLS:    tlsVersionName(state.Version),
		CipherSuite:      state.CipherSuite,
		PeerCertificates: peerCertificates,
		VerifiedChains:   verifiedChains,
		HandshakeSuccess: handshakeSuccess,
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func validatePort(port string) error {
	for _, r := range port {
		if r < '0' || r > '9' {
			return fmt.Errorf("port must contain only decimal digits")
		}
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func normalizeTarget(hostname string) (string, bool, error) {
	if hostname == "" || strings.TrimSpace(hostname) != hostname || strings.ContainsAny(hostname, "/\\@?#[]%") {
		return "", false, fmt.Errorf("hostname syntax is invalid")
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		return address.Unmap().String(), true, nil
	}
	if strings.Contains(hostname, ":") {
		return "", false, fmt.Errorf("IPv6 literals must be valid and unbracketed")
	}
	hostname = strings.TrimSuffix(hostname, ".")
	if looksLikeInvalidIPv4(hostname) {
		return "", false, fmt.Errorf("IPv4 literal is invalid")
	}
	ascii, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		return "", false, fmt.Errorf("hostname IDNA validation failed")
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || len(ascii) > 253 {
		return "", false, fmt.Errorf("hostname length is invalid")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return "", false, fmt.Errorf("hostname label is invalid")
		}
		for i := 0; i < len(label); i++ {
			if !isASCIIAlphaNumeric(label[i]) && label[i] != '-' {
				return "", false, fmt.Errorf("hostname label contains invalid characters")
			}
		}
	}
	if !strings.Contains(ascii, ".") {
		return "", false, fmt.Errorf("single-label hostnames are not permitted")
	}
	return ascii, false, nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
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

func isLocalHostname(hostname string) bool {
	if hostname == "localhost" {
		return true
	}
	for _, suffix := range []string{"localhost", "local", "internal", "lan", "home", "home.arpa", "test", "invalid", "example", "onion", "corp", "intranet", "private", "localdomain"} {
		if hostname == suffix {
			return true
		}
		if strings.HasSuffix(hostname, suffix) {
			if len(hostname) > len(suffix) && hostname[len(hostname)-len(suffix)-1] == '.' {
				return true
			}
		}
	}
	return false
}

var prohibitedPrefixes = mustParsePrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
	"2001:db8::/32", "2002::/16", "3fff::/20",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

func mustParsePrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic("invalid built-in prohibited prefix")
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func isAllowedAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	if address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range prohibitedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func appendUniqueAddress(addresses []netip.Addr, candidate netip.Addr) []netip.Addr {
	for _, address := range addresses {
		if address == candidate {
			return addresses
		}
	}
	return append(addresses, candidate)
}
