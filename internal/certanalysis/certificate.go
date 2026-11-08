// Package certanalysis evaluates certificate metadata already captured by
// tlscheck. It performs no network access.
package certanalysis

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"bouclier/internal/tlscheck"
)

// Config controls the reference time and trust roots used by certificate
// analysis. A zero CurrentTime selects the current UTC time; nil Roots selects
// the system certificate pool.
type Config struct {
	CurrentTime time.Time
	Roots       *x509.CertPool
}

type ValidityStatus string

const (
	ValidityCurrent     ValidityStatus = "current"
	ValidityExpired     ValidityStatus = "expired"
	ValidityNotYetValid ValidityStatus = "not_yet_valid"
)

// VerificationStatus distinguishes a completed positive or negative check
// from a check that could not be performed.
type VerificationStatus string

const (
	VerificationVerified    VerificationStatus = "verified"
	VerificationFailed      VerificationStatus = "failed"
	VerificationUnavailable VerificationStatus = "unavailable"
)

// CertificateInfo contains selected, non-key certificate metadata.
type CertificateInfo struct {
	IsLeaf             bool
	SubjectCommonName  string
	IssuerCommonName   string
	DNSNames           []string
	IPAddresses        []string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	IsCA               bool
	IsSelfSigned       bool
	ValidAtTime        bool
	ValidityStatus     ValidityStatus
}

// Finding is a structured certificate observation, not a risk score or
// verdict.
type Finding struct {
	Code        string
	Title       string
	Description string
	Category    string
	Evidence    string
}

// CertificateAnalysis reports hostname, time-validity, and trust results
// separately. TLSHandshakeSuccess is copied from the connection result; it
// does not determine whether available certificate metadata is analyzed.
type CertificateAnalysis struct {
	TargetHostname      string
	ServerName          string
	TLSHandshakeSuccess bool
	HasCertificate      bool
	HostnameMatch       bool
	ValidAtTime         bool
	PathTrusted         bool
	PathTrustStatus     VerificationStatus
	ChainValidAtTime    bool
	ChainValidityStatus VerificationStatus
	// ChainTrusted is retained as a compatibility alias for PathTrusted.
	// Deprecated: use PathTrusted and inspect PathTrustStatus.
	ChainTrusted bool
	Certificates []CertificateInfo
	Findings     []Finding
}

// AnalyzeCertificates evaluates certificates already present in result.
// Verification uses the supplied roots or system roots, the effective TLS
// server name, and the selected analysis time. Peer certificate validity is
// assessed separately from trust-path verification.
func AnalyzeCertificates(result *tlscheck.TLSConnectionResult, cfg Config) (*CertificateAnalysis, error) {
	return analyzeCertificates(result, cfg, x509.SystemCertPool)
}

func analyzeCertificates(result *tlscheck.TLSConnectionResult, cfg Config, systemRoots func() (*x509.CertPool, error)) (*CertificateAnalysis, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze certificates: TLS connection result is nil")
	}
	if len(result.PeerCertificates) == 0 {
		return nil, fmt.Errorf("analyze certificates: no peer certificates are available")
	}
	for i, cert := range result.PeerCertificates {
		if cert == nil {
			return nil, fmt.Errorf("analyze certificates: peer certificate %d is nil", i+1)
		}
	}

	now := cfg.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	analysis := &CertificateAnalysis{
		TargetHostname:      result.TargetHostname,
		ServerName:          result.ServerName,
		TLSHandshakeSuccess: result.HandshakeSuccess,
		HasCertificate:      true,
		Certificates:        make([]CertificateInfo, 0, len(result.PeerCertificates)),
		Findings:            make([]Finding, 0),
		PathTrustStatus:     VerificationUnavailable,
		ChainValidityStatus: VerificationUnavailable,
	}

	for i, cert := range result.PeerCertificates {
		info := extractCertificateInfo(cert, i == 0, now)
		analysis.Certificates = append(analysis.Certificates, info)
		if !info.ValidAtTime {
			analysis.Findings = append(analysis.Findings, validityFinding(i, info.ValidityStatus))
		}
	}
	analysis.ValidAtTime = analysis.Certificates[0].ValidAtTime

	leaf := result.PeerCertificates[0]
	if err := leaf.VerifyHostname(result.ServerName); err != nil {
		analysis.Findings = append(analysis.Findings, Finding{
			Code:        "CERT_HOSTNAME_MISMATCH",
			Title:       "Certificate does not match TLS server name",
			Description: "The leaf certificate does not match the effective TLS identity used for this connection.",
			Category:    "certificate-identity",
			Evidence:    "leaf certificate does not match the effective TLS server name",
		})
	} else {
		analysis.HostnameMatch = true
	}
	if analysis.Certificates[0].IsSelfSigned {
		analysis.Findings = append(analysis.Findings, Finding{
			Code:        "CERT_SELF_SIGNED",
			Title:       "Leaf certificate is self-signed",
			Description: "The leaf certificate's signature verifies with its own public key. Self-signing alone does not establish malicious activity.",
			Category:    "certificate-trust",
			Evidence:    "leaf certificate is cryptographically self-signed",
		})
	}

	roots := cfg.Roots
	if roots == nil {
		var err error
		roots, err = systemRoots()
		if err != nil || roots == nil {
			analysis.Findings = append(analysis.Findings, Finding{
				Code:        "CERT_ROOTS_UNAVAILABLE",
				Title:       "Certificate trust roots unavailable",
				Description: "The system trust pool could not be loaded, so the certificate chain could not be evaluated against system roots.",
				Category:    "certificate-trust",
				Evidence:    "system certificate pool unavailable",
			})
		}
	}
	if roots != nil {
		var err error
		analysis.PathTrusted, analysis.PathTrustStatus, err = verifyPathTrust(leaf, result.PeerCertificates[1:], roots, now)
		if err != nil {
			analysis.Findings = append(analysis.Findings, trustFinding(err))
		}
		analysis.ChainValidAtTime, analysis.ChainValidityStatus, err = verifyFullChainAtTime(leaf, result.PeerCertificates[1:], roots, now)
		if err != nil {
			analysis.Findings = append(analysis.Findings, trustFinding(err))
		}
	}
	analysis.ChainTrusted = analysis.PathTrusted

	analysis.Findings = deduplicateAndSort(analysis.Findings)
	return analysis, nil
}

func extractCertificateInfo(cert *x509.Certificate, isLeaf bool, now time.Time) CertificateInfo {
	info := CertificateInfo{
		IsLeaf:             isLeaf,
		SubjectCommonName:  cert.Subject.CommonName,
		IssuerCommonName:   cert.Issuer.CommonName,
		DNSNames:           append([]string(nil), cert.DNSNames...),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		SignatureAlgorithm: cert.SignatureAlgorithm,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
		IsCA:               cert.IsCA,
		IsSelfSigned:       isSelfSigned(cert),
	}
	for _, address := range cert.IPAddresses {
		if parsed, err := netip.ParseAddr(address.String()); err == nil {
			info.IPAddresses = append(info.IPAddresses, parsed.String())
		}
	}
	sort.Strings(info.DNSNames)
	sort.Strings(info.IPAddresses)
	switch {
	case now.Before(info.NotBefore):
		info.ValidityStatus = ValidityNotYetValid
	case now.After(info.NotAfter):
		info.ValidityStatus = ValidityExpired
	default:
		info.ValidityStatus = ValidityCurrent
		info.ValidAtTime = true
	}
	return info
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func validityFinding(index int, status ValidityStatus) Finding {
	if index == 0 {
		if status == ValidityExpired {
			return Finding{"CERT_EXPIRED", "Leaf certificate expired", "The leaf certificate is outside its validity period at the selected analysis time.", "certificate-validity", "leaf certificate is expired at the selected analysis time"}
		}
		return Finding{"CERT_NOT_YET_VALID", "Leaf certificate is not yet valid", "The leaf certificate's validity period has not started at the selected analysis time.", "certificate-validity", "leaf certificate is not yet valid at the selected analysis time"}
	}
	if status == ValidityExpired {
		return Finding{"CERT_INTERMEDIATE_EXPIRED", "Presented intermediate certificate expired", "A presented non-leaf certificate is outside its validity period at the selected analysis time.", "certificate-validity", fmt.Sprintf("presented certificate %d is expired at the selected analysis time", index+1)}
	}
	return Finding{"CERT_INTERMEDIATE_NOT_YET_VALID", "Presented intermediate certificate is not yet valid", "A presented non-leaf certificate's validity period has not started at the selected analysis time.", "certificate-validity", fmt.Sprintf("presented certificate %d is not yet valid at the selected analysis time", index+1)}
}

// verifyPathTrust verifies the signed path, constraints, server-auth usage,
// and root membership while ignoring dates on presented peer certificates.
// It does not include hostname matching; the root certificates remain subject
// to their normal validity checks at now.
func verifyPathTrust(leaf *x509.Certificate, presentedIntermediates []*x509.Certificate, roots *x509.CertPool, now time.Time) (bool, VerificationStatus, error) {
	if err := validatePresentedIntermediates(presentedIntermediates); err != nil {
		return false, VerificationFailed, err
	}
	leafCopy, intermediates := copyPeerCertificatesWithExpandedValidity(leaf, presentedIntermediates)
	return verifyChain(leafCopy, intermediates, roots, now)
}

// verifyFullChainAtTime verifies the original peer certificates and selected
// roots at now. Hostname matching is deliberately performed separately.
func verifyFullChainAtTime(leaf *x509.Certificate, presentedIntermediates []*x509.Certificate, roots *x509.CertPool, now time.Time) (bool, VerificationStatus, error) {
	if err := validatePresentedIntermediates(presentedIntermediates); err != nil {
		return false, VerificationFailed, err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range presentedIntermediates {
		intermediates.AddCert(cert)
	}
	return verifyChain(leaf, intermediates, roots, now)
}

func validatePresentedIntermediates(certificates []*x509.Certificate) error {
	for _, cert := range certificates {
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return x509.CertificateInvalidError{Cert: cert, Reason: x509.NotAuthorizedToSign}
		}
	}
	return nil
}

func copyPeerCertificatesWithExpandedValidity(leaf *x509.Certificate, presentedIntermediates []*x509.Certificate) (*x509.Certificate, *x509.CertPool) {
	const earliestYear = 1
	const latestYear = 9999
	intermediates := x509.NewCertPool()
	for _, cert := range presentedIntermediates {
		copy := *cert
		copy.NotBefore = time.Date(earliestYear, time.January, 1, 0, 0, 0, 0, time.UTC)
		copy.NotAfter = time.Date(latestYear, time.December, 31, 23, 59, 59, 0, time.UTC)
		intermediates.AddCert(&copy)
	}
	leafCopy := *leaf
	leafCopy.NotBefore = time.Date(earliestYear, time.January, 1, 0, 0, 0, 0, time.UTC)
	leafCopy.NotAfter = time.Date(latestYear, time.December, 31, 23, 59, 59, 0, time.UTC)
	return &leafCopy, intermediates
}

func verifyChain(leaf *x509.Certificate, intermediates, roots *x509.CertPool, now time.Time) (bool, VerificationStatus, error) {
	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, err := leaf.Verify(options)
	if err == nil {
		return true, VerificationVerified, nil
	}
	return false, VerificationFailed, err
}

func trustFinding(err error) Finding {
	var unknownAuthority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return Finding{
			Code:        "CERT_CHAIN_INVALID",
			Title:       "Certificate chain is invalid",
			Description: "The certificate path failed standard x509 validation for server authentication.",
			Category:    "certificate-trust",
			Evidence:    fmt.Sprintf("certificate path failed validation (reason %d)", invalid.Reason),
		}
	}
	if errors.As(err, &unknownAuthority) {
		return Finding{
			Code:        "CERT_UNTRUSTED",
			Title:       "Certificate chain is not trusted",
			Description: "The presented certificate chain does not terminate at a root in the configured trust pool.",
			Category:    "certificate-trust",
			Evidence:    "no configured trust anchor was found for the presented chain",
		}
	}
	return Finding{
		Code:        "CERT_CHAIN_INVALID",
		Title:       "Certificate chain is invalid",
		Description: "The certificate path failed standard x509 validation for server authentication.",
		Category:    "certificate-trust",
		Evidence:    fmt.Sprintf("certificate path verification failed (%T)", err),
	}
}

func deduplicateAndSort(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Code + "\x00" + finding.Evidence
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Code == result[j].Code {
			return result[i].Evidence < result[j].Evidence
		}
		return result[i].Code < result[j].Code
	})
	return result
}
