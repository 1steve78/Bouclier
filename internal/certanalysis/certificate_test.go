package certanalysis

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"

	"bouclier/internal/tlscheck"
)

func TestAnalyzeCertificatesValidityAndMetadata(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		leafBefore    time.Time
		leafAfter     time.Time
		interBefore   time.Time
		interAfter    time.Time
		wantStatus    ValidityStatus
		wantValid     bool
		wantLeafCode  string
		wantInterCode string
	}{
		{name: "valid", leafBefore: now.Add(-time.Hour), leafAfter: now.Add(time.Hour), interBefore: testStart(), interAfter: testEnd(), wantStatus: ValidityCurrent, wantValid: true},
		{name: "expired leaf", leafBefore: now.Add(-48 * time.Hour), leafAfter: now.Add(-24 * time.Hour), interBefore: testStart(), interAfter: testEnd(), wantStatus: ValidityExpired, wantLeafCode: "CERT_EXPIRED"},
		{name: "not-yet-valid leaf", leafBefore: now.Add(time.Hour), leafAfter: now.Add(48 * time.Hour), interBefore: testStart(), interAfter: testEnd(), wantStatus: ValidityNotYetValid, wantLeafCode: "CERT_NOT_YET_VALID"},
		{name: "expired intermediate", leafBefore: now.Add(-time.Hour), leafAfter: now.Add(time.Hour), interBefore: testStart(), interAfter: now.Add(-time.Minute), wantStatus: ValidityCurrent, wantValid: true, wantInterCode: "CERT_INTERMEDIATE_EXPIRED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pki := newTestPKI(t, tt.interBefore, tt.interAfter)
			leaf := newLeaf(t, pki, leafTemplate(tt.leafBefore, tt.leafAfter, "target.example", []string{"target.example"}, nil))
			analysis, err := AnalyzeCertificates(tlsResult("destination.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
			if err != nil {
				t.Fatal(err)
			}
			if analysis.ValidAtTime != tt.wantValid || analysis.Certificates[0].ValidityStatus != tt.wantStatus {
				t.Fatalf("leaf validity = %v/%s", analysis.ValidAtTime, analysis.Certificates[0].ValidityStatus)
			}
			if len(analysis.Certificates) != 2 || analysis.Certificates[1].ValidityStatus == "" {
				t.Fatalf("presented intermediate metadata missing: %+v", analysis.Certificates)
			}
			if tt.wantInterCode != "" && !hasCode(analysis.Findings, tt.wantInterCode) {
				t.Fatalf("intermediate finding %s missing: %+v", tt.wantInterCode, analysis.Findings)
			}
			if tt.wantLeafCode != "" && !hasCode(analysis.Findings, tt.wantLeafCode) {
				t.Fatalf("leaf finding %s missing: %+v", tt.wantLeafCode, analysis.Findings)
			}
			if tt.name == "valid" {
				info := analysis.Certificates[0]
				if info.SubjectCommonName != "target.example" || info.IssuerCommonName != "Bouclier test intermediate" || !slices.Equal(info.DNSNames, []string{"target.example"}) || info.IsSelfSigned || info.IsCA || info.SignatureAlgorithm == 0 || info.PublicKeyAlgorithm != x509.ECDSA {
					t.Fatalf("unexpected leaf metadata: %+v", info)
				}
				if !analysis.PathTrusted || !analysis.ChainTrusted || !analysis.ChainValidAtTime || analysis.PathTrustStatus != VerificationVerified || analysis.ChainValidityStatus != VerificationVerified || !analysis.HostnameMatch {
					t.Fatalf("valid test chain should be trusted and match: %+v", analysis)
				}
			}
		})
	}
}

func TestAnalyzeCertificatesHostnameVerification(t *testing.T) {
	now := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		commonName string
		dnsNames   []string
		ips        []net.IP
		serverName string
		wantMatch  bool
	}{
		{name: "DNS SAN match", commonName: "unused.example", dnsNames: []string{"service.example"}, serverName: "service.example", wantMatch: true},
		{name: "DNS mismatch", commonName: "unused.example", dnsNames: []string{"service.example"}, serverName: "other.example"},
		{name: "wildcard match", dnsNames: []string{"*.example.com"}, serverName: "www.example.com", wantMatch: true},
		{name: "wildcard does not span labels", dnsNames: []string{"*.example.com"}, serverName: "a.b.example.com"},
		{name: "IP SAN match", ips: []net.IP{net.ParseIP("192.0.2.10")}, serverName: "192.0.2.10", wantMatch: true},
		{name: "IP SAN mismatch", ips: []net.IP{net.ParseIP("192.0.2.10")}, serverName: "192.0.2.11"},
		{name: "CN is not a SAN fallback", commonName: "service.example", serverName: "service.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pki := newTestPKI(t, testStart(), testEnd())
			leaf := newLeaf(t, pki, &x509.Certificate{
				SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: tt.commonName},
				DNSNames: tt.dnsNames, IPAddresses: tt.ips,
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			analysis, err := AnalyzeCertificates(tlsResult("target.example", tt.serverName, true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
			if err != nil {
				t.Fatal(err)
			}
			if analysis.HostnameMatch != tt.wantMatch {
				t.Fatalf("HostnameMatch = %v, want %v; findings=%+v", analysis.HostnameMatch, tt.wantMatch, analysis.Findings)
			}
			if !tt.wantMatch && !hasCode(analysis.Findings, "CERT_HOSTNAME_MISMATCH") {
				t.Fatalf("hostname mismatch finding missing: %+v", analysis.Findings)
			}
		})
	}
}

func TestAnalyzeCertificatesTrustAnalysis(t *testing.T) {
	now := time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC)
	t.Run("trusted root", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || !analysis.PathTrusted || !analysis.ChainValidAtTime || analysis.PathTrustStatus != VerificationVerified || analysis.ChainValidityStatus != VerificationVerified {
			t.Fatalf("trusted chain analysis=%+v err=%v", analysis, err)
		}
	})
	t.Run("self-signed and untrusted", func(t *testing.T) {
		leaf := newSelfSignedLeaf(t, now, "target.example", []string{"target.example"})
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", false, leaf), Config{CurrentTime: now, Roots: x509.NewCertPool()})
		if err != nil || analysis.ChainTrusted || analysis.PathTrustStatus != VerificationFailed || analysis.ChainValidityStatus != VerificationFailed || !analysis.Certificates[0].IsSelfSigned || !hasCode(analysis.Findings, "CERT_SELF_SIGNED") || !hasCode(analysis.Findings, "CERT_UNTRUSTED") {
			t.Fatalf("self-signed result=%+v err=%v", analysis, err)
		}
	})
	t.Run("unknown root", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: x509.NewCertPool()})
		if err != nil || analysis.PathTrustStatus != VerificationFailed || analysis.ChainValidityStatus != VerificationFailed || analysis.ChainTrusted || !hasCode(analysis.Findings, "CERT_UNTRUSTED") {
			t.Fatalf("unknown root result=%+v err=%v", analysis, err)
		}
	})
	t.Run("missing intermediate", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || analysis.PathTrustStatus != VerificationFailed || analysis.ChainValidityStatus != VerificationFailed || analysis.ChainTrusted || !hasCode(analysis.Findings, "CERT_UNTRUSTED") {
			t.Fatalf("missing intermediate result=%+v err=%v", analysis, err)
		}
	})
	t.Run("invalid intermediate CA constraints", func(t *testing.T) {
		pki := newTestPKIWithIntermediateCA(t, testStart(), testEnd(), false)
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || analysis.PathTrustStatus != VerificationFailed || analysis.ChainValidityStatus != VerificationFailed || analysis.ChainTrusted || !hasCode(analysis.Findings, "CERT_CHAIN_INVALID") || hasCode(analysis.Findings, "CERT_UNTRUSTED") {
			t.Fatalf("invalid chain result=%+v err=%v", analysis, err)
		}
	})
	t.Run("expired but otherwise trusted", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", false, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || !analysis.PathTrusted || analysis.ChainTrusted != analysis.PathTrusted || analysis.ChainValidAtTime || analysis.PathTrustStatus != VerificationVerified || analysis.ChainValidityStatus != VerificationFailed || analysis.ValidAtTime || !hasCode(analysis.Findings, "CERT_EXPIRED") {
			t.Fatalf("expired-but-trusted result=%+v err=%v", analysis, err)
		}
	})
	t.Run("expired intermediate separates path trust and full validity", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), now.Add(-time.Minute))
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", false, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || !analysis.PathTrusted || analysis.PathTrustStatus != VerificationVerified || analysis.ChainValidAtTime || analysis.ChainValidityStatus != VerificationFailed || !hasCode(analysis.Findings, "CERT_INTERMEDIATE_EXPIRED") {
			t.Fatalf("expired intermediate result=%+v err=%v", analysis, err)
		}
	})
	t.Run("wrong EKU", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		template := leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		leaf := newLeaf(t, pki, template)
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || analysis.ChainValidAtTime || analysis.ChainValidityStatus != VerificationFailed || !hasCode(analysis.Findings, "CERT_CHAIN_INVALID") {
			t.Fatalf("wrong EKU result=%+v err=%v", analysis, err)
		}
	})
	t.Run("empty roots are available but establish no trust", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: x509.NewCertPool()})
		if err != nil || analysis.PathTrustStatus != VerificationFailed || analysis.ChainValidityStatus != VerificationFailed || !hasCode(analysis.Findings, "CERT_UNTRUSTED") {
			t.Fatalf("empty roots result=%+v err=%v", analysis, err)
		}
	})
	t.Run("system roots unavailable", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "target.example", []string{"target.example"}, nil))
		analysis, err := analyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now}, func() (*x509.CertPool, error) { return nil, errors.New("test provider unavailable") })
		if err != nil || analysis.PathTrustStatus != VerificationUnavailable || analysis.ChainValidityStatus != VerificationUnavailable || analysis.PathTrusted || analysis.ChainValidAtTime || !hasCode(analysis.Findings, "CERT_ROOTS_UNAVAILABLE") {
			t.Fatalf("unavailable roots result=%+v err=%v", analysis, err)
		}
	})
	t.Run("hostname mismatch is independent", func(t *testing.T) {
		pki := newTestPKI(t, testStart(), testEnd())
		leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "wrong.example", []string{"wrong.example"}, nil))
		analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil || !analysis.PathTrusted || !analysis.ChainValidAtTime || analysis.HostnameMatch || !hasCode(analysis.Findings, "CERT_HOSTNAME_MISMATCH") {
			t.Fatalf("hostname mismatch result=%+v err=%v", analysis, err)
		}
	})
}

func TestAnalyzeCertificatesTask31ResultsAndOverrides(t *testing.T) {
	now := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, testStart(), testEnd())
	leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "tls-name.example", []string{"tls-name.example"}, nil))
	for _, handshakeSuccess := range []bool{true, false} {
		result := tlsResult("target.example", "tls-name.example", handshakeSuccess, leaf, pki.Intermediate)
		analysis, err := AnalyzeCertificates(result, Config{CurrentTime: now, Roots: pki.Roots})
		if err != nil {
			t.Fatal(err)
		}
		if analysis.TargetHostname != "target.example" || analysis.ServerName != "tls-name.example" || analysis.TLSHandshakeSuccess != handshakeSuccess || !analysis.HostnameMatch || !analysis.ChainTrusted {
			t.Fatalf("analysis lost identity/handshake fields: %+v", analysis)
		}
	}
	if _, err := AnalyzeCertificates(nil, Config{}); err == nil {
		t.Fatal("nil TLS result must fail")
	}
	if _, err := AnalyzeCertificates(&tlscheck.TLSConnectionResult{}, Config{}); err == nil {
		t.Fatal("missing peer certificates must fail")
	}
}

func TestAnalyzeCertificatesDeterminismAndRootPoolImmutability(t *testing.T) {
	now := time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, testStart(), testEnd())
	leaf := newLeaf(t, pki, leafTemplate(now.Add(-48*time.Hour), now.Add(-24*time.Hour), "wrong.example", []string{"wrong.example"}, nil))
	result := tlsResult("target.example", "target.example", false, leaf, pki.Intermediate)
	before := cloneSubjects(pki.Roots.Subjects())
	first, err := AnalyzeCertificates(result, Config{CurrentTime: now, Roots: pki.Roots})
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeCertificates(result, Config{CurrentTime: now, Roots: pki.Roots})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated analysis differs: %+v vs %+v", first, second)
	}
	if !reflect.DeepEqual(before, pki.Roots.Subjects()) {
		t.Fatal("analysis mutated caller-provided root pool")
	}
	for i := 1; i < len(first.Findings); i++ {
		if first.Findings[i-1].Code > first.Findings[i].Code || first.Findings[i-1].Code == first.Findings[i].Code && first.Findings[i-1].Evidence > first.Findings[i].Evidence {
			t.Fatalf("findings are not ordered: %+v", first.Findings)
		}
	}
}

func TestAnalyzeCertificatesDoesNotInferSelfSignedFromNames(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, testStart(), testEnd())
	leaf := newLeaf(t, pki, leafTemplate(now.Add(-time.Hour), now.Add(time.Hour), "Bouclier test intermediate", []string{"target.example"}, nil))
	analysis, err := AnalyzeCertificates(tlsResult("target.example", "target.example", true, leaf, pki.Intermediate), Config{CurrentTime: now, Roots: pki.Roots})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Certificates[0].SubjectCommonName != analysis.Certificates[0].IssuerCommonName || analysis.Certificates[0].IsSelfSigned {
		t.Fatalf("self-signed status inferred from names rather than signature: %+v", analysis.Certificates[0])
	}
}

type testPKI struct {
	Root         *x509.Certificate
	RootKey      *ecdsa.PrivateKey
	Intermediate *x509.Certificate
	InterKey     *ecdsa.PrivateKey
	Roots        *x509.CertPool
}

func newTestPKI(t *testing.T, intermediateNotBefore, intermediateNotAfter time.Time) *testPKI {
	return newTestPKIWithIntermediateCA(t, intermediateNotBefore, intermediateNotAfter, true)
}

func newTestPKIWithIntermediateCA(t *testing.T, intermediateNotBefore, intermediateNotAfter time.Time, isCA bool) *testPKI {
	t.Helper()
	rootKey := newTestKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Bouclier test root"},
		NotBefore: testStart(), NotAfter: testEnd(), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	interKey := newTestKey(t)
	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "Bouclier test intermediate"},
		NotBefore: intermediateNotBefore, NotAfter: intermediateNotAfter,
		IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &testPKI{Root: root, RootKey: rootKey, Intermediate: intermediate, InterKey: interKey, Roots: roots}
}

func newLeaf(t *testing.T, pki *testPKI, template *x509.Certificate) *x509.Certificate {
	t.Helper()
	key := newTestKey(t)
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(200)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.Intermediate, &key.PublicKey, pki.InterKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newSelfSignedLeaf(t *testing.T, now time.Time, commonName string, dnsNames []string) *x509.Certificate {
	t.Helper()
	key := newTestKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(300), Subject: pkix.Name{CommonName: commonName},
		DNSNames: dnsNames, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func leafTemplate(notBefore, notAfter time.Time, commonName string, dnsNames []string, ips []net.IP) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: commonName},
		DNSNames: dnsNames, IPAddresses: ips, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func tlsResult(target, serverName string, success bool, certificates ...*x509.Certificate) *tlscheck.TLSConnectionResult {
	return &tlscheck.TLSConnectionResult{
		TargetHostname: target, ServerName: serverName,
		PeerCertificates: certificates, HandshakeSuccess: success,
	}
}

func testStart() time.Time { return time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC) }
func testEnd() time.Time   { return time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC) }

func hasCode(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func cloneSubjects(subjects [][]byte) [][]byte {
	clones := make([][]byte, len(subjects))
	for i, subject := range subjects {
		clones[i] = append([]byte(nil), subject...)
	}
	return clones
}
