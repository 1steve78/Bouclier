package certanalysis

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"bouclier/internal/tlscheck"
)

func FuzzCertificateSANProcessing(f *testing.F) {
	seeds := []string{
		"example.com",
		"*.example.com",
		"sub.sub2.example.co.uk",
		"192.0.2.1",
		"::1",
		"xn--e1afmkfd.xn--p1ai",
		"",
		"invalid\x00san",
		"very.long.domain.name.that.might.exceed.label.lengths.or.domain.lengths.example.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, san string) {
		if len(san) > 512 {
			t.Skip()
		}

		// Synthetic certificate with fuzzed SANs
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "test.example.com",
			},
			DNSNames:    []string{san, "valid.example.com"},
			IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
			NotBefore:   time.Now().Add(-24 * time.Hour),
			NotAfter:    time.Now().Add(24 * time.Hour),
		}

		connResult := &tlscheck.TLSConnectionResult{
			TargetHostname:   "test.example.com",
			ServerName:       "test.example.com",
			Address:          "192.0.2.1:443",
			NegotiatedTLS:    "TLS 1.3",
			PeerCertificates: []*x509.Certificate{cert},
			HandshakeSuccess: true,
		}

		// Must not panic on arbitrary SAN data
		_, _ = AnalyzeCertificates(connResult, Config{
			CurrentTime: time.Now().UTC(),
		})
	})
}
