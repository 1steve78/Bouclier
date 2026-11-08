package heuristics

import (
	"testing"
)

func FuzzDomainNormalization(f *testing.F) {
	seeds := []string{
		"example.com",
		"sub.example.co.uk",
		"xn--e1afmkfd.xn--p1ai",
		"localhost",
		"192.0.2.1",
		"[2001:db8::1]",
		"a.b.c.d.e.f.g.com",
		"",
		" ",
		"-bad-label.com",
		"bad-label-.com",
		"invalid..double.dots.com",
		"trailing.dot.com.",
		"\x00\x01\x02",
		"very.long.domain.name.with.many.many.subdomain.labels.that.could.approach.the.limit.of.rfc1035.standards.example.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, domain string) {
		if len(domain) > 1024 {
			t.Skip()
		}
		// Must not panic
		_, _ = normalizeDNSHostname(domain)
		_, _ = RegistrableDomain(domain)
	})
}

func FuzzIPParsing(f *testing.F) {
	seeds := []string{
		"192.168.1.1",
		"10.0.0.1",
		"127.0.0.1",
		"::1",
		"2001:db8::1",
		"256.256.256.256",
		"0.0.0.0",
		"::",
		"fe80::1%eth0",
		"::ffff:192.0.2.128",
		"192.168.1.1:80",
		"[2001:db8::1]:443",
		"",
		"invalid-ip",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, ipStr string) {
		if len(ipStr) > 512 {
			t.Skip()
		}
		// Must not panic
		_, _, _, _, _ = parseAuthority(ipStr)
	})
}
