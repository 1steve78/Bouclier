package heuristics

import (
	"testing"
)

func BenchmarkNormalizeURL_Simple(b *testing.B) {
	raw := "https://example.com/login"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NormalizeURL(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizeURL_Complex(b *testing.B) {
	raw := "https://user@sub.sub2.banking-portal.example.co.uk:443/auth/v2/login.php?session=xyz123&redirect=https%3A%2F%2Fother.com#section-1"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NormalizeURL(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizeURL_IDNA(b *testing.B) {
	raw := "https://xn--e1afmkfd.xn--p1ai/path"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NormalizeURL(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeURL(b *testing.B) {
	raw := "https://secure-login.paypal.com.verify-account.suspicious-domain.xyz/auth/login"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := AnalyzeURL(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}
