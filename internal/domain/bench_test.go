package domain

import (
	"testing"

	"bouclier/internal/heuristics"
)

func BenchmarkAnalyzeDomain(b *testing.B) {
	norm, err := heuristics.NormalizeURL("https://secure.paypal.account-verify.login.example.com/")
	if err != nil {
		b.Fatal(err)
	}
	info, err := heuristics.ExtractDomainInfo(norm)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := AnalyzeDomain(info)
		if err != nil {
			b.Fatal(err)
		}
	}
}
