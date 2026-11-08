package intel

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzNormalizeIndicator(f *testing.F) {
	seeds := []string{
		"example.com",
		"sub.domain.co.uk",
		"https://example.com/login?u=1",
		"192.0.2.1",
		"2001:db8::1",
		"xn--e1afmkfd.xn--p1ai",
		"http://evil.com",
		"::1",
		"127.0.0.1",
		"",
		" ",
		"\x00\x01\x02",
		"http://user:pass@evil.com/",
	}
	for _, s := range seeds {
		f.Add(s, "domain")
		f.Add(s, "url")
		f.Add(s, "ipv4")
		f.Add(s, "ipv6")
	}

	f.Fuzz(func(t *testing.T, rawVal string, typeStr string) {
		if len(rawVal) > 10240 {
			t.Skip()
		}
		indType := IndicatorType(strings.ToLower(strings.TrimSpace(typeStr)))
		if !ValidIndicatorType(indType) {
			return
		}
		// Must not panic on arbitrary fuzz input
		_, _ = NormalizeIndicator(indType, rawVal)
	})
}

func FuzzParseIndicatorsJSON(f *testing.F) {
	seeds := [][]byte{
		[]byte(`[{"type":"domain","value":"evil.com","category":"phishing","confidence":90}]`),
		[]byte(`{"indicators":[{"type":"url","value":"https://evil.com/login"}]}`),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`[{"type":"ipv4","value":"198.51.100.1"}]`),
		[]byte(`{"invalid": true}`),
		[]byte(`malformed json content`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	cfg := SourceConfig{ID: "fuzz-feed", Name: "Fuzz Feed"}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		// Must not panic
		_, _, _ = ParseIndicators(bytes.NewReader(data), "json", cfg)
	})
}

func FuzzParseIndicatorsCSV(f *testing.F) {
	seeds := [][]byte{
		[]byte("type,value,category,confidence,severity\ndomain,evil.com,phishing,90,high\n"),
		[]byte("indicator,type\nhttps://evil.com/,url\n"),
		[]byte(""),
		[]byte("not a csv"),
		[]byte("type,value\nipv4,198.51.100.22\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	cfg := SourceConfig{ID: "fuzz-csv", Name: "Fuzz CSV"}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		// Must not panic
		_, _, _ = ParseIndicators(bytes.NewReader(data), "csv", cfg)
	})
}

func FuzzReadBundle(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"manifest":{"schema_version":"bouclier-intel-bundle/v1","checksum_sha256":"abc"},"indicators":[]}`),
		[]byte(`{}`),
		[]byte(`not json`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		// Must not panic
		_, _ = ReadBundle(bytes.NewReader(data))
	})
}
