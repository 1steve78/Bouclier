package heuristics

import (
	"strings"
	"testing"
)

func TestClassifyURL(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		port    string
		want    Classification
		wantErr bool
	}{
		{name: "IPv4 loopback", host: "127.0.0.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsLoopback: true, IsLiteralIP: true}},
		{name: "IPv4 private 10", host: "10.0.0.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsPrivateIP: true, IsLiteralIP: true}},
		{name: "IPv4 private 172", host: "172.16.0.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsPrivateIP: true, IsLiteralIP: true}},
		{name: "IPv4 private 192", host: "192.168.1.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsPrivateIP: true, IsLiteralIP: true}},
		{name: "IPv4 link local", host: "169.254.1.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsLinkLocal: true, IsLiteralIP: true}},
		{name: "IPv4 multicast", host: "224.0.0.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsLinkLocal: true, IsMulticast: true, IsLiteralIP: true}},
		{name: "IPv4 unspecified", host: "0.0.0.0", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsUnspecified: true, IsLiteralIP: true}},
		{name: "IPv4 public example", host: "8.8.8.8", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsPublicIP: true, IsLiteralIP: true}},
		{name: "IPv4 public example two", host: "1.1.1.1", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsPublicIP: true, IsLiteralIP: true}},
		{name: "IPv6 loopback", host: "::1", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsLoopback: true, IsLiteralIP: true}},
		{name: "IPv6 unspecified", host: "::", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsUnspecified: true, IsLiteralIP: true}},
		{name: "IPv6 link local", host: "fe80::1", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsLinkLocal: true, IsLiteralIP: true}},
		{name: "IPv6 unique local", host: "fc00::1", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsPrivateIP: true, IsLiteralIP: true}},
		{name: "IPv6 multicast", host: "ff02::1", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsLinkLocal: true, IsMulticast: true, IsLiteralIP: true}},
		{name: "IPv6 public example", host: "2001:4860:4860::8888", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsPublicIP: true, IsLiteralIP: true}},
		{name: "IPv6 documentation", host: "2001:db8::1", want: Classification{HostType: HostTypeIPv6, IsIPAddress: true, IsLiteralIP: true}},
		{name: "DNS", host: "example.com", want: Classification{HostType: HostTypeDNS}},
		{name: "localhost", host: "localhost", want: Classification{HostType: HostTypeLocal, IsLocalDomain: true}},
		{name: "localhost subdomain", host: "sub.localhost", want: Classification{HostType: HostTypeLocal, IsLocalDomain: true}},
		{name: "local suffix", host: "printer.local", want: Classification{HostType: HostTypeLocal, IsLocalDomain: true}},
		{name: "internal suffix", host: "service.internal", want: Classification{HostType: HostTypeLocal, IsLocalDomain: true}},
		{name: "mixed case DNS", host: "ExAmPlE.CoM", want: Classification{HostType: HostTypeDNS}},
		{name: "DNS trailing dot", host: "example.com.", want: Classification{HostType: HostTypeDNS}},
		{name: "IP with port", host: "8.8.8.8", port: "443", want: Classification{HostType: HostTypeIPv4, IsIPAddress: true, IsPublicIP: true, IsLiteralIP: true}},
		{name: "empty hostname", wantErr: true},
		{name: "malformed IP flag", host: "not-an-ip", wantErr: true},
		{name: "malformed dotted numeric IP", host: "192.168.1.999", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &NormalizedURL{Hostname: tt.host, Port: tt.port, IsIPAddress: tt.name == "malformed IP flag"}
			got, err := ClassifyURL(u)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ClassifyURL() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyURL() error = %v", err)
			}
			if *got != tt.want {
				t.Fatalf("ClassifyURL() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestClassifyURLFromNormalized(t *testing.T) {
	for _, input := range []string{"http://[2001:4860:4860::8888]:8080/", "https://8.8.8.8:8443/"} {
		u, err := NormalizeURL(input)
		if err != nil {
			t.Fatalf("NormalizeURL(%q): %v", input, err)
		}
		got, err := ClassifyURL(u)
		if err != nil {
			t.Fatalf("ClassifyURL(%q): %v", input, err)
		}
		if got.HostType != HostTypeIPv4 && got.HostType != HostTypeIPv6 {
			t.Errorf("HostType = %q for %s", got.HostType, input)
		}
	}
}

func TestClassifyURLErrors(t *testing.T) {
	if _, err := ClassifyURL(nil); err == nil {
		t.Fatal("ClassifyURL(nil) error = nil, want error")
	}
	if _, err := ClassifyURL(&NormalizedURL{}); err == nil || !strings.Contains(err.Error(), "hostname is empty") {
		t.Fatalf("ClassifyURL(empty) error = %v", err)
	}
}

func FuzzClassifyURL(f *testing.F) {
	for _, seed := range []string{"127.0.0.1", "::1", "2001:db8::1", "example.com", "localhost", "192.168.1.999", "", "bad:host"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, hostname string) {
		_, _ = ClassifyURL(&NormalizedURL{Hostname: hostname})
	})
}
