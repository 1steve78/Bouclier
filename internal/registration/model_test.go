package registration

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRegistrationInfoNormalizeAndValidate(t *testing.T) {
	created := time.Date(2024, 3, 1, 12, 30, 0, 0, time.FixedZone("offset", 5*60*60))
	updated := time.Date(2024, 3, 2, 12, 30, 0, 0, time.FixedZone("offset", -4*60*60))
	retrieved := time.Date(2024, 3, 3, 12, 0, 0, 0, time.FixedZone("offset", 2*60*60))
	info := &RegistrationInfo{
		Domain:      " WWW.BÜCHER.CO.UK. ",
		Registrar:   " Example Registrar ",
		CreatedAt:   &created,
		UpdatedAt:   &updated,
		Status:      []string{" ACTIVE ", "active", " clientTransferProhibited "},
		NameServers: []string{" NS2.Example.COM. ", "ns1.example.com", "ns1.example.com"},
		DataSource:  " mock-rdap ",
		RetrievedAt: retrieved,
	}
	if err := info.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if info.Domain != "xn--bcher-kva.co.uk" {
		t.Errorf("Domain = %q", info.Domain)
	}
	if info.CreatedAt.Location() != time.UTC || info.UpdatedAt.Location() != time.UTC || info.RetrievedAt.Location() != time.UTC {
		t.Error("timestamps were not normalized to UTC")
	}
	if !reflect.DeepEqual(info.Status, []string{"active", "clienttransferprohibited"}) {
		t.Errorf("Status = %#v", info.Status)
	}
	if !reflect.DeepEqual(info.NameServers, []string{"ns1.example.com", "ns2.example.com"}) {
		t.Errorf("NameServers = %#v", info.NameServers)
	}
	if info.Registrar != "Example Registrar" || info.DataSource != "mock-rdap" {
		t.Errorf("strings were not trimmed: %+v", info)
	}
}

func TestRegistrationInfoOptionalAndRedactedFields(t *testing.T) {
	info := validRegistrationInfo()
	info.CreatedAt = nil
	info.UpdatedAt = nil
	info.ExpiresAt = nil
	info.NameServers = nil
	info.IsRedacted = true
	if err := info.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if info.CreatedAt != nil || info.UpdatedAt != nil || info.ExpiresAt != nil || len(info.NameServers) != 0 || !info.IsRedacted {
		t.Fatalf("optional/redacted values not retained correctly: %+v", info)
	}
}

func TestRegistrationInfoZeroDatesBecomeUnavailable(t *testing.T) {
	zero := time.Time{}
	info := validRegistrationInfo()
	info.CreatedAt = &zero
	if err := info.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if info.CreatedAt != nil {
		t.Fatalf("zero date should be represented as missing: %v", info.CreatedAt)
	}
}

func TestRegistrationInfoRejectsInvalidValues(t *testing.T) {
	for _, mutate := range []func(*RegistrationInfo){
		func(info *RegistrationInfo) { info.Domain = "bad..example" },
		func(info *RegistrationInfo) { info.Domain = "com" },
		func(info *RegistrationInfo) { info.Domain = "192.0.2.1" },
		func(info *RegistrationInfo) { info.NameServers = []string{"-invalid.example"} },
		func(info *RegistrationInfo) { info.DataSource = " " },
		func(info *RegistrationInfo) { info.RetrievedAt = time.Time{} },
	} {
		info := validRegistrationInfo()
		mutate(info)
		if err := info.NormalizeAndValidate(); err == nil {
			t.Errorf("NormalizeAndValidate(%+v) succeeded; want error", info)
		}
	}
	if err := (*RegistrationInfo)(nil).NormalizeAndValidate(); !errors.Is(err, ErrInvalidProviderResponse) {
		t.Errorf("nil validation error = %v", err)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for input, want := range map[string]string{
		"Example.COM.":          "example.com",
		"www.example.co.uk":     "example.co.uk",
		"bücher.example":        "xn--bcher-kva.example",
		"XN--BCHER-KVA.EXAMPLE": "xn--bcher-kva.example",
	} {
		got, err := NormalizeDomain(input)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestRegistrationModelHasNoRegistrantContactFields(t *testing.T) {
	forbidden := []string{"Email", "Phone", "Address", "Registrant", "Contact"}
	typeOf := reflect.TypeOf(RegistrationInfo{})
	for i := 0; i < typeOf.NumField(); i++ {
		name := typeOf.Field(i).Name
		for _, prohibited := range forbidden {
			if strings.Contains(strings.ToLower(name), strings.ToLower(prohibited)) {
				t.Fatalf("registration model includes personal-data field %q", name)
			}
		}
	}
}

func validRegistrationInfo() *RegistrationInfo {
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return &RegistrationInfo{
		Domain: "example.com", Registrar: "Example Registrar", CreatedAt: &created,
		Status: []string{"active"}, NameServers: []string{"ns1.example.com"},
		DataSource: "test-provider", RetrievedAt: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
	}
}
