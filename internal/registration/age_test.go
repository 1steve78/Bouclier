package registration

import (
	"reflect"
	"testing"
	"time"
)

func TestAnalyzeRegistrationAgeThresholds(t *testing.T) {
	now := time.Date(2025, 4, 30, 12, 0, 0, 0, time.FixedZone("local", -5*60*60))
	tests := []struct {
		name    string
		age     time.Duration
		status  string
		newly   bool
		veryNew bool
	}{
		{name: "very new", age: 6 * 24 * time.Hour, status: AgeStatusVeryNew, newly: true, veryNew: true},
		{name: "exactly seven days", age: 7 * 24 * time.Hour, status: AgeStatusNew, newly: true},
		{name: "newly created", age: 15 * 24 * time.Hour, status: AgeStatusNew, newly: true},
		{name: "exactly thirty days", age: 30 * 24 * time.Hour, status: AgeStatusEstablished},
		{name: "older", age: 90 * 24 * time.Hour, status: AgeStatusEstablished},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created := now.Add(-tt.age).In(time.FixedZone("created", 3*60*60))
			got, err := AnalyzeRegistrationAge(&RegistrationInfo{CreatedAt: &created}, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.status || got.IsNewlyCreated != tt.newly || got.IsVeryNew != tt.veryNew {
				t.Fatalf("analysis = %+v", got)
			}
			if got.Age == nil || *got.Age != tt.age || got.Explanation == "" {
				t.Fatalf("age/explanation not populated: %+v", got)
			}
		})
	}
}

func TestAnalyzeRegistrationAgeMissingAndRedacted(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		info   RegistrationInfo
		status string
	}{
		{name: "missing date", status: AgeStatusUnavailable},
		{name: "redacted date", info: RegistrationInfo{IsRedacted: true}, status: AgeStatusRedacted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AnalyzeRegistrationAge(&tt.info, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.Age != nil || got.Status != tt.status || got.IsNewlyCreated || got.IsVeryNew {
				t.Fatalf("analysis = %+v", got)
			}
		})
	}
}

func TestAnalyzeRegistrationAgeZeroAndFutureDates(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	zero := time.Time{}
	got, err := AnalyzeRegistrationAge(&RegistrationInfo{CreatedAt: &zero}, now)
	if err != nil || got.Status != AgeStatusUnavailable || got.Age != nil {
		t.Fatalf("zero date analysis = %+v, %v", got, err)
	}
	future := now.Add(time.Second)
	if result, err := AnalyzeRegistrationAge(&RegistrationInfo{CreatedAt: &future}, now); err == nil || result != nil {
		t.Fatalf("future date returned (%+v, %v), want error and nil result", result, err)
	}
	if result, err := AnalyzeRegistrationAge(nil, now); err == nil || result != nil {
		t.Fatalf("nil info returned (%+v, %v), want error and nil result", result, err)
	}
}

func TestAnalyzeRegistrationAgeDeterministic(t *testing.T) {
	now := time.Date(2025, 6, 1, 10, 30, 0, 0, time.UTC)
	created := now.Add(-48 * time.Hour)
	info := &RegistrationInfo{CreatedAt: &created}
	first, err := AnalyzeRegistrationAge(info, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeRegistrationAge(info, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("results differ: %+v and %+v", first, second)
	}
}
