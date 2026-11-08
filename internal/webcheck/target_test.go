package webcheck

import (
	"errors"
	"testing"

	"bouclier/internal/heuristics"
)

func TestValidateTargetStaticAddressPolicy(t *testing.T) {
	tests := []struct {
		target  string
		blocked bool
	}{
		{"https://example.com", false},
		{"http://127.0.0.1", true},
		{"http://10.0.0.1", true},
		{"http://169.254.1.1", true},
		{"http://[::1]", true},
		{"http://[::ffff:127.0.0.1]", true},
		{"http://[::8.8.8.8]", true},
		{"http://[fd00::1]", true},
		{"http://localhost", true},
		{"http://service.internal", true},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			normalized, err := heuristics.NormalizeURL(tt.target)
			if err != nil {
				if tt.blocked {
					return
				}
				t.Fatalf("NormalizeURL() error = %v", err)
			}
			err = ValidateTarget(normalized)
			if tt.blocked {
				if err == nil {
					t.Fatal("ValidateTarget() accepted a disallowed target")
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateTarget() rejected public target: %v", err)
			}
		})
	}
}

func TestValidateTargetDistinguishesUnsafeDestinations(t *testing.T) {
	normalized, err := heuristics.NormalizeURL("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget(normalized); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("ValidateTarget() error = %v, want ErrUnsafeTarget", err)
	}
}
