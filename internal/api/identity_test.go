package api

import (
	"strings"
	"testing"
)

func TestSanitizeIdentity(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain issuer unchanged", "https://op.example.com", "https://op.example.com"},
		{"newline stripped", "alice\nFAKE LOG LINE", "aliceFAKE LOG LINE"},
		{"carriage return stripped", "a\rb", "ab"},
		{"tab and control stripped", "a\tb\x00c", "abc"},
		{"del stripped", "a\x7fb", "ab"},
		{"empty stays empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeIdentity(tt.in); got != tt.want {
				t.Errorf("sanitizeIdentity(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("length capped at 256", func(t *testing.T) {
		got := sanitizeIdentity(strings.Repeat("a", 300))
		if len(got) != 256 {
			t.Errorf("len = %d, want 256", len(got))
		}
	})
}
