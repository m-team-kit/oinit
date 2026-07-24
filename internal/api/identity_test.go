package api

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestTokenHasAudience(t *testing.T) {
	tests := []struct {
		name   string
		aud    interface{}
		want   string
		expect bool
	}{
		{"single string match", "https://ca.example.com", "https://ca.example.com", true},
		{"single string mismatch", "https://other", "https://ca.example.com", false},
		{"array contains", []interface{}{"a", "https://ca.example.com"}, "https://ca.example.com", true},
		{"array missing", []interface{}{"a", "b"}, "https://ca.example.com", false},
		{"absent claim", nil, "https://ca.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tt.aud != nil {
				claims["aud"] = tt.aud
			}
			if got := tokenHasAudience(claims, tt.want); got != tt.expect {
				t.Errorf("tokenHasAudience(%v, %q) = %v, want %v", tt.aud, tt.want, got, tt.expect)
			}
		})
	}
}

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
