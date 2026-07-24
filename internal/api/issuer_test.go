package api

import "testing"

func TestNormalizeIssuer(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://op.example.com", "https://op.example.com"},
		{"https://op.example.com/", "https://op.example.com"},
		{"https://op.example.com//", "https://op.example.com"},
		{"https://op.example.com/auth/realms/x/", "https://op.example.com/auth/realms/x"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeIssuer(tt.in); got != tt.want {
			t.Errorf("normalizeIssuer(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	// The point of the change: an issuer that differs only by a trailing slash
	// must normalise equal to the slashless advertised provider URL.
	if normalizeIssuer("https://aai.egi.eu/auth/realms/egi/") != normalizeIssuer("https://aai.egi.eu/auth/realms/egi") {
		t.Error("trailing-slash issuer did not normalise equal to the slashless form")
	}
}
