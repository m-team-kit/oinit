package oidc

import "testing"

func TestRequireHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https ok", "https://op.example.com", false},
		{"https with path ok", "https://op.example.com/userinfo", false},
		{"plaintext http rejected", "http://op.example.com", true},
		{"other scheme rejected", "ftp://op.example.com", true},
		{"schemeless rejected", "op.example.com/userinfo", true},
		{"empty rejected", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireHTTPS(tt.url)
			if tt.wantErr && err == nil {
				t.Fatalf("requireHTTPS(%q) = nil, want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("requireHTTPS(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}
