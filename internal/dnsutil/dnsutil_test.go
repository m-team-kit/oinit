package dnsutil

import "testing"

func TestValidateAndSelectCA(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		wantErr bool
		wantCA  string
	}{
		{"https accepted", []string{"https://ca.example.com"}, false, "https://ca.example.com"},
		{"https with port and path", []string{"https://ca.example.com:8443/oinit"}, false, "https://ca.example.com:8443/oinit"},
		{"plaintext http rejected", []string{"http://ca.example.com"}, true, ""},
		{"other scheme rejected", []string{"ftp://ca.example.com"}, true, ""},
		{"no scheme rejected", []string{"ca.example.com"}, true, ""},
		{"empty record rejected", []string{"   "}, true, ""},
		{"first valid https of many", []string{"https://ca.example.com", "https://other.example.com"}, false, "https://ca.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, err := validateAndSelectCA(tt.records, "_oinit-ca.example.com")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %v, got CA %q", tt.records, ca)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %v: %v", tt.records, err)
			}
			if ca != tt.wantCA {
				t.Fatalf("got CA %q, want %q", ca, tt.wantCA)
			}
		})
	}
}
