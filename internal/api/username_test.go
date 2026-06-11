package api

import "testing"

func TestIsValidUsername(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "alice", true},
		{"with digits", "alice42", true},
		{"underscore start", "_svc", true},
		{"dash and underscore", "a-b_c", true},
		{"max length 32", "abcdefghijklmnopqrstuvwxyz012345", true},
		{"empty", "", false},
		{"uppercase", "Alice", false},
		{"samba trailing dollar", "machine$", false},
		{"digit start", "1alice", false},
		{"dash start", "-alice", false},
		{"space inside", "alice bob", false},
		{"leading space", " alice", false},
		{"trailing space", "alice ", false},
		{"tab", "alice\tbob", false},
		{"newline", "alice\nroot", false},
		{"semicolon", "alice;reboot", false},
		{"slash", "al/ice", false},
		{"dollar inside", "ali$ce", false},
		{"too long 33", "abcdefghijklmnopqrstuvwxyz0123456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidUsername(tt.input); got != tt.valid {
				t.Errorf("isValidUsername(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}
