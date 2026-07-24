package api

import (
	"testing"

	"github.com/lbrocke/oinit/internal/config"
)

func TestIsUsernameAllowed(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		allowRoot bool
		allowList []string
		blockList []string
		wantOK    bool
	}{
		{"regular user, no lists", "alice", false, nil, nil, true},
		{"oinit service account always denied", "oinit", true, []string{"oinit"}, nil, false},
		{"root denied without allow-root", "root", false, nil, nil, false},
		{"root allowed with allow-root", "root", true, nil, nil, true},
		{"user in allowlist accepted", "alice", false, []string{"alice", "bob"}, nil, true},
		{"user not in allowlist refused", "carol", false, []string{"alice", "bob"}, nil, false},
		{"allowlist does not gate root (allow-root does)", "root", true, []string{"alice"}, nil, true},
		{"blocked user refused", "mallory", false, nil, []string{"mallory"}, false},
		{"block-users wins over allow-users", "alice", false, []string{"alice"}, []string{"alice"}, false},
		{"block-users wins over allow-root for root", "root", true, nil, []string{"root"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := config.HostInfo{AllowRoot: tt.allowRoot, AllowUsers: tt.allowList, BlockUsers: tt.blockList}
			ok, reason := isUsernameAllowed(tt.username, info)
			if ok != tt.wantOK {
				t.Fatalf("isUsernameAllowed(%q) = %v (%q), want %v", tt.username, ok, reason, tt.wantOK)
			}
		})
	}
}
