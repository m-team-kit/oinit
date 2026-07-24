package main

import "testing"

// TestSelectSessionSocket exercises the security-critical socket-selection
// logic: a forwarded oidc socket is only ever selected when its inode is held
// by this session's own sshd AND the path is owned by the current user. Any
// other case (a concurrent session's socket, an unowned path, no inode match)
// must yield "" so forwarding is disabled rather than a wrong socket chowned.
func TestSelectSessionSocket(t *testing.T) {
	ownedAll := func(string) bool { return true }
	ownedNone := func(string) bool { return false }

	mine := unixSocket{inode: "111", path: "/tmp/oidc-forward-1"}
	theirs := unixSocket{inode: "222", path: "/tmp/oidc-forward-2"}

	tests := []struct {
		name       string
		candidates []unixSocket
		sshdInodes map[string]bool
		owned      func(string) bool
		want       string
	}{
		{
			name:       "own session socket selected",
			candidates: []unixSocket{mine, theirs},
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedAll,
			want:       "/tmp/oidc-forward-1",
		},
		{
			name:       "concurrent session socket never selected",
			candidates: []unixSocket{theirs},
			sshdInodes: map[string]bool{"111": true}, // our sshd does not hold 222
			owned:      ownedAll,
			want:       "",
		},
		{
			name:       "lone candidate not held by our sshd is rejected",
			candidates: []unixSocket{theirs},
			sshdInodes: map[string]bool{}, // no inode match at all
			owned:      ownedAll,
			want:       "",
		},
		{
			name:       "inode match but not owned is rejected",
			candidates: []unixSocket{mine},
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedNone,
			want:       "",
		},
		{
			name:       "no candidates",
			candidates: nil,
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedAll,
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectSessionSocket(tt.candidates, tt.sshdInodes, tt.owned); got != tt.want {
				t.Fatalf("selectSessionSocket = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestChooseForwardedSocket covers the selection policy layered on top of the
// inode match: prefer inode-bound; else fall back to a sole owned candidate;
// else refuse. The sole-owned fallback must never fire when more than one
// forwarded socket is owned (the concurrent-session case P0-2 must block).
func TestChooseForwardedSocket(t *testing.T) {
	ownedAll := func(string) bool { return true }

	mine := unixSocket{inode: "111", path: "/tmp/oidc-forward-1"}
	theirs := unixSocket{inode: "222", path: "/tmp/oidc-forward-2"}

	tests := []struct {
		name       string
		candidates []unixSocket
		sshdInodes map[string]bool
		owned      func(string) bool
		wantPath   string
		wantReason string
	}{
		{
			name:       "inode-bound wins even with multiple candidates",
			candidates: []unixSocket{mine, theirs},
			sshdInodes: map[string]bool{"111": true},
			owned:      ownedAll,
			wantPath:   "/tmp/oidc-forward-1",
			wantReason: "inode-bound",
		},
		{
			name:       "no inode match, single owned -> sole-owned fallback",
			candidates: []unixSocket{mine},
			sshdInodes: map[string]bool{}, // e.g. sshd fds not readable
			owned:      ownedAll,
			wantPath:   "/tmp/oidc-forward-1",
			wantReason: "sole-owned",
		},
		{
			name:       "no inode match, multiple owned -> refuse (concurrent sessions)",
			candidates: []unixSocket{mine, theirs},
			sshdInodes: map[string]bool{},
			owned:      ownedAll,
			wantPath:   "",
			wantReason: "ambiguous",
		},
		{
			name:       "no inode match, none owned -> refuse",
			candidates: []unixSocket{mine},
			sshdInodes: map[string]bool{},
			owned:      func(string) bool { return false },
			wantPath:   "",
			wantReason: "ambiguous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, reason := chooseForwardedSocket(tt.candidates, tt.sshdInodes, tt.owned)
			if path != tt.wantPath || reason != tt.wantReason {
				t.Fatalf("chooseForwardedSocket = (%q, %q), want (%q, %q)", path, reason, tt.wantPath, tt.wantReason)
			}
		})
	}
}
