package config

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeTestKeys generates an ed25519 key pair and writes the private key
// (PEM/OpenSSH format) and public key (authorized_keys format) into dir,
// returning their paths. Both the host and user CA reuse the same pair here;
// the parsing under test does not care whether they differ.
func writeTestKeys(t *testing.T, dir string) (priv string, pub string) {
	t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}

	priv = filepath.Join(dir, "ca")
	pub = filepath.Join(dir, "ca.pub")

	if err := os.WriteFile(priv, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pub, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	return priv, pub
}

// loadTestConfig writes an ini file with the given host group body (the keys,
// cache-duration and cert-validity are supplied automatically) and loads it.
func loadTestConfig(t *testing.T, groupBody string) (Config, error) {
	t.Helper()

	dir := t.TempDir()
	priv, pub := writeTestKeys(t, dir)

	ini := "" +
		"host-ca-privkey = " + priv + "\n" +
		"host-ca-pubkey  = " + pub + "\n" +
		"user-ca-privkey = " + priv + "\n" +
		"user-ca-pubkey  = " + pub + "\n" +
		"cert-validity   = 21600\n" +
		"cache-duration  = 600\n" +
		"\n" +
		"[example.com]\n" +
		"login.example.com = https://login.example.com:8443\n" +
		groupBody

	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte(ini), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return Load(path)
}

func TestAllowRootParsing(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    bool
		wantErr bool
	}{
		{name: "absent defaults to false", body: "", want: false},
		{name: "true", body: "allow-root = true\n", want: true},
		{name: "false", body: "allow-root = false\n", want: false},
		{name: "invalid value errors", body: "allow-root = maybe\n", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := loadTestConfig(t, tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			info, err := conf.GetInfo("login.example.com")
			if err != nil {
				t.Fatalf("GetInfo: %v", err)
			}
			if info.AllowRoot != tc.want {
				t.Errorf("AllowRoot = %v, want %v", info.AllowRoot, tc.want)
			}
		})
	}
}

func TestAllowUsersParsing(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{name: "absent is empty", body: "", want: nil},
		{name: "comma separated", body: "allow-users = alice, bob\n", want: []string{"alice", "bob"}},
		{name: "space separated", body: "allow-users = alice bob\n", want: []string{"alice", "bob"}},
		{name: "single", body: "allow-users = git\n", want: []string{"git"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := loadTestConfig(t, tc.body)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			info, err := conf.GetInfo("login.example.com")
			if err != nil {
				t.Fatalf("GetInfo: %v", err)
			}
			if len(info.AllowUsers) != len(tc.want) {
				t.Fatalf("AllowUsers = %v, want %v", info.AllowUsers, tc.want)
			}
			for i, w := range tc.want {
				if info.AllowUsers[i] != w {
					t.Errorf("AllowUsers[%d] = %q, want %q", i, info.AllowUsers[i], w)
				}
			}
		})
	}
}

func TestBlockUsersParsing(t *testing.T) {
	conf, err := loadTestConfig(t, "block-users = mallory, eve\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := conf.GetInfo("login.example.com")
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	want := []string{"mallory", "eve"}
	if len(info.BlockUsers) != len(want) {
		t.Fatalf("BlockUsers = %v, want %v", info.BlockUsers, want)
	}
	for i, w := range want {
		if info.BlockUsers[i] != w {
			t.Errorf("BlockUsers[%d] = %q, want %q", i, info.BlockUsers[i], w)
		}
	}
}

func TestRequireTokenAudParsing(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "absent defaults to empty", body: "", want: ""},
		{name: "set per host group", body: "require-token-aud = https://ca.example.com\n", want: "https://ca.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := loadTestConfig(t, tc.body)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			info, err := conf.GetInfo("login.example.com")
			if err != nil {
				t.Fatalf("GetInfo: %v", err)
			}
			if info.RequireTokenAud != tc.want {
				t.Errorf("RequireTokenAud = %q, want %q", info.RequireTokenAud, tc.want)
			}
		})
	}
}

// TestCacheDurationDefault verifies that cache-duration is optional (falls back
// to DefaultCacheDuration) and that an explicit value is respected. It builds
// the config directly because the shared loadTestConfig helper always sets
// cache-duration.
func TestCacheDurationDefault(t *testing.T) {
	tests := []struct {
		name string
		line string // cache-duration line for the default section (may be empty)
		want int
	}{
		{name: "absent falls back to default", line: "", want: DefaultCacheDuration},
		{name: "explicit value is respected", line: "cache-duration = 600\n", want: 600},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			priv, pub := writeTestKeys(t, dir)

			ini := "" +
				"host-ca-privkey = " + priv + "\n" +
				"host-ca-pubkey  = " + pub + "\n" +
				"user-ca-privkey = " + priv + "\n" +
				"user-ca-pubkey  = " + pub + "\n" +
				"cert-validity   = 21600\n" +
				tc.line +
				"\n" +
				"[example.com]\n" +
				"login.example.com = https://login.example.com:8443\n"

			path := filepath.Join(dir, "config.ini")
			if err := os.WriteFile(path, []byte(ini), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			conf, err := Load(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			info, err := conf.GetInfo("login.example.com")
			if err != nil {
				t.Fatalf("GetInfo: %v", err)
			}
			if info.CacheDuration != tc.want {
				t.Errorf("CacheDuration = %d, want %d", info.CacheDuration, tc.want)
			}
		})
	}
}
