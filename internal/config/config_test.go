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
