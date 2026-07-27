package api

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
)

func sshKey(t *testing.T, key interface{}) ssh.PublicKey {
	t.Helper()
	var pub interface{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PublicKey:
		pub = k
	}
	sk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestIsStrongPublicKey(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name   string
		key    ssh.PublicKey
		wantOK bool
	}{
		{"ed25519 accepted", sshKey(t, edPub), true},
		{"ecdsa p256 accepted", sshKey(t, ec256), true},
		{"rsa 3072 accepted", sshKey(t, rsa3072), true},
		{"rsa 2048 rejected", sshKey(t, rsa2048), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := isStrongPublicKey(tt.key)
			if ok != tt.wantOK {
				t.Fatalf("isStrongPublicKey(%s) = %v (%q), want %v", tt.key.Type(), ok, reason, tt.wantOK)
			}
		})
	}
}
