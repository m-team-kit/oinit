package sshutil

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

// testPubKey returns a valid ed25519 public key in authorized_keys format,
// with a trailing comment.
func testPubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	assert.NoError(t, err)
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n") + " user@host"
}

func TestGenerateKnownHosts(t *testing.T) {
	line, err := GenerateKnownHosts("example.com", "22", testPubKey(t))
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "@cert-authority example.com ssh-ed25519 "))
	// The trailing comment must be stripped and only one line produced.
	assert.NotContains(t, line, "user@host")
	assert.NotContains(t, line, "\n")
}

func TestGenerateKnownHostsNonStandardPort(t *testing.T) {
	line, err := GenerateKnownHosts("example.com", "2222", testPubKey(t))
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "@cert-authority [example.com]:2222 "))
}

func TestGenerateKnownHostsRejectsInjection(t *testing.T) {
	// A CA must not be able to inject extra known_hosts lines (e.g. a global
	// "@cert-authority *") through a newline in the returned key.
	key := testPubKey(t)
	malicious := key + "\n@cert-authority * " + key

	line, err := GenerateKnownHosts("example.com", "22", malicious)
	assert.NoError(t, err)
	assert.NotContains(t, line, "@cert-authority *")
	assert.NotContains(t, line, "\n")
}

func TestGenerateKnownHostsRejectsBadKey(t *testing.T) {
	_, err := GenerateKnownHosts("example.com", "22", "not-a-real-key")
	assert.Error(t, err)
}

func TestGenerateKnownHostsRejectsBadHost(t *testing.T) {
	_, err := GenerateKnownHosts("example.com ssh-ed25519 AAAA evil", "22", testPubKey(t))
	assert.Error(t, err)
}
