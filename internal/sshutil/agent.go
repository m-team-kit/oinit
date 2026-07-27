package sshutil

import (
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
)

type socket struct {
	AddressEnvVar string
	Type          string
}

const (
	PRINCIPAL = "oinit"
)

// IsGPGAgent checks if the current SSH agent is gpg-agent.
// gpg-agent does not support SSH certificates, so we need to detect it
// and avoid using the agent for certificate storage.
func IsGPGAgent() bool {
	// Check for GPG_AGENT_INFO environment variable
	if os.Getenv("GPG_AGENT_INFO") != "" {
		return true
	}

	// Check SSH_AUTH_SOCK path pattern
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock != "" {
		// gpg-agent typically uses paths containing "gnupg" or "gpg-agent"
		return strings.Contains(sshAuthSock, "gnupg") ||
			strings.Contains(sshAuthSock, "gpg-agent")
	}

	return false
}

func AgentIsRunning() bool {
	sockets := []socket{
		{
			"SSH_AUTH_SOCK",
			"unix",
		},
	}

	for _, sock := range sockets {
		if _, err := net.Dial(sock.Type, os.Getenv(sock.AddressEnvVar)); err == nil {
			return true
		}
	}

	return false
}

func GetAgent() (agent.ExtendedAgent, error) {
	sshAgentSock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	return agent.NewClient(sshAgentSock), err
}

// AgentCertComment returns the ssh-agent key comment oinit tags its own
// certificates with, so it can later recognise its certificate for a given
// host. The certificate's KeyId is the CA's audit identity ("sub @ iss -> user")
// and does not encode the host, so the client-controlled agent comment is used
// instead.
func AgentCertComment(host string) string {
	return PRINCIPAL + "@" + strings.ToLower(host)
}

// agentGetOinitCertificates returns a slice of all certificates in the agent
// that have been issued by oinit for the given host.
//
// oinit tags its own certificates with the per-host comment from
// AgentCertComment when it adds them to the agent; that comment (plus the
// "oinit" principal) is used to identify them here.
func agentGetOinitCertificates(agent agent.ExtendedAgent, host string) ([]ssh.Certificate, error) {
	var certificates []ssh.Certificate

	keys, err := agent.List()
	if err != nil {
		return certificates, err
	}

	comment := AgentCertComment(host)

	for _, key := range keys {
		if key.Comment != comment {
			continue
		}

		pk, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			// This should never happen
			continue
		}

		cert, ok := pk.(*ssh.Certificate)
		if !ok {
			// pk is not a certificate but a normal public key
			continue
		}

		if cert.CertType == ssh.UserCert &&
			slices.Contains(cert.ValidPrincipals, PRINCIPAL) {
			certificates = append(certificates, *cert)
		}
	}

	return certificates, nil
}

// AgentHasCertificate returns a bool indicating whether a certificate issued
// by oinit-ca for the given host is currently present in the agent.
// An error is returned when communication with the agent is not possible, for
// example if it isn't running.
func AgentHasCertificate(agent agent.ExtendedAgent, host string) (bool, error) {
	certificates, err := agentGetOinitCertificates(agent, host)

	return len(certificates) != 0, err
}

// AgentRemoveCertificates removes all certificates issued by oinit-ca for the
// given host from the agent.
// An error is returned when communication with the agent is not possible, for
// example if it isn't running.
func AgentRemoveCertificates(agent agent.ExtendedAgent, host string) error {
	certificates, err := agentGetOinitCertificates(agent, host)
	if err != nil {
		return err
	}

	for _, cert := range certificates {
		agent.Remove(&cert)
	}

	return nil
}
