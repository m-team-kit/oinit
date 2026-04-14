package api

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// generateUserCertificate generates a new OpenSSH certificate based on the
// given public key. The principals and forceCommand are configurable per
// host group. If forceCommand is empty, no force-command critical option
// is set.
func generateUserCertificate(host string, pubkey ssh.PublicKey, username string, subject string, issuer string, duration uint64, principals []string, forceCommand string) ssh.Certificate {
	validAfter := uint64(time.Now().Unix())
	validBefore := validAfter + duration

	criticalOptions := map[string]string{}
	if forceCommand != "" {
		criticalOptions["force-command"] = forceCommand
	}

	return ssh.Certificate{
		Key: pubkey,
		// From OpenSSH PROTOCOL.certkeys:
		//   serial is an optional certificate serial number set by the CA to
		//   provide an abbreviated way to refer to certificates from that CA.
		//   If a CA does not wish to number its certificates it must set this
		//   field to zero.
		Serial:   0,
		CertType: ssh.UserCert,
		// From OpenSSH PROTOCOL.certkeys:
		//   key id is a free-form text field that is filled in by the CA at
		//   the time of signing; the intention is that the contents of this
		//   field are used to identify the identity principal in log messages.
		//
		// Set KeyId to "user@host" which can be used by the client to check
		// which host this certificate was issued for.
		KeyId:           subject + " @ " + issuer + " -> " + username,
		ValidPrincipals: principals,
		// From OpenSSH PROTOCOL.certkeys:
		//   "valid after" and "valid before" specify a validity period for the
		//   certificate. Each represents a time in seconds since 1970-01-01
		//   00:00:00. A certificate is considered valid if:
		//     valid after <= current time < valid before
		ValidAfter:  validAfter - 10, // account for slight clock differences
		ValidBefore: validBefore,
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
			},
		},
	}
}
