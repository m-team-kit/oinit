# oinit

> Certificate-based OpenSSH for Federated Identities

[![Latest release](https://img.shields.io/gitlab/v/tag/m-team/oidc/ssh/oinit?gitlab_url=https%3A%2F%2Fcodebase.helmholtz.cloud&sort=semver&color=blue&label=release)](https://codebase.helmholtz.cloud/m-team/oidc/ssh/oinit/-/tags)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/m-team-kit/oinit/blob/main/LICENSE)
[![Gitlab CI](https://codebase.helmholtz.cloud/m-team/oidc/ssh/oinit/badges/main/pipeline.svg)](https://codebase.helmholtz.cloud/m-team/oidc/ssh/oinit/-/pipelines)

oinit is a Go-based certificate management system for OpenSSH that enables
federated identity login. It uses OpenID Connect tokens (via oidc-agent)
to authenticate users and issues SSH certificates signed by a Certificate
Authority.

This repository contains a collection of programs to enable OpenSSH login for federated identities based on certificates.


<p align="center">
  <img src=".github/oinit.gif" /><br>
  <i>OpenID Connect access token for selected provider is loaded from <a href="https://github.com/indigo-dc/oidc-agent">oidc-agent</a>.</i>
</p>

## Architecture

### End-to-End Certificate Flow

1. **Client (`oinit match`)** is invoked transparently by OpenSSH via a `Match exec` block in `~/.ssh/config`.
2. The client resolves the CA URL for the target host (from `~/.ssh/oinit_hosts` or `/etc/ssh/ssh_oinit_hosts`).
3. An OIDC access token is obtained — checked in order: environment variables (`ACCESS_TOKEN`, `BEARER_TOKEN`, etc.), `BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR/bt_u$UID`, `/tmp/bt_u$UID`, oidc-agent, manual TTY prompt.
4. The client generates an ephemeral Ed25519 key pair, sends the public key + token to the CA.
5. **CA (`oinit-ca`)** validates the token against motley_cue (`/user/deploy`), then signs and returns an SSH certificate with `force-command: oinit-switch <username>` and principal `oinit`.
6. The client loads the certificate into ssh-agent (preferred) or saves it to `~/.ssh/oinit_<host>_<port>-cert.pub`. If gpg-agent is detected, file-based storage is used instead.
7. OpenSSH connects as the `oinit` user. The server's `ForceCommand` invokes **oinit-shell**, which only allows running **oinit-switch**, which `su`s to the target user. If the user connected directly as themselves (via the username principal), `oinit-switch` detects `targetUid == curUid` and exits immediately.

### Server-Side Privilege Escalation

No setuid bit is needed on any oinit binary. Privilege escalation is handled entirely by PAM: a rule in `/etc/pam.d/su` allows the `oinit` user to `su` to non-system users without a password. The `oinit-switch` code enforces that only the `oinit` user can invoke it (others would be prompted for a password by `su` and fail). The system user guard (`targetUid < SYS_UID_MAX`) is an additional safety check, even though oinit-ca would never issue a certificate targeting a system user.

### oidc-agent Socket Forwarding

oinit-switch supports forwarding the client's oidc-agent socket to the remote server via SSH remote port forwarding (`ssh -R /tmp/oidc-forward-$RANDOM:<local-oidc-socket> host`). On the server side, oinit-switch:

1. Detects the forwarded socket by scanning `/proc/net/unix` for entries matching `oidc-forward`. Multiple concurrent sessions are disambiguated by matching socket inodes against the session's sshd process; if that fails, the newest socket owned by the current user is selected.
2. Chowns the socket to the target user (requires `CAP_CHOWN` on the oinit-switch binary, set via `setcap cap_chown=ep`).
3. Sets `OIDC_SOCK` in the environment and passes it through `su -w OIDC_SOCK` so the target user's session can use it.
4. Cleans up the socket on session exit (via `rm -f` appended to the `su -c` command) and on fatal errors.

### CA Discovery (`internal/dnsutil/`)

When running `oinit add <host>`, the CA is auto-discovered via:
1. DNS TXT records: `_oinit-ca.<hostname>`, then `_oinit-ca.<parent-domain>`
2. HTTPS probes (fallback): `https://<hostname>/oinit/`, then `https://<parent-domain>/oinit/`

Results are cached (5 min success, 1 min failure) using the generic `TimedCache`.

## Security considerations

A few properties of the design are worth being explicit about for operators:

- **CA discovery is trust-on-first-use.** `oinit add <host>` accepts whatever CA
  a DNS TXT record (or, as a fallback, an HTTPS probe) points to. The DNS lookup
  itself is not authenticated, so without DNSSEC an attacker who can spoof DNS
  responses during the first `oinit add` can substitute their own CA. To bound
  this, `oinit add` prints the CA host-key **SHA256 fingerprint** and requires
  confirmation before pinning it into `known_hosts`; verify that fingerprint out
  of band. Operators are encouraged to publish it in a DNSSEC-signed record (see
  [Verifying the CA key](docs/oinit.md#verifying-the-ca-key)); this is currently
  an operational check, not auto-verified. Prefer specifying the CA explicitly
  (`oinit add <host> <ca>`); `-y`/`--yes` accepts the fingerprint non-interactively.

- **Issued certificates permit port and agent forwarding.** The user certificate
  carries the `permit-port-forwarding` and `permit-agent-forwarding` extensions.
  This is **required** for the oidc-agent socket forwarding feature (which uses
  SSH remote port forwarding), so it cannot be disabled without removing that
  feature. Operators who do not need agent forwarding and want to restrict
  tunnelling should enforce it server-side (e.g. `AllowTcpForwarding`,
  `PermitOpen` in `sshd_config`) rather than relying on the certificate.

- **The CA delegates access-token validity to motley_cue.** For a JWT the CA
  additionally verifies the signature against the issuer's JWKS (and the audience,
  if `require-token-aud` is set), but the decision that a token is valid and
  authorises the user is made by motley_cue. Opaque (non-JWT) tokens have no
  CA-inspectable audience, so `require-token-aud` does not apply to them. The
  discovery/JWKS/userinfo requests the CA makes are restricted to
  motley_cue-advertised issuers, require HTTPS, and do not follow redirects.

- **Issued certificates are not bound to a specific host.** An SSH *user*
  certificate carries no host restriction, and a host group may cover many hosts
  (including wildcards) that all trust the same user CA. A certificate obtained for
  one host in a group is therefore technically usable on any host trusting that CA.
  This is inherent to the SSH user-certificate model; it is mitigated by the short
  certificate lifetime (`cert-validity`). Use separate host groups / user CAs to
  isolate sets of hosts that must not share trust.

- **Revocation relies on short certificate lifetimes.** Certificates are issued
  with serial `0` and oinit does not maintain a KRL, so there is no serial- or
  key-based revocation — keep `cert-validity` short. Serial-based KRL revocation is
  a possible future addition.

- **gpg-agent detection is heuristic.** The client decides whether the running
  agent is gpg-agent (which cannot hold SSH certificates) from `GPG_AGENT_INFO` and
  the `SSH_AUTH_SOCK` path. A misdetection only changes whether the certificate is
  held in the agent or written to `~/.ssh` (the private key file is mode `0600`), so
  the impact is limited to storage location, not exposure of the key to others.

- **The client public-key strength floor is defence-in-depth.** The CA refuses to
  certify weak client keys (RSA below 3072 bits, and non-Ed25519/ECDSA/RSA types
  such as DSA). Because the client certifies its own freshly generated key, this
  primarily guards against a non-standard or malicious client rather than a
  third-party risk.

## Configuration

See `configs/config.sample.ini` for the CA config format. Key settings per host group: `host-ca-privkey`, `host-ca-pubkey`, `user-ca-privkey`, `user-ca-pubkey`, `cert-validity` (seconds or `"token"`), `cert-validity-fallback`, `cache-duration`. The `listen-address` can also be set in the default section or overridden via `-l` flag.

## Docker

- `make oinit-ca-docker` builds using `build/Dockerfile` (multi-stage, Go 1.20 + Alpine)

## Development

```sh
# Client application
$ make oinit

# oinit-shell and oinit-switch
$ make oinit-shell oinit-switch

# Server application (CA)
$ make oinit-ca
```

When changing the REST API annotations, run `make swagger` to generate the Swagger files.

### Branches

Development happens on feature branches checked out from and merged back into `prerel`.
When ready, commits are merged into `main` and tagged as release.


## License

This project is licensed under the [MIT License](LICENSE).
