% OINIT 1 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit - obtain and manage SSH certificates for federated (OIDC) login

# SYNOPSIS

**oinit add** [**-y**|**--yes**] *ssh-host*[:*port*] [*ca-url*]

**oinit del** *ssh-host*[:*port*]

**oinit list**

**oinit match** *ssh-host*[:*port*] [*port*]

**oinit** [**-v**|**--version**] [**-h**|**--help**]

# DESCRIPTION

**oinit** is the client for the oinit SSH certificate management system. It
provides federated, identity-based SSH login by automatically obtaining and
managing short-lived SSH certificates from an oinit Certificate Authority
(**oinit-ca**(8)). It integrates with OpenSSH and, when available,
**oidc-agent**(1).

Once a host is registered with **oinit add**, an SSH connection to that host is
transparently intercepted through a `Match exec` block written to the user's SSH
configuration. For each connection **oinit** obtains an OpenID Connect access
token, generates an ephemeral Ed25519 key pair, requests a signed certificate
from the CA, and loads it into **ssh-agent**(1) (or stores it on disk), after
which OpenSSH proceeds normally using the certificate.

# COMMANDS

**add** [**-y**] *ssh-host*[**:**\ *port*] [*ca-url*]
: Register *ssh-host* for oinit management. If *ca-url* is omitted the CA is
auto-discovered (see **CA DISCOVERY**). Before the CA's public key is trusted,
its SHA256 fingerprint is printed and confirmation is requested; the accepted key
is written to *known_hosts* as a `@cert-authority` entry. Only accept a
fingerprint you have verified out of band. **-y**, **--yes** accepts the
fingerprint non-interactively (for scripted setups where it is verified by other
means).

**del** *ssh-host*[**:**\ *port*]
: Remove *ssh-host* from oinit management and clean up stored certificates. The
alias **delete** is also accepted.

**list**
: List all hosts currently managed by oinit.

**match** *ssh-host*[**:**\ *port*] [*port*]
: Fetch a certificate for a managed host. This is invoked automatically by
OpenSSH through the generated `Match exec` block (as `oinit match %h %p`) and is
rarely run by hand. Exits 0 if the host is managed, non-zero otherwise.

# OPTIONS

**-y**, **--yes**
: Accept the CA host-key fingerprint non-interactively during **add**.

**-v**, **--version**
: Print the oinit version and exit.

**-h**, **--help**
: Print a usage summary and exit.

# CA DISCOVERY

When *ca-url* is not given to **add**, the CA is discovered in two phases:

1. DNS TXT records: `_oinit-ca.`*hostname* then `_oinit-ca.`*parent-domain*
   (a TXT record contains the CA base URL).
2. HTTPS probes (fallback): `https://`*hostname*`/oinit/` then
   `https://`*parent-domain*`/oinit/`.

DNS TXT records are recommended for production. Discovery results are cached
(5 minutes on success, 1 minute on failure). CA operators are encouraged to also
publish the CA host-key fingerprint in a DNSSEC-signed TXT record
(`_oinit-ca-fp.`*hostname*) so it can be verified before **add** trusts it.

# ACCESS TOKEN DISCOVERY

An access token is located using the first source that yields one, in order:

1. Environment variables: `ACCESS_TOKEN`, `BEARER_TOKEN`, `OIDC`,
   `OS_ACCESS_TOKEN`, `OIDC_ACCESS_TOKEN`, `WATTS_TOKEN`, `WATTSON_TOKEN`.
2. A file named by `BEARER_TOKEN_FILE`.
3. `$XDG_RUNTIME_DIR/bt_u$UID` (e.g. `/run/user/1000/bt_u1000`).
4. `/tmp/bt_u$UID`.
5. **oidc-agent**(1): if running, the CA is queried for supported OIDC providers
   and a token is requested from the agent.
6. A manual prompt on the terminal.

# ENVIRONMENT

`OIDC_AGENT_ACCOUNT`
: Pre-select a specific oidc-agent account (skips the provider prompt).

`OIDC_ISS`, `OIDC_ISSUER`
: Pre-select a specific OIDC issuer by URL.

`ACCESS_TOKEN`, `BEARER_TOKEN`, `OIDC`, `OS_ACCESS_TOKEN`, `OIDC_ACCESS_TOKEN`, `WATTS_TOKEN`, `WATTSON_TOKEN`
: Provide an access token directly.

`BEARER_TOKEN_FILE`
: Path to a file containing an access token.

`OINIT_DEBUG`
: Enable detailed debug logging.

`NO_COLOR`
: Disable coloured output.

# FILES

*~/.ssh/oinit_hosts*
: Per-user list of managed hosts and their CA URLs. See **oinit_hosts**(5).

*/etc/ssh/ssh_oinit_hosts*
: System-wide list of managed hosts. See **oinit_hosts**(5).

*~/.ssh/config*
: A `Match exec "oinit match %h %p"` block is added here by **add**.

*~/.ssh/known_hosts*
: The CA public key is written here as a `@cert-authority` entry.

*~/.ssh/oinit_<host>_<port>*, *~/.ssh/oinit_<host>_<port>-cert.pub*
: Private key and certificate used when ssh-agent storage is unavailable (for
example when gpg-agent is in use).

# EXAMPLES

Register a host, auto-discovering the CA (prompts to confirm the fingerprint):

    oinit add login.example.com

Register a host with an explicit CA URL and non-default SSH port:

    oinit add login.example.com:2222 https://ca.example.com:8443

Accept the CA fingerprint non-interactively in automation:

    oinit add -y login.example.com

List and then remove a managed host:

    oinit list
    oinit del login.example.com

Inspect an issued certificate:

    ssh-keygen -L -f ~/.ssh/oinit_login.example.com_22-cert.pub

# SEE ALSO

**oinit_hosts**(5), **oinit-ca**(8), **oinit-shell**(8), **oinit-switch**(8),
**oidc-agent**(1), **ssh**(1), **ssh-agent**(1), **ssh-keygen**(1)

Full documentation lives in the project's `docs/` directory.

# AUTHOR

oinit is developed by the KIT-SCC m-team.
