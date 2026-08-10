% OINIT-CA 8 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit-ca - SSH Certificate Authority server for oinit

# SYNOPSIS

**oinit-ca** **-c** *config* [**-l** *host*:*port*]

# DESCRIPTION

**oinit-ca** is the Certificate Authority server of the oinit system. It exposes
a REST API that issues short-lived OpenSSH user certificates to clients that
present a valid OpenID Connect (OIDC) access token. Tokens are validated through
a motley_cue instance, which also resolves the local user name that becomes the
certificate principal.

The server maintains SSH CA key pairs, supports multiple host groups with
independent keys and policies, and rate-limits certificate issuance per client
IP. It serves plain HTTP and is intended to run behind a TLS-terminating reverse
proxy; do not expose it directly to untrusted networks.

Issued certificates carry the principals `oinit` and the resolved user name, and
a `force-command` critical option of `oinit-switch <user>` so that the server's
**oinit-switch**(8) mediates the actual login.

# OPTIONS

**-c** *config*
: Path to the configuration file (required). See **oinit-ca-config**(5).

**-l** *host*:*port*
: Listen address, overriding the `listen-address` set in the configuration file.

# FILES

*/etc/oinit/ca-config.ini*
: Default configuration file installed by the package. See
**oinit-ca-config**(5).

*/usr/lib/systemd/system/oinit-ca.service*
: systemd service unit that runs the server.

# EXAMPLES

Run against a configuration file, listening on all interfaces:

    oinit-ca -c /etc/oinit/ca-config.ini -l 0.0.0.0:8443

Generate the user CA key pair the server signs with:

    ssh-keygen -t ed25519 -f /etc/oinit/user-ca -C "oinit User CA"

# SEE ALSO

**oinit-ca-config**(5), **oinit**(1), **oinit-switch**(8), **ssh-keygen**(1),
**systemd**(1)

# AUTHOR

oinit is developed by the KIT-SCC m-team.
