% OINIT-CA-CONFIG 5 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit-ca-config - configuration file for the oinit Certificate Authority

# SYNOPSIS

*/etc/oinit/ca-config.ini*

# DESCRIPTION

The oinit CA configuration is an INI-format file read by **oinit-ca**(8) (via its
**-c** option). It consists of an unnamed default section holding global
settings, followed by one or more *host group* sections. Each host group maps SSH
host names to the URL of the motley_cue instance used to validate tokens and
resolve local user names, and may override the global settings.

Within a host group, each `<ssh-host> = <motley_cue-url>` line assigns a host to
a motley_cue endpoint. Wildcards are supported: `*.example.com` matches a full
label prefix (`sub.example.com` but not `example.com`).

# GLOBAL SETTINGS

`listen-address`
: Address and port to listen on, for example `0.0.0.0:8082`. May be overridden
with the **-l** command-line option.

`host-ca-privkey`, `host-ca-pubkey`
: Paths to the host CA key pair (reserved for future use).

`user-ca-privkey`, `user-ca-pubkey`
: Paths to the user CA key pair used to sign issued certificates.

`cert-validity`
: Certificate lifetime, either a duration in seconds or the literal `token` to
inherit the access token's expiry.

`cert-validity-fallback`
: Lifetime in seconds used when `cert-validity = token` but the token carries no
`exp` claim. Default `300`.

`cache-duration`
: Seconds to cache the motley_cue provider list (including advertised OIDC
scopes). Default `10`.

`provision-user`
: Whether to provision a local account via motley_cue (`/user/deploy`). When
`false`, the token is still validated (`/user/get_status`) but no account is
provisioned, and `default-user` must be set. Default `true`.

`default-user`
: Fixed user name used when `provision-user = false`.

`cert-principals`
: Space-separated certificate principals. `$provisioned-user` is replaced with
the resolved user name. Default `oinit $provisioned-user`.

`force-command`
: Value of the certificate's `force-command` critical option. `$cert-principals`
and `$provisioned-user` are substituted. Empty disables it. **Security
relevant** — change only with care. Default `oinit-switch $cert-principals`.

# HOST-GROUP SETTINGS

Any global setting may be repeated inside a host group to override it. The
following are decided per host group and are security relevant:

`allow-root`
: Permit issuing certificates whose resolved user name is `root`. Default
`false`. A root login additionally requires the target server to list `root` in
*/etc/oinit/oinit-switch.conf* and PAM to permit the switch.

`allow-users`
: Optional allowlist of user names permitted a certificate for this host group.
When unset there is no per-user restriction. The `oinit` service account is
always refused and `root` is gated by `allow-root`.

`block-users`
: Optional denylist of user names always refused for this host group. Takes
precedence over `allow-users` and `allow-root`.

`require-token-aud`
: When set, a JWT access token must carry this value in its `aud` claim. Only
enforced for JWTs; opaque tokens are unaffected.

# EXAMPLES

    # Global defaults
    listen-address = 0.0.0.0:8082
    user-ca-privkey = /etc/oinit/user-ca
    user-ca-pubkey  = /etc/oinit/user-ca.pub
    cert-validity = 21600
    cert-validity-fallback = 1800

    # Host group
    [example.com]
    login.example.com = https://login.example.com:8443
    *.dev.example.com = https://dev-login.example.com:8443
    allow-users = alice bob

    # Git hosting: no provisioning, everyone logs in as "git"
    [git.example.com]
    git.example.com = https://git.example.com:8443
    provision-user = false
    default-user = git
    cert-principals = git

# SEE ALSO

**oinit-ca**(8), **oinit**(1), **oinit-switch.conf**(5)

# AUTHOR

oinit is developed by the KIT-SCC m-team.
