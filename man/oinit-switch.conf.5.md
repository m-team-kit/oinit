% OINIT-SWITCH.CONF 5 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit-switch.conf - server-side policy for oinit-switch su targets

# SYNOPSIS

*/etc/oinit/oinit-switch.conf*

# DESCRIPTION

This file controls which accounts **oinit-switch**(8) is permitted to `su` to on
an SSH server. It is a defence-in-depth control that is enforced on the server
independently of the Certificate Authority: even if the CA issues a certificate
for a given user, that user is only reachable if this file permits it.

By default **oinit-switch**(8) refuses to switch to any system user (including
`root`); non-system users are permitted unless explicitly blocked. The keys below
adjust that policy. Values are comma- or whitespace-separated user-name lists.
Lines beginning with `#` are comments. If the file is absent, all system users
are denied.

# SETTINGS

`allow-users`
: System users permitted as `su` targets. Non-system users are always permitted
and need not be listed. **Security relevant:** listing `root` enables federated
root logins — this additionally requires the CA host group to set `allow-root`
and PAM to permit the `oinit` -> `root` switch.

`block-users`
: User names that are never permitted as `su` targets, regardless of uid. Takes
precedence over `allow-users` and over the "non-system users are always allowed"
rule — a hard, server-side override to keep specific accounts unreachable via
oinit.

# EXAMPLES

    # Allow federated root logins (also needs CA allow-root + PAM)
    allow-users = root

    # Never allow these accounts, even if the CA issues a certificate
    block-users = deploy backup

# SEE ALSO

**oinit-switch**(8), **oinit-shell**(8), **oinit-ca-config**(5), **su**(1)

# AUTHOR

oinit is developed by the KIT-SCC m-team.
