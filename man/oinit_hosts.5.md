% OINIT_HOSTS 5 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit_hosts - list of SSH hosts managed by oinit and their Certificate Authorities

# SYNOPSIS

*~/.ssh/oinit_hosts*

*/etc/ssh/ssh_oinit_hosts*

# DESCRIPTION

The oinit hosts file lists the SSH hosts that **oinit**(1) manages and maps each
of them to the base URL of the oinit Certificate Authority (**oinit-ca**(8))
that issues certificates for it. It is maintained automatically by
`oinit add` and `oinit del`; it can also be edited by hand.

Two locations are read: the per-user file *~/.ssh/oinit_hosts* and the
system-wide file */etc/ssh/ssh_oinit_hosts*. Both are consulted when oinit
determines whether a host is managed.

# FORMAT

The file is line-based. Each non-empty line describes one managed host:

    <ssh-host>:<port> <ca-url>

*ssh-host*
: The SSH host name as used on the **ssh**(1) command line.

*port*
: The SSH port. `oinit add host` without a port uses the default SSH port 22.

*ca-url*
: The base URL of the CA, for example `https://ca.example.com:8443`.

Fields are separated by whitespace. There is one entry per line.

# EXAMPLES

    login.example.com:22 https://ca.example.com:8443
    compute.example.com:2222 https://ca.example.com:8443

# SEE ALSO

**oinit**(1), **oinit-ca**(8), **ssh**(1), **ssh_config**(5)

# AUTHOR

oinit is developed by the KIT-SCC m-team.
