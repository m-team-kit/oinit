% OINIT-SWITCH 8 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit-switch - switch from the oinit service account to the certificate's target user

# SYNOPSIS

**oinit-switch** *username* [*username* ...]

# DESCRIPTION

**oinit-switch** is the entry point for SSH sessions authenticated with an oinit
certificate. It is named in the certificate's `force-command` critical option
(as `oinit-switch <username>`), so OpenSSH runs it in place of the requested
command. Its arguments are the certificate principals; **oinit-switch** switches
from the `oinit` service account to the target user with **su**(1) and then runs
the user's requested command or an interactive login shell.

No setuid bit is required. The privilege change is performed by PAM: a rule
permits the `oinit` account to `su` to permitted users without a password.
**oinit-switch** enforces that it is being run as the `oinit` account,
re-validates each certificate principal against the same user-name rules the CA
uses, resolves **su**(1) from a fixed absolute-path list, and resets `PATH` to a
safe value, so no program is resolved through a caller-controlled environment. If
the resolved target is the current user, it exits immediately.

By default it refuses to switch to system users (including `root`); such accounts
must be explicitly allowed on the server. See **oinit-switch.conf**(5).

**oinit-switch** optionally forwards a client's **oidc-agent**(1) socket
(received via SSH remote port forwarding) into the target user's session, setting
`OIDC_SOCK` accordingly. It is not intended to be run by users directly.

# CONFIGURATION

Target-selection policy is read from */etc/oinit/oinit-switch.conf*; see
**oinit-switch.conf**(5). Requirements: the `oinit` account must exist, target
users must exist, **su**(1) must be available, and PAM must permit the switch.

# FILES

*/etc/oinit/oinit-switch.conf*
: Server-side allow/deny policy for `su` targets. See **oinit-switch.conf**(5).

*/var/log/oinit/oinit.log*
: Session log written by oinit-switch.

# DIAGNOSTICS

"This is not allowed."
: A policy violation was detected, for example switching to a disallowed system
user, not running as the `oinit` account, or a TTY allocated for command
execution.

"Internal error. oinit might not be set up correctly."
: The `oinit` account does not exist, or **su**(1) was not found.

# SEE ALSO

**oinit-switch.conf**(5), **oinit-shell**(8), **oinit-ca**(8), **su**(1),
**sshd**(8), **oidc-agent**(1)

# AUTHOR

oinit is developed by the KIT-SCC m-team.
