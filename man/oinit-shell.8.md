% OINIT-SHELL 8 "@DATE@" "oinit @VERSION@" "oinit Manual"

# NAME

oinit-shell - restricted login shell for the oinit service account

# SYNOPSIS

**oinit-shell** **-c** "**oinit-switch** *username*"

# DESCRIPTION

**oinit-shell** is a restricted shell used as the login shell of the `oinit`
service account on an SSH server. It exists so that the `oinit` account has a
valid shell for SSH to function, while never granting interactive access.

It accepts only a single non-interactive command of the form
`oinit-switch <username>` (as passed by OpenSSH through the certificate's
`force-command` when it invokes the shell with **-c**). Any other invocation —
an interactive session, a different command, or the wrong number of arguments —
is refused. On a valid command it replaces itself with **oinit-switch**(8) via
**execve**(2), resolving that binary relative to its own location and using a
fixed safe `PATH`.

**oinit-shell** is not intended to be run by users directly.

# OPTIONS

**-c** *command*
: The only accepted form. *command* must be `oinit-switch` followed by exactly
one user name argument.

# CONFIGURATION

No configuration file is used. The set of permitted commands is fixed.

# SETUP

The `oinit` account is created with **oinit-shell** as its login shell, for
example:

    useradd -r -s /usr/bin/oinit-shell -d /nonexistent \
        -c "oinit system user" oinit

# DIAGNOSTICS

"This user does not provide interactive access."
: An interactive session or an unauthorized command was attempted.

"An error occurred."
: The **oinit-switch**(8) binary could not be located or executed.

# SEE ALSO

**oinit-switch**(8), **oinit-ca**(8), **sshd**(8), **sshd_config**(5)

# AUTHOR

oinit is developed by the KIT-SCC m-team.
