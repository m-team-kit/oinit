## oinit-shell

`oinit-shell` is a restricted shell that acts as a security layer between
SSH and `oinit-switch`. It ensures that the `oinit` user can only execute
the force-command specified in SSH certificates and prevents interactive
shell access.

### Purpose

The `oinit` user needs a login shell for SSH connections to work, but
should never provide interactive access. oinit-shell serves as this
restricted shell by:

- Only accepting commands in the format: `oinit-shell -c 'oinit-switch <username>'`
- Rejecting any other command attempts
- Preventing interactive shell sessions


### Configuration

No configuration needed. The shell is hardcoded to only execute `oinit-switch` commands.

### System Setup

```bash
# Create oinit user with oinit-shell
sudo useradd -r -s /usr/local/bin/oinit-shell -d /nonexistent -c "oinit system user" oinit

# Verify setup
grep oinit /etc/passwd
# oinit:x:999:999:oinit system user:/nonexistent:/usr/local/bin/oinit-shell
```

### How It Works

1. SSH invokes the user's shell with `-c` flag when executing force-command
2. oinit-shell validates the command matches `oinit-switch <target>`
3. If valid, it executes oinit-switch using `execve`
4. If invalid, it exits with an error message

### Security Features

- **Command Validation**: Only allows `oinit-switch` with exactly one argument
- **No Interactive Access**: Rejects any attempt at interactive shell
- **Minimal Attack Surface**: Simple validation logic with no complex parsing
- **Process Replacement**: Uses `execve` to avoid lingering processes

### Error Messages

- **"This user does not provide interactive access."**: Attempt to use shell interactively or run unauthorized commands
- **"An error occurred."**: oinit-switch binary not found in PATH

### Testing

```bash
# Valid command (would work via SSH)
sudo -u oinit /usr/local/bin/oinit-shell -c 'oinit-switch alice'

# Invalid attempts (will be rejected)
sudo -u oinit /usr/local/bin/oinit-shell              # No -c flag
sudo -u oinit /usr/local/bin/oinit-shell -c 'ls'      # Wrong command
sudo -u oinit /usr/local/bin/oinit-shell -c 'oinit-switch alice bob'  # Too many args
```
