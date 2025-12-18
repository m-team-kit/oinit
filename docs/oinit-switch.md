## oinit-switch

### Overview

`oinit-switch` is a secure user switching utility that serves as the entry
point for SSH connections authenticated with oinit certificates. It's
specified as a `force-command` in SSH certificates to ensure controlled
access.

### How It Works

1. SSH certificates issued by oinit-ca contain: `force-command="oinit-switch <username>"`
2. When users connect, SSH runs `oinit-switch` instead of their requested command
3. oinit-switch validates the request and uses `su` to switch to the target user
4. The final user session runs with proper privileges and environment

### Security Features

- **System User Protection**: Refuses to switch to system users (`UID < 100`)
- **User Validation**: Only allows switching from the `oinit` user or to oneself
- **TTY Detection**: Prevents command execution with TTY allocation to avoid security holes
- **Minimal Privileges**: Uses `execve` to replace itself, minimizing resource usage

### Configuration

No configuration files needed. Requirements:

- `oinit` system user must exist
- Target users must exist on the system
- `su` command must be available

### Usage

oinit-switch is not meant to be run directly. It's invoked automatically via SSH force-command:

```bash
# Interactive session (SSH without command)
ssh user@host
# → Runs: oinit-switch username → su - username -P

# Command execution (SSH with command)
ssh user@host "ls -la"
# → Runs: oinit-switch username → su - username -c "ls -la"
```

### Error Messages

- **"This is not allowed."**: Security violation detected
  - Attempting to switch to system user
  - Not running as oinit user
  - TTY allocated for command execution
- **"Internal error. oinit might not be set up correctly."**:
  - oinit user doesn't exist
  - su command not found

### Security Considerations

1. **Force Command**: Always specified in certificates to prevent bypass
2. **TTY Restrictions**: Commands run without TTY to prevent injection attacks
3. **User Validation**: Strict checks on source and target users
4. **No Direct Execution**: Users cannot run oinit-switch directly
