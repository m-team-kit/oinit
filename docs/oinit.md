# oinit Client

## How It Works

1. **Host Registration**: Administrators use `oinit add` to register SSH
   hosts that require certificate-based authentication
2. **SSH Integration**: oinit modifies your SSH config to intercept
   connections to registered hosts  
3. **Certificate Retrieval**: When you SSH to a registered host, oinit
   automatically:
    - Retrieves an OIDC token (e.g. from oidc-agent)
    - Requests a signed SSH certificate from the oinit-ca server
    - Adds the certificate to your SSH agent
4. **Transparent Connection**: SSH proceeds normally using the
   ssh-certificate for authentication

## Overview

`oinit` is the main client application for the oinit ssh-certificate management system. It provides
federated identity-based SSH authentication by automatically obtaining and managing SSH certificates
from an oinit Certificate Authority (CA). The client integrates seamlessly with OpenSSH and supports
multiple authentication workflows.

## Commands

### `oinit add <host>[:port] [ca-url]`

Registers an ssh-host for oinit management. The CA URL can be auto-discovered via DNS or specified
manually.

**Examples:**

```bash
# Auto-discover CA via DNS
oinit add login.example.com

# Specify CA URL manually  
oinit add login.example.com:2222 https://ca.example.com:8443

# Add with custom port
oinit add compute.example.com:2222
```

### `oinit del <host>[:port]`

Removes a host from oinit management and cleans up stored certificates.

**Examples:**

```bash
oinit del login.example.com
oinit del compute.example.com:2222
```

### `oinit list`

Lists all hosts currently managed by oinit.

### `oinit match <host> <port>`

Internal command used by SSH via ProxyCommand to obtain certificates. Not typically run manually.

## DNS CA Discovery

When using `oinit add <host>` without specifying a CA URL, oinit automatically discovers the Certificate Authority via DNS TXT records.

### DNS Record Format

oinit looks for TXT records with the prefix `_oinit-ca.` containing the CA URL:

```dns
_oinit-ca.login.example.com.    IN    TXT    "https://ca.example.com:8443"
```

### Lookup Process

For a given SSH host (e.g., `login.example.com`), oinit performs the following DNS lookups:

1. **Full hostname**: `_oinit-ca.login.example.com`
2. **Parent domain** (if first lookup fails): `_oinit-ca.example.com`

### Wildcard Support

Wildcard domains are supported. For a wildcard host like `*.login.example.com`, oinit will:

1. Strip the wildcard: `login.example.com`
2. Lookup: `_oinit-ca.login.example.com`  
3. Fallback: `_oinit-ca.example.com`

### Examples

**Direct host lookup:**
```bash
# For host: login.example.com
# DNS query: _oinit-ca.login.example.com
# Fallback: _oinit-ca.example.com
oinit add login.example.com
```

**Wildcard host lookup:**
```bash
# For host: *.compute.example.com  
# DNS query: _oinit-ca.compute.example.com
# Fallback: _oinit-ca.example.com
oinit add "*.compute.example.com"
```

**DNS record setup example:**
```dns
; Direct host record
_oinit-ca.login.example.com.        IN  TXT  "https://ca.example.com:8443"

; Domain-wide record (fallback for all subdomains)
_oinit-ca.example.com.              IN  TXT  "https://ca.example.com:8443"
```

### Error Handling

If DNS lookup fails:
```
The CA for this host could not be determined from DNS.
You can manually specify the CA by running:
    oinit add hostname [ca-url]
```

## Access Token Discovery

oinit searches for access tokens in the following order, using the first token found:

### 1. Environment Variables

The following environment variables are checked (in order):

```bash
 ACCESS_TOKEN, BEARER_TOKEN, OIDC, OS_ACCESS_TOKEN, OIDC_ACCESS_TOKEN, WATTS_TOKEN, WATTSON_TOKEN
```

### 2. Custom Token File

Specify a custom file path containing the token:

```bash
export BEARER_TOKEN_FILE="/path/to/my-token.txt"
```

### 3. XDG Runtime Directory

Standard location following XDG Base Directory specification:

- Path: `$XDG_RUNTIME_DIR/bt_u$UID`
- Example: `/run/user/1000/bt_u1000`

### 4. Temporary Directory Fallback

Fallback location for systems without XDG support:

- Path: `/tmp/bt_u$UID`
- Example: `/tmp/bt_u1000`

### 5. oidc-agent Integration

If no token is found in files or environment variables, oinit will:

1. Check if `oidc-agent` is running
2. Query the CA for supported OIDC providers
3. Prompt you to select a provider
4. Automatically request a token from oidc-agent

**Environment Variables for oidc-agent:**

- `OIDC_AGENT_ACCOUNT`: Pre-select a specific oidc-agent account
- `OIDC_ISS` or `OIDC_ISSUER`: Pre-select a specific OIDC issuer, by the issuer URL

```bash
export OIDC_ISS="https://accounts.google.com
```

### 6. Manual Token Entry

As a last resort, oinit will prompt you to manually enter a token.


## Certificate Storage

`oinit` stores SSH certificates using different methods based on your environment:

### SSH Agent (Preferred)

When `ssh-agent` is running and it's not `gpg-agent`:

- Certificates are stored in memory
- Automatic expiry handling
- Seamless SSH integration

**Note:** gpg-agent does not support SSH certificates, so oinit automatically falls back to file storage.

### File Storage (Fallback)

When `ssh-agent` is not available or is gpg-agent:

- Private key: `~/.ssh/oinit_<host>_<port>`
- Certificate: `~/.ssh/oinit_<host>_<port>-cert.pub`
- Files are automatically managed and cleaned up when expired

## Configuration Files

oinit reads configuration from:

- **System-wide**: `/etc/ssh/oinit_hosts`
- **User-specific**: `~/.ssh/oinit_hosts`

The hosts file maps hostnames to CA URLs using a simple space-separated format:

``` bas
login.example.com:22 https://ca.example.com:8443
compute.example.com:2222 https://ca.example.com:8443
```

## SSH Integration

`oinit add host[:port] [ca-url]` automatically adds a `Match exec` block to your SSH config (`~/.ssh/config`):

```bash
Match exec "oinit match %h %p"
    User oinit
    IdentityFile ~/.ssh/oinit_%h_%p
    CertificateFile ~/.ssh/oinit_%h_%p-cert.pub
```

This ensures oinit is invoked for managed hosts and certificates are used correctly.

## Environment Variables

### Authentication Control

- `OIDC_AGENT_ACCOUNT`: Pre-select oidc-agent account
- `OIDC_ISS`, `OIDC_ISSUER`: Pre-select OIDC issuer
- `ACCESS_TOKEN`, `BEARER_TOKEN, OIDC, ...`: Provide token directly
- `BEARER_TOKEN_FILE`: Path to file containing token

### Debugging

- `OINIT_DEBUG`: Enable detailed debug logging


## Troubleshooting

### Common Issues

#### "gpg-agent does not support ssh-certificates"

- This is normal behavior - oinit automatically uses file storage instead
- Your certificates will be saved to `~/.ssh/oinit_*` files

#### "Could not contact CA"

- Verify the CA URL is correct and accessible
- Check network connectivity and firewall settings
- Ensure the CA server is running

#### "Token expired" or authentication errors

- Refresh your oidc-agent token: `oidc-token <account>`
- Check token validity: `oidc-token --time <account>`
- Verify you have access to the requested host

#### Certificate not being used

- Check SSH config has the oinit Match block
- Verify `IdentitiesOnly yes` is set
- Check certificate hasn't expired: `ssh-keygen -L -f ~/.ssh/oinit_host_port-cert.pub`

### Debug Mode

Enable debug logging to see detailed token discovery and certificate management:

```bash
export OINIT_DEBUG=1
oinit match login.example.com 22
```

Debug output shows:

- Token search locations and results
- Certificate validation and storage decisions
- SSH agent integration status
- File operations and paths

## Security Considerations

- Tokens and private keys are handled securely in memory
- Certificate files use appropriate permissions (600 for private keys, 644 for certificates)
- Expired certificates are automatically detected and replaced
- No sensitive information is logged unless debug mode is enabled
