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

## CA Discovery

When using `oinit add <host>` without specifying a CA URL, oinit automatically discovers the Certificate Authority using a two-phase discovery process:

1. **DNS TXT Record Discovery** (preferred)
2. **HTTPS Endpoint Discovery** (fallback)

### Phase 1: DNS TXT Record Discovery

oinit looks for TXT records with the prefix `_oinit-ca.` containing the CA URL.

#### DNS Record Format

```dns
_oinit-ca.login.example.com.    IN    TXT    "https://ca.example.com:8443"
```

#### Two-Level Lookup Strategy

For any given SSH hostname, oinit performs **exactly two DNS lookups**:

1. **Full hostname lookup**: Query `_oinit-ca.<hostname>`
2. **Parent domain lookup**: Query `_oinit-ca.<parent-domain>` (one subdomain level up)

This two-level strategy allows both host-specific CA assignments and organization-wide defaults.

#### Lookup Examples

**Example 1: Simple hostname**
```bash
oinit add login.example.com

# Lookup sequence:
# 1. _oinit-ca.login.example.com     (host-specific)
# 2. _oinit-ca.example.com           (domain-wide fallback)
```

**Example 2: Nested subdomain**
```bash
oinit add node1.cluster.example.com

# Lookup sequence:
# 1. _oinit-ca.node1.cluster.example.com     (host-specific)
# 2. _oinit-ca.cluster.example.com           (one level up)
```

**Example 3: Wildcard hostname**
```bash
oinit add "*.compute.example.com"

# Wildcard prefix stripped first: compute.example.com
# Lookup sequence:
# 1. _oinit-ca.compute.example.com   (host-specific)
# 2. _oinit-ca.example.com           (domain-wide fallback)
```

#### DNS Record Setup Examples

**Host-specific CA assignment:**
```dns
; Specific host uses dedicated CA
_oinit-ca.secure.example.com.       IN  TXT  "https://secure-ca.example.com:8443"

; Other hosts use organization CA
_oinit-ca.example.com.              IN  TXT  "https://ca.example.com:8443"
```

**Department-level CA assignment:**
```dns
; Finance department has dedicated CA
_oinit-ca.finance.example.com.      IN  TXT  "https://finance-ca.example.com:8443"

; Engineering uses different CA
_oinit-ca.eng.example.com.          IN  TXT  "https://eng-ca.example.com:8443"

; Organization-wide fallback
_oinit-ca.example.com.              IN  TXT  "https://ca.example.com:8443"
```

### Phase 2: HTTPS Endpoint Discovery (Fallback)

If both DNS TXT lookups fail, oinit attempts to discover the CA by probing HTTPS endpoints directly.

#### Discovery Process

oinit makes HTTPS requests to the `/oinit/` endpoint on port 443 for:

1. **Full hostname**: `https://<hostname>:443/oinit/`
2. **Parent domain**: `https://<parent-domain>:443/oinit/` (one level up)

If either endpoint responds with a valid oinit-ca server response, that hostname is used as the CA base URL.

#### HTTPS Probe Examples

**Example 1: CA running on SSH host itself**
```bash
oinit add login.example.com

# After DNS TXT lookups fail:
# 1. HTTPS probe: https://login.example.com:443/oinit/
#    ✓ SUCCESS - CA is running on login.example.com itself
#    → Use: https://login.example.com
```

**Example 2: CA running on parent domain**
```bash
oinit add node1.cluster.example.com

# After DNS TXT lookups fail:
# 1. HTTPS probe: https://node1.cluster.example.com:443/oinit/
#    ✗ FAIL - not an oinit-ca server
# 2. HTTPS probe: https://cluster.example.com:443/oinit/
#    ✓ SUCCESS - CA found on parent domain
#    → Use: https://cluster.example.com
```

#### When to Use HTTPS Discovery

HTTPS discovery is useful when:
- DNS TXT records cannot be configured (limited DNS access)
- Rapid prototyping or development environments
- The CA server runs on the SSH host itself
- Small deployments where DNS management is overhead

**Note:** DNS TXT records are still the **recommended** approach for production because:
- Explicit CA assignment is clearer and more maintainable
- DNS records are cached by resolvers (better performance)
- Allows CA and SSH hosts to be completely separate
- HTTPS probes add latency and require network connectivity

### Complete Discovery Flow

For any hostname, the full discovery sequence is:

```
Input: login.example.com

1. DNS TXT: _oinit-ca.login.example.com
   ├─ Found? → Return CA URL ✓
   └─ Not found → Continue

2. DNS TXT: _oinit-ca.example.com
   ├─ Found? → Return CA URL ✓
   └─ Not found → Continue

3. HTTPS: https://login.example.com:443/oinit/
   ├─ Valid response? → Return https://login.example.com ✓
   └─ Failed → Continue

4. HTTPS: https://example.com:443/oinit/
   ├─ Valid response? → Return https://example.com ✓
   └─ Failed → Error: CA not found ✗
```

### Caching

Discovery results are cached to minimize overhead:
- **Successful lookups**: Cached for 5 minutes
- **Failed lookups**: Cached for 1 minute

Caching applies to the entire discovery process, not individual methods.

### Error Handling

If all discovery methods fail:
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
