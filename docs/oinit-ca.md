## oinit-ca

### Overview

`oinit-ca` is the Certificate Authority (CA) server component of the oinit
system. It is an SSH certificate authority that issues short-lived
SSH certificates to users who authenticate with OpenID Connect (OIDC)
tokens. The server integrates with motley_cue for user authentication and
authorisation.

### Architecture

The oinit-ca server:

- Exposes a REST API for certificate operations
- Maintains SSH CA key pairs (separate for host and user certificates)
- Validates OIDC tokens through `motley_cue`
- Issues time-limited SSH certificates
- Supports multiple host groups with different CA keys and policies

### Installation

#### Prerequisites

- Access to a motley_cue instance for OIDC token validation
- SSH CA key pairs (can be generated with `ssh-keygen`)

#### Packages

```bash
apt install oinit-ca
```

#### Sources

```bash
make 
# Binaries will be in bin/*
```

### Configuration

#### Configuration File Format

The server uses an INI-format configuration file with:

- Global defaults section
- Host group sections for different sets of hosts

Example configuration (`/etc/oinit-ca/config.ini`):

```ini
# Global defaults - can be overridden per host group
host-ca-privkey = /etc/oinit-ca/host-ca
host-ca-pubkey  = /etc/oinit-ca/host-ca.pub
user-ca-privkey = /etc/oinit-ca/user-ca
user-ca-pubkey  = /etc/oinit-ca/user-ca.pub

# Certificate validity: "token" or seconds (e.g., 3600 = 1 hour)
# cert-validity = token
# 
# Fixed certificate validity of 8 hours
cert-validity = 28800

# Fallback certificate validity, in case the token does not contain an
# `exp`iry claim (e.g. google)
cert-validity-fallback = 1000

# How long to cache motley_cue responses (seconds)
cache-duration = 600

# Host group for example.com domain
[example.com]
# Map hosts to their motley_cue endpoints
login.example.com = https://login.example.com:8443
compute.example.com = https://login.example.com:8443

# Wildcard matching is supported
*.dev.example.com = https://dev-login.example.com:8443

# Override CA keys for this group (optional)
#user-ca-privkey = /etc/oinit-ca/example-user-ca
#user-ca-pubkey  = /etc/oinit-ca/example-user-ca.pub

# Another host group with different settings
[university.edu]
hpc.university.edu = https://auth.university.edu:8080
*.lab.university.edu = https://auth.university.edu:8080
```

#### Key Configuration Options

- **host-ca-privkey/pubkey**: SSH CA keys for signing host certificates (not currently used)
- **user-ca-privkey/pubkey**: SSH CA keys for signing user certificates
- **cert-validity**: Certificate lifetime
  - `token`: Inherit from OIDC token expiration
  - Number: Fixed duration in seconds
- **cache-duration**: How long to cache motley_cue user info responses

#### Generating CA Keys

```bash
# Generate user CA key pair
ssh-keygen -t ed25519 -f /etc/oinit-ca/user-ca -C "oinit User CA"

# Generate host CA key pair (for future use)
ssh-keygen -t ed25519 -f /etc/oinit-ca/host-ca -C "oinit Host CA"

# Set appropriate permissions
chmod 600 /etc/oinit-ca/*-ca
chmod 644 /etc/oinit-ca/*.pub
```

### Running the Server

#### Command Line

```bash
oinit-ca -c <path/to/config> [-l <host:port>]

# Example
oinit-ca -c /etc/oinit-ca/config.ini -l 0.0.0.0:8443 
```

#### Systemd Service

```ini
[Unit]
Description=oinit Certificate Authority
After=network.target

[Service]
Type=simple
User=oinit
ExecStart=/usr/local/bin/oinit-ca -c /etc/oinit-ca/config.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

#### Docker Compose

```yaml
version: '3'
services:
  oinit-ca:
    image: oinit-ca
    ports:
      - "8443:8443"
    volumes:
      - ./config.ini:/etc/oinit-ca/config.ini:ro
      - ./keys:/etc/oinit-ca/keys:ro
    command: ["-c", "/etc/oinit-ca/config.ini"]
```


### SSH-Certificate Details

For taking a look into the generated certificates of oinit, simply
- Make sure ssh-agent is not being used: `unset SSH_AUTH_SOCK; unset
    SSH_AGENT_PID`
- Use ssh with oinit
- Look at the certificate details with

```bash
ssh-keygen -L -f ~/.ssh/oinit_${HOST}_${PORT}-cert.pub
```

#### SSH-Certificate Properties

Generated certificates include:

- **Type**: User certificate
- **Key ID**: `oinit@hostname` (for identification in logs)
- **Principals**: `oinit` and the username from motley_cue
- **Validity**: Based on configuration (token expiry or fixed duration)
- **Critical Options**: `force-command` set to `oinit-switch <username>`
- **Extensions**: Standard SSH permissions (agent forwarding, port forwarding, etc.)

#### Security Features

- Certificates are tied to specific hosts via the Key ID
- Force command ensures users can only run oinit-switch
- Short validity periods limit exposure
- Each certificate has a unique public key

### Integration with motley_cue

The CA server relies on motley_cue for:

1. **Token Validation**: Verifying OIDC tokens are valid and not expired
2. **User Information**: Getting the local username for the certificate
3. **Authorization**: Ensuring users are in "deployed" state
4. **Provider Discovery**: Learning which OIDC providers are supported

### Monitoring and Logs

The server logs:

- API requests with timestamps
- Certificate issuance with fingerprints and validity periods
- Errors from motley_cue communication
- Configuration loading issues

Example log entry:

```bash
[API] 2024/01/15 - 14:23:45 Issued certificate 'SHA256:AbC123...' valid until '2024-01-15 18:23:45 +0000 UTC'
```

### Security Considerations

1. **CA Key Protection**: Keep CA private keys secure and limit access
2. **Network Security**: Use HTTPS/TLS for the API endpoint in production
3. **Token Validation**: The CA doesn't validate tokens directly - it trusts motley_cue
4. **Host Verification**: Ensure motley_cue endpoints in config are correct
5. **Certificate Scope**: Certificates are only valid for the specific host requested

### Troubleshooting

#### Common Issues

1. **"motley_cue is not reachable"**
   - Check the motley_cue URL in configuration
   - Verify network connectivity
   - Check motley_cue service status

2. **"User is not authorized or suspended"**
   - Token may be expired
   - User account may be suspended in motley_cue
   - Token may not have required scopes

3. **"Unknown host"**
   - Host is not configured in any host group
   - Check configuration file for typos
   - Verify wildcard patterns match correctly

4. **Certificate not accepted by SSH server**
   - Ensure SSH server trusts the CA public key
   - Check certificate validity period
   - Verify principals match SSH configuration

#### Debugging

Enable debug logging by setting Gin mode:

```bash
export GIN_MODE=debug
oinit-ca 0.0.0.0:8443 /etc/oinit-ca/config.ini
```
