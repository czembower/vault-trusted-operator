# Vault Trusted Operator

A lightweight service that brokers HashiCorp Vault authentication for local host processes, injecting valid Vault tokens via a Unix socket (or Windows named pipe) without exposing credentials to those processes.

## Overview

**Problem:** Host applications need Vault tokens, but managing credentials (Role IDs, Secret IDs) securely across multiple processes is complex.

**Solution:** `vault-trusted-operator` runs as a privileged service that:
- Bootstraps via manual operator authentication (OIDC only) to set a host-scoped AppRole credential
- Authenticates as the configured AppRole entity, resulting in a Vault token for the host
- Manages Vault token lifecycle automatically (renewal, proactive refresh)
- Maintains a short-lived (1 minute) AppRole Secret ID in memory, treated as single-use in all cases
- Transparently injects Vault tokens into requests bound for Vault via a reverse proxy (`/v1/` endpoints)
- Requests a wrapped AppRole Secret ID at shutdown, storing this credential on the host for subsequent use
- Encrypts a "state file" that stores both the persisted credential and the host-specific configuration
- Transparently retries upstream Vault requests

This pattern allows applications running on systems without inherent machine identity to establish a durable and well-protected credential.

## Key Features

### Token Management
- **Automatic Renewal**: Watches token TTL and renews before expiration
- **Proactive Refresh for Batch Tokens**: Non-renewable tokens are refreshed at 2/3 TTL by requesting new authentication
- **Single-Use Secret ID Coordination**: Keeps fresh in-memory Secret IDs available for re-authentication if token renewal fails

### Secure Credential Storage
- **Sealed State**: Credentials and configuration are encrypted at rest using OS keystore (TPM for Linux, DPAPI for Windows, or file-based fallback)
- **No Secrets in Logs**: Credentials and secrets are never logged

### Access Control
- **Process-Level Restrictions**: Whitelist which user/group IDs can access the broker via socket (Linux only)

### Performance
- **Minimal Proxy Overhead**: HTTP reverse proxy with optimized connection pooling
- **Bounded Response Reading**: Prevents resource leaks from large responses
- **Lock-Free Credential Snapshots**: Copy-on-write pattern for credential updates

## Architecture

```
┌─────────────────────────────┐
│  Host Process (unprivileged)│
└────────────┬────────────────┘
             │
        Unix Socket (0600)
        Access controlled
        (or plain HTTP)
             │
             ▼
┌─────────────────────────────────┐
│ vault-trusted-operator          │
│ ┌───────────────────────────────┤
│ │ HTTP Broker                   │
│ │ ├─ /health                    │
│ │ ├─ /token (Vault token status)│
│ │ ├─ /v1/* (reverse proxy)      │
│ │ └─ /v1/echo (debug)           │
│ │                               │
│ │ AuthManager                   │
│ │ ├─ Token lifecycle            │
│ │ ├─ Proactive reauth           │
│ │ └─ Secret ID refresh          │
│ │                               │
│ │ CredStore                     │
│ │ ├─ Role ID                    │
│ │ ├─ Wrapped Secret ID token    │
│ │ └─ In-memory Secret ID        │
│ └───────────────────────────────┤
└────────────┬────────────────────┘
             │
           HTTP(S)
             │
             ▼
  ┌──────────────────────┐
  │  HashiCorp Vault     │
  │  AppRole Auth Method │
  └──────────────────────┘
```

## Configuration
Command-line flags (or environment variables) are used for bootstrap. After the first run, only the path to the encrypted state file needs to be supplied as an argument.
Configuration can be adjusted via a privileged operator using the `-reconfigure` flag.

### Options

**Socket/Pipe (Local, Default):**
```bash
-socket-path string
    Unix socket path (non-Windows) for broker/proxy service (default "./socket.sock")
-socket-mode uint
    Unix socket file mode (default 0600)
-pipe-path string
    Windows named pipe name (default "./pipe")
```

**HTTP Listener (Loopback Only, Optional):**
```bash
-http-addr string
    HTTP loopback address:port (e.g., 127.0.0.1:8080, localhost:9090); empty = use socket/pipe (env: BROKER_HTTP_ADDR)
    Note: Plain HTTP, restricted to localhost only - not suitable for remote access
```

**Access Control (Linux only):**
```bash
-allowed-uids string
    Comma-separated list of allowed user IDs (e.g., 1000,1001, env: BROKER_ALLOWED_UIDS)
-allowed-gids string
    Comma-separated list of allowed group IDs (e.g., 100,101, env: BROKER_ALLOWED_GIDS)
```

**AppRole & Vault:**
```bash
-approle-mount string
    AppRole auth mount path (default "auth/approle", env: APPROLE_MOUNT)
-approle-role string
    AppRole role name (env: APPROLE_ROLE, required)
-vault-addrs string
    Comma-separated Vault addresses (default "https://localhost:8200", env: VAULT_ADDRS)
-namespace string
    Vault namespace (env: VAULT_NAMESPACE)
-insecure-tls
    Skip TLS verification (env: VAULT_SKIP_VERIFY, not recommended)
```

**State & Encryption:**
```bash
-state-file string
    Path to sealed state file (default "./state.json", env: STATE_FILE)
-state-key-file string
    Path to file keystore key (env: STATE_KEY_FILE)
-keystore string
    Keystore backend: auto|file|dpapi (default "auto", env: KEYSTORE)
-reconfigure
    Force initial configuration (env: RECONFIGURE)
```

**OIDC (Optional Fallback):**
```bash
-oidc-mount string
    OIDC auth mount name (default "oidc", env: OIDC_MOUNT)
-oidc-role string
    OIDC role name (default "default_role", env: OIDC_ROLE)
-oidc-redirect-uri string
    OIDC callback URI (env: OIDC_REDIRECT_URI)
```

**Other:**
```bash
-debug
    Print verbose debugging logs (env: DEBUG)
-wrap-ttl string
    Secret ID wrapping TTL (default "24h", env: WRAP_TTL)
```

### Systemd Service

```ini
[Unit]
Description=Vault Trusted Operator
After=network.target

[Service]
Type=simple
User=vault-operator
ExecStart=/usr/local/bin/vault-trusted-operator \
  -state-file /etc/vault-operator/state.json \
  -socket-path /run/vault-broker.sock
Restart=on-failure
StandardOutput=journal
StandardError=journal
SocketGroup=vault-clients
SocketMode=0660

[Install]
WantedBy=multi-user.target
```

