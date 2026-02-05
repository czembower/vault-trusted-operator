# Broker Access Control

The vault-trusted-operator broker now supports process-level access control to restrict which host processes can connect to the token service.

## Configuration

Access control is configured via command-line flags or environment variables:

**Flags:**
- `-allowed-uids`: Comma-separated list of allowed user IDs (e.g., `-allowed-uids=1000,1001`)
- `-allowed-gids`: Comma-separated list of allowed group IDs (e.g., `-allowed-gids=1000`)

**Environment Variables:**
- `BROKER_ALLOWED_UIDS`: Comma-separated list of allowed user IDs
- `BROKER_ALLOWED_GIDS`: Comma-separated list of allowed group IDs

Flags override environment variables.

### Example Usage

Allow only processes running as UID 1000 to connect to the broker:
```bash
vault-trusted-operator -allowed-uids=1000
```

Or via environment variable:
```bash
export BROKER_ALLOWED_UIDS=1000
vault-trusted-operator
```

Allow processes in group 1000 or 1001:
```bash
vault-trusted-operator -allowed-gids=1000,1001
```

Combine UID and GID restrictions (peer must match both lists):
```bash
vault-trusted-operator -allowed-uids=1000 -allowed-gids=100
```

## How It Works

### Connection Flow
1. When a local process connects to the broker's Unix socket, the operating system associates the connection with the peer process's credentials.
2. At the **listener level** (before HTTP processing), the `accessControlListener` extracts the peer's UID and GID.
3. The credentials are validated against the configured whitelist using `CheckAccessControl()`.
4. If validation fails, the connection is immediately closed with an error.
5. If validation succeeds (or no access control is configured), the connection proceeds to HTTP request handling.

### Platform Support

| Platform | Support | Notes |
|----------|---------|-------|
| **Linux** | Full | SO_PEERCRED provides UID, GID, and PID |
| **macOS** | No | SO_PEERCRED is not available; access control disabled |
| **Windows** | No | Named pipes don't support UID/GID; access control disabled |

On platforms without peer credential support (macOS, Windows):
- If no access control is configured, connections are allowed normally
- If access control lists are populated, an error is logged and returned

### Security Benefits

1. **Process Isolation**: Only specified processes can call the broker endpoints
2. **Early Rejection**: Access checks happen at the socket layer, before HTTP request parsing
3. **No Token Leakage**: Rejected connections never reach the token endpoint
4. **Audit Trail**: Access denials are logged with peer UID/GID for investigation

## Implementation Details

### Files Added/Modified

- `broker/access_control.go`: Platform-specific credential extraction (Linux)
- `broker/access_control_darwin.go`: macOS stub (no peer credentials)
- `broker/access_control_windows.go`: Windows stub (no peer credentials)
- `broker/server.go`: `accessControlListener` wraps the socket listener
- `broker/broker.go`: Pass access control lists through Server config
- `config/config.go`: Configuration parsing for `AllowedUIDs` and `AllowedGIDs`
- `main.go`: Wire access control configuration to broker

### Key Functions

#### `GetPeerCreds(conn net.Conn) *PeerCreds`
Extracts UID, GID, and PID from a Unix socket connection. Returns `nil` on non-Unix sockets or platforms without peer credential support.

#### `CheckAccessControl(creds, allowedUIDs, allowedGIDs) error`
Validates peer credentials against configured whitelists:
- Empty lists = no restriction
- If `allowedUIDs` is non-empty, peer's UID must be in the list
- If `allowedGIDs` is non-empty, peer's GID must be in the list

#### `accessControlListener.Accept()`
Wraps the base listener, validates credentials on each new connection, and closes unauthorized connections immediately.

## Examples

### Restrict to a Single User
```bash
# Allow only processes running as www-data (UID 33)
export BROKER_ALLOWED_UIDS=33
vault-trusted-operator
```

### Restrict to Multiple Services
```bash
# Allow only processes in the 'vault-clients' group (GID 1050)
export BROKER_ALLOWED_GIDS=1050
vault-trusted-operator
```

### Verify Access Logs
When a peer is denied access:
```
broker: access denied - peer UID 1001 not in allowed list (UID=1001, GID=1000)
```

## Testing

```bash
# Start the broker with UID restriction (only UID 1000 allowed)
export BROKER_ALLOWED_UIDS=1000
vault-trusted-operator

# From a shell running as UID 1000 (should succeed)
curl --unix-socket ./socket.sock http://localhost/token

# From a shell running as different UID (should fail with 403 Forbidden or immediate connection error)
sudo -u nobody curl --unix-socket ./socket.sock http://localhost/token
# Error: Permission denied or connection refused
```

## Notes

- Access control is **optional**; omit these environment variables to allow all connections
- Access checks are performed at the **socket layer**, making them very efficient
- For maximum security, set restrictive socket permissions (`-socket-mode 0600`) in addition to peer credential checking
- On systems without peer credential support, the broker logs a warning if access control lists are configured
