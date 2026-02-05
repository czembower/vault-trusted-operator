//go:build darwin
// +build darwin

package broker

import (
	"fmt"
	"net"
)

// PeerCreds holds peer process credentials extracted from a Unix socket connection.
type PeerCreds struct {
	UID uint32
	GID uint32
	PID uint32
}

// GetPeerCreds retrieves peer credentials from a Unix socket connection.
// On macOS, SO_PEERCRED is not available, so we return nil.
// Access control via UID/GID is not supported on macOS.
func GetPeerCreds(conn net.Conn) *PeerCreds {
	// macOS doesn't support SO_PEERCRED; peer credential checking is not available
	return nil
}

// CheckAccessControl verifies whether the peer should be allowed based on UID/GID whitelist.
// On macOS, this is a no-op since credentials cannot be extracted.
func CheckAccessControl(creds *PeerCreds, allowedUIDs, allowedGIDs []uint32) error {
	// If creds are nil (which they will be on macOS), allow the connection
	if creds == nil {
		if len(allowedUIDs) > 0 || len(allowedGIDs) > 0 {
			return fmt.Errorf("access control requires peer credentials, which are not available on macOS")
		}
		return nil
	}

	// If UID whitelist exists, peer must be in it
	if len(allowedUIDs) > 0 {
		found := false
		for _, uid := range allowedUIDs {
			if creds.UID == uid {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("peer UID %d not in allowed list", creds.UID)
		}
	}

	// If GID whitelist exists, peer must be in it
	if len(allowedGIDs) > 0 {
		found := false
		for _, gid := range allowedGIDs {
			if creds.GID == gid {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("peer GID %d not in allowed list", creds.GID)
		}
	}

	return nil
}
