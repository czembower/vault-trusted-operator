//go:build windows
// +build windows

package broker

import (
	"fmt"
	"net"
)

// PeerCreds holds peer process credentials extracted from a named pipe connection.
type PeerCreds struct {
	UID uint32
	GID uint32
	PID uint32
}

// GetPeerCreds retrieves peer credentials from a named pipe connection.
// On Windows, named pipes don't directly expose UID/GID, so we return nil.
// Access control via UID/GID is not supported on Windows.
func GetPeerCreds(conn net.Conn) *PeerCreds {
	// Windows named pipes don't support peer credential extraction in the same way
	return nil
}

// CheckAccessControl verifies whether the peer should be allowed based on UID/GID whitelist.
// On Windows, this is a no-op since UID/GID don't apply.
func CheckAccessControl(creds *PeerCreds, allowedUIDs, allowedGIDs []uint32) error {
	// If creds are nil (which they will be on Windows), allow the connection
	if creds == nil {
		if len(allowedUIDs) > 0 || len(allowedGIDs) > 0 {
			return fmt.Errorf("access control via UID/GID is not supported on Windows")
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
