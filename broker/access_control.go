//go:build !darwin && !windows
// +build !darwin,!windows

package broker

import (
	"fmt"
	"net"
	"syscall"
)

// PeerCreds holds peer process credentials extracted from a Unix socket connection.
type PeerCreds struct {
	UID uint32
	GID uint32
	PID uint32
}

// GetPeerCreds retrieves the UID, GID, and PID of the process connecting via a Unix socket.
// Returns nil if the connection is not a Unix socket or credentials cannot be retrieved.
func GetPeerCreds(conn net.Conn) *PeerCreds {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}

	f, err := unixConn.File()
	if err != nil {
		return nil
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return nil
	}

	return &PeerCreds{
		UID: cred.Uid,
		GID: cred.Gid,
		PID: uint32(cred.Pid),
	}
}

// CheckAccessControl verifies whether the peer should be allowed based on UID/GID whitelist.
// If allowedUIDs is empty, any UID is allowed. Same for GID.
// If both lists are non-empty, the peer must match at least one of each list.
func CheckAccessControl(creds *PeerCreds, allowedUIDs, allowedGIDs []uint32) error {
	if creds == nil {
		// No credentials available (e.g., Windows named pipe, loopback TCP)
		// Allow unless access control is explicitly required
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
