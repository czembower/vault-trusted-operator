//go:build !windows

package broker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type unixProvider struct{}

func DefaultProvider() Provider { return unixProvider{} }

func (unixProvider) DescribeEndpoint(cfg Config) string {
	return fmt.Sprintf("unix://%s", cfg.SocketPath)
}

func (unixProvider) Listen(cfg Config) (net.Listener, error) {
	path := cfg.SocketPath
	if path == "" {
		return nil, fmt.Errorf("SocketPath is empty")
	}
	mode := os.FileMode(cfg.SocketMode)
	if mode == 0 {
		mode = 0o660
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}

	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}

	return ln, nil
}
