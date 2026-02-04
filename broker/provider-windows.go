//go:build windows

package broker

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

type windowsProvider struct{}

func DefaultProvider() Provider { return windowsProvider{} }

func (windowsProvider) DescribeEndpoint(cfg Config) string {
	return fmt.Sprintf("npipe://%s", cfg.PipeName)
}

func (windowsProvider) Listen(cfg Config) (net.Listener, error) {
	name := cfg.PipeName
	if name == "" {
		return nil, fmt.Errorf("PipeName is empty")
	}

	// NOTE: This uses default security settings for now.
	// Next step: provide an explicit security descriptor to restrict allowed SIDs.
	ln, err := winio.ListenPipe(name, nil)
	if err != nil {
		return nil, fmt.Errorf("listen pipe: %w", err)
	}
	return ln, nil
}
