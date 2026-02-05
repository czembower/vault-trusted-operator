package broker

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"
	"vault-trusted-operator/authmanager"
)

// Config controls the local endpoint and behavior.
type Config struct {
	// Non-Windows: Unix socket path (e.g., /run/vault-broker.sock)
	SocketPath string
	SocketMode uint32 // e.g., 0660 (only used on non-Windows)

	// Windows: named pipe path (e.g., \\.\pipe\vault-broker)
	PipeName string

	ReadHeaderTimeout time.Duration
	ShutdownTimeout   time.Duration

	VaultAddress    string
	VaultNamespace  string
	VaultSkipVerify bool
	Logger          *log.Logger

	// Access control: allowed peer process UIDs and GIDs
	AllowedUIDs []uint32
	AllowedGIDs []uint32
}

// Provider hides OS/build-specific listener creation.
type Provider interface {
	Listen(cfg Config) (net.Listener, error)
	DescribeEndpoint(cfg Config) string
}

func DefaultConfig() Config {
	return Config{
		SocketPath:        "/run/vault-broker.sock",
		SocketMode:        0o660,
		PipeName:          `\\.\pipe\vault-broker`,
		ReadHeaderTimeout: 5 * time.Second,
		ShutdownTimeout:   5 * time.Second,
	}
}

// Run starts the broker server on the OS-appropriate local transport.
// The Provider implementation is chosen by build tags via DefaultProvider().
func Run(ctx context.Context, cfg Config, t *authmanager.TokenProvider) error {
	p := DefaultProvider()

	ln, err := p.Listen(cfg)
	if err != nil {
		return err
	}
	defer ln.Close()

	srv := NewServer(cfg, t)

	cfg.Logger.Printf("broker: listening on %s", p.DescribeEndpoint(cfg))
	return srv.Serve(ctx, ln)
}

func NewServer(cfg Config, t *authmanager.TokenProvider) *Server {
	mux := http.NewServeMux()
	s := &Server{
		Mux: mux,
		HTTP: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		},
		ShutdownTimeout: cfg.ShutdownTimeout,
		AllowedUIDs:     cfg.AllowedUIDs,
		AllowedGIDs:     cfg.AllowedGIDs,
		start:           time.Now(),
	}
	s.routes(cfg, t)

	cfg.Logger.Printf("broker: new server started")
	return s
}
