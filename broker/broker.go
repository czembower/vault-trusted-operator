package broker

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"
	"vault-trusted-operator/authmanager"
)

// Config controls the local endpoint and behavior.
type Config struct {
	// Local Unix socket / Windows named pipe
	SocketPath string
	SocketMode uint32 // e.g., 0660 (only used on non-Windows)
	PipeName   string

	// HTTP listener on loopback (alternative to socket/pipe)
	HTTPAddr string // e.g., "127.0.0.1:8080" (empty = disabled)

	ReadHeaderTimeout time.Duration
	ShutdownTimeout   time.Duration

	VaultAddress    string
	VaultNamespace  string
	VaultSkipVerify bool
	Logger          *log.Logger
	Debug           bool

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

// Run starts the broker server on the OS-appropriate local transport or HTTP loopback.
// If HTTPAddr is configured, starts HTTP listener on loopback; otherwise uses socket/pipe via Provider.
func Run(ctx context.Context, cfg Config, t *authmanager.TokenProvider) error {
	srv := NewServer(cfg, t)

	if cfg.HTTPAddr != "" {
		// HTTP loopback mode (localhost only, not for remote access)
		cfg.Logger.Printf("INFO: broker: starting HTTP listener on %s (loopback only)", cfg.HTTPAddr)
		return srv.ServeHTTP(ctx, cfg.HTTPAddr)
	}

	// Socket/pipe mode (default)
	p := DefaultProvider()
	ln, err := p.Listen(cfg)
	if err != nil {
		return err
	}
	defer ln.Close()

	cfg.Logger.Printf("INFO: broker: listening on %s", p.DescribeEndpoint(cfg))
	return srv.Serve(ctx, ln)
}

func NewServer(cfg Config, t *authmanager.TokenProvider) *Server {
	mux := http.NewServeMux()

	// Create HTTP client for upstream health checks (shared transport, reasonable timeouts)
	upstreamClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: cfg.VaultSkipVerify,
			},
		},
	}

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
		upstreamClient:  upstreamClient,
		upstreamAddr:    cfg.VaultAddress,
	}
	s.routes(cfg, t)

	cfg.Logger.Printf("INFO: broker: new server started")
	return s
}
