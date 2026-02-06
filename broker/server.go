package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
	"vault-trusted-operator/authmanager"
)

type Server struct {
	HTTP            *http.Server
	Mux             *http.ServeMux
	ShutdownTimeout time.Duration
	AllowedUIDs     []uint32
	AllowedGIDs     []uint32
	start           time.Time
	upstreamClient  *http.Client
	upstreamAddr    string
}

type HealthStatus struct {
	Healthy     bool   `json:"ok"`
	UptimeSec   int64  `json:"uptime_sec"`
	Token       string `json:"token"`
	UpstreamOk  bool   `json:"upstream_ok"`
	UpstreamMsg string `json:"upstream_msg,omitempty"`
}

func (s *Server) routes(cfg Config, t *authmanager.TokenProvider) {
	vaultProxy, err := NewVaultReverseProxy(cfg, t)
	if err != nil {
		cfg.Logger.Printf("ERROR: broker: error configuring proxy")
	}

	s.Mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Debug {
			cfg.Logger.Printf("DEBUG: broker health check: %s %s", r.Method, r.URL.Path)
		}
		uptime := int64(time.Since(s.start).Seconds())
		upstreamOk, upstreamMsg := s.checkUpstreamHealth(r.Context())
		writeJSON(w, http.StatusOK, HealthStatus{
			Token:       authmanager.TokenPrefix(t.GetToken()),
			UptimeSec:   uptime,
			Healthy:     true,
			UpstreamOk:  upstreamOk,
			UpstreamMsg: upstreamMsg,
		})
	})

	// Wrap proxy with debug logging if enabled
	var proxyHandler http.Handler = vaultProxy
	if cfg.Debug {
		proxyHandler = debugProxyHandler(cfg.Logger, vaultProxy)
	}
	s.Mux.Handle("/v1/", proxyHandler)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// Wrap listener with access control if needed
	if len(s.AllowedUIDs) > 0 || len(s.AllowedGIDs) > 0 {
		ln = &accessControlListener{
			Listener:    ln,
			allowedUIDs: s.AllowedUIDs,
			allowedGIDs: s.AllowedGIDs,
		}
	}

	errc := make(chan error, 1)
	go func() { errc <- s.HTTP.Serve(ln) }()

	select {
	case <-ctx.Done():
		to := s.ShutdownTimeout
		if to <= 0 {
			to = 5 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		_ = s.HTTP.Shutdown(shutdownCtx)
		return ctx.Err()

	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ServeHTTP starts the HTTP server on the specified loopback address.
func (s *Server) ServeHTTP(ctx context.Context, addr string) error {
	s.HTTP.Addr = addr
	errc := make(chan error, 1)
	go func() {
		errc <- s.HTTP.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		to := s.ShutdownTimeout
		if to <= 0 {
			to = 5 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		_ = s.HTTP.Shutdown(shutdownCtx)
		return ctx.Err()

	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// accessControlListener wraps a listener and enforces access control at connection time.
type accessControlListener struct {
	net.Listener
	allowedUIDs []uint32
	allowedGIDs []uint32
}

// Accept accepts a connection and validates peer credentials if access control is configured.
func (acl *accessControlListener) Accept() (net.Conn, error) {
	conn, err := acl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Try to get peer credentials (only works for Unix sockets on Linux)
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// Not a Unix socket; allow (Windows named pipe or loopback TCP)
		return conn, nil
	}

	creds := GetPeerCreds(unixConn)
	if creds == nil {
		// No credentials available; allow (platform doesn't support peer credentials)
		return conn, nil
	}

	// Validate credentials against allow list
	if err := CheckAccessControl(creds, acl.allowedUIDs, acl.allowedGIDs); err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer access denied: %w", err)
	}

	return conn, nil
}

// checkUpstreamHealth probes the upstream Vault server's health endpoint
func (s *Server) checkUpstreamHealth(ctx context.Context) (bool, string) {
	if s.upstreamClient == nil || s.upstreamAddr == "" {
		return false, "upstream client not configured"
	}

	// Create a health check request with the current timeout
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstreamAddr+"/v1/sys/health", nil)
	if err != nil {
		return false, "failed to create health request"
	}

	resp, err := s.upstreamClient.Do(req)
	if err != nil {
		return false, fmt.Sprintf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	switch resp.StatusCode {
	case http.StatusOK:
		return true, "healthy primary"
	case 429:
		return true, "standby server"
	case 472:
		return false, "dr secondary"
	case 473:
		return true, "performance replication secondary"
	case 474:
		return false, "primary node not found"
	case 501:
		return false, "vault uninitialized"
	case 503:
		return false, "vault sealed"
	default:
		return false, fmt.Sprintf("unexpected status: %d", resp.StatusCode)
	}
}

// debugProxyHandler wraps a reverse proxy with debug logging for incoming requests
func debugProxyHandler(logger *log.Logger, proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("DEBUG: proxy request: %s %s", r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	})
}
