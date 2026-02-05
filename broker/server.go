package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
}

type HealthStatus struct {
	OK        bool   `json:"ok"`
	UptimeSec int64  `json:"uptime_sec"`
	Message   string `json:"message,omitempty"`
	Token     string `json:"token"`
}

type TokenResponse struct {
	Token   string `json:"token"`
	Address string `json:"address"`
}

func (s *Server) routes(cfg Config, t *authmanager.TokenProvider) {
	vaultProxy, err := NewVaultReverseProxy(cfg, t)
	if err != nil {
		cfg.Logger.Printf("broker: error configuring proxy")
	}

	s.Mux.HandleFunc("/health", s.handleHealth)
	s.Mux.HandleFunc("/v1/echo", s.handleEcho)
	s.Mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		address := fmt.Sprintf("%p", t)
		writeJSON(w, http.StatusOK, TokenResponse{
			Token:   authmanager.TokenPrefix(t.GetToken()),
			Address: address,
		})
	})
	s.Mux.Handle("/v1/", vaultProxy)

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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	uptime := int64(time.Since(s.start).Seconds())
	writeJSON(w, http.StatusOK, HealthStatus{
		OK:        true,
		UptimeSec: uptime,
		Message:   "ok",
	})
}

func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	writeJSON(w, http.StatusOK, map[string]any{
		"echo": string(b),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ContextKey for storing peer credentials in request context
type contextKey string

const peerCredsContextKey contextKey = "peerCreds"

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

	// Validate credentials against whitelist
	if err := CheckAccessControl(creds, acl.allowedUIDs, acl.allowedGIDs); err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer access denied: %w", err)
	}

	return conn, nil
}
