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
	"reflect"
	"time"
	"vault-trusted-operator/authmanager"
)

type Server struct {
	HTTP              *http.Server
	Mux               *http.ServeMux
	ShutdownTimeout   time.Duration
	AllowedUIDs       []uint32
	AllowedGIDs       []uint32
	start             time.Time
	upstreamClient    *http.Client
	upstreamAddr      string
	vaultAddresses    []string    // All addresses for failover
	serverSelector    interface{} // (*ServerSelector from main.go)
	vaultSkipVerify   bool        // For proxy recreation
	vaultNamespace    string      // For proxy recreation
	authManager         *authmanager.AuthManager
	tokenProvider       *authmanager.TokenProvider // For proxy recreation
	identityTokenFunc   func() string              // Function to get current identity token
	logger              *log.Logger
	lastUpstreamState   bool // tracks if upstream was healthy on last check
}

type HealthStatus struct {
	Healthy       bool   `json:"ok"`
	UptimeSec     int64  `json:"uptime_sec"`
	Token         string `json:"token,omitempty"`
	IdentityToken string `json:"identity_token,omitempty"`
	UpstreamOk    bool   `json:"upstream_ok"`
	UpstreamMsg   string `json:"upstream_msg,omitempty"`
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
		status := HealthStatus{
			UptimeSec:   uptime,
			Healthy:     true,
			UpstreamOk:  upstreamOk,
			UpstreamMsg: upstreamMsg,
		}
		// Log upstream status (not just debug)
		if !upstreamOk {
			cfg.Logger.Printf("WARN: broker health: upstream unhealthy - %s", upstreamMsg)
		}
		// Only expose token prefix in debug mode to avoid leaking partial tokens
		if cfg.Debug {
			status.Token = authmanager.TokenPrefix(t.GetToken())
		}
		// Include identity token in response (typically consumed by applications for API authentication)
		if s.identityTokenFunc != nil {
			if idToken := s.identityTokenFunc(); idToken != "" {
				status.IdentityToken = idToken
			}
		}
		writeJSON(w, http.StatusOK, status)
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

	// Start proactive upstream health monitoring
	go s.monitorUpstreamHealth(ctx)

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

	// Start proactive upstream health monitoring
	go s.monitorUpstreamHealth(ctx)

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

// monitorUpstreamHealth periodically checks upstream health and triggers credential refresh
// when upstream transitions from unhealthy to healthy. This enables rapid broker recovery
// when the upstream Vault server becomes available again. It also implements failover
// by trying alternative addresses when the primary becomes unavailable.
func (s *Server) monitorUpstreamHealth(ctx context.Context) {
	if s.authManager == nil || s.logger == nil {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var unhealthyCount int // Track how many consecutive unhealthy checks (for periodic logging)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check current upstream health
			currentUpstreamOk, msg := s.checkUpstreamHealth(ctx)

			// Detect transition from unhealthy to healthy
			if currentUpstreamOk && !s.lastUpstreamState {
				s.logger.Printf("INFO: broker: upstream recovered (was: unhealthy, now: healthy) - refreshing credentials")
				// Force re-authentication to establish a fresh client
				s.authManager.ForceReauth()
				s.lastUpstreamState = true
				unhealthyCount = 0
			} else if !currentUpstreamOk && s.lastUpstreamState {
				// Transition from healthy to unhealthy
				s.logger.Printf("WARN: broker: upstream became unavailable - %s", msg)
				s.lastUpstreamState = false
				unhealthyCount = 1

				// Try to find a healthy alternative server
				if s.serverSelector != nil && len(s.vaultAddresses) > 1 {
					s.attemptFailover(ctx)
				}
			} else if !currentUpstreamOk && !s.lastUpstreamState {
				// Still unhealthy - log periodically (every ~15 seconds = 7-8 iterations of 2s ticker)
				unhealthyCount++
				if unhealthyCount%8 == 0 {
					s.logger.Printf("WARN: broker: upstream still unavailable - %s", msg)
				}
			}
			// If healthy and was healthy, no action needed
		}
	}
}

// attemptFailover tries to find a healthy alternative Vault server from the configured list
// and switches to it if found. This allows the broker to recover when the primary fails.
func (s *Server) attemptFailover(ctx context.Context) {
	// Build list of alternatives (all addresses except current)
	var alternatives []string
	for _, addr := range s.vaultAddresses {
		if addr != s.upstreamAddr {
			alternatives = append(alternatives, addr)
		}
	}

	if len(alternatives) == 0 {
		s.logger.Printf("WARN: broker: no alternative servers configured for failover")
		return
	}

	// Try to find a healthy alternative using reflection to call SelectAlternative
	// (we can't directly type assert the serverSelector without creating import cycles)
	if s.serverSelector == nil {
		s.logger.Printf("WARN: broker: serverSelector not configured for failover")
		return
	}

	selectorValue := reflect.ValueOf(s.serverSelector)
	selectAltMethod := selectorValue.MethodByName("SelectAlternative")

	if !selectAltMethod.IsValid() {
		s.logger.Printf("WARN: broker: serverSelector doesn't have SelectAlternative method")
		return
	}

	// Call SelectAlternative(ctx, alternatives)
	results := selectAltMethod.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(alternatives),
	})

	if len(results) != 2 {
		s.logger.Printf("WARN: broker: SelectAlternative returned unexpected number of values")
		return
	}

	// Check if error is non-nil (second return value)
	errVal := results[1].Interface()
	if errVal != nil {
		s.logger.Printf("WARN: broker: failover failed - %v (no healthy alternatives found)", errVal)
		return
	}

	// Get the new address (first return value)
	newAddr := results[0].String()

	// Switch to the new address
	s.logger.Printf("INFO: broker: failover successful - switching from %s to %s", s.upstreamAddr, newAddr)
	s.upstreamAddr = newAddr

	// Recreate the proxy with the new upstream address
	if err := s.updateProxyAddress(newAddr); err != nil {
		s.logger.Printf("WARN: broker: failed to update proxy for new address %s: %v", newAddr, err)
		// Continue anyway - requests might still work if the issue is transient
	}

	s.authManager.ForceReauth()
}

// updateProxyAddress recreates the reverse proxy handler with a new upstream Vault address
func (s *Server) updateProxyAddress(newAddr string) error {
	if s.tokenProvider == nil || s.Mux == nil {
		return errors.New("server not properly initialized for proxy updates")
	}

	// Create a temporary config with the new address for proxy creation
	tempConfig := Config{
		VaultAddress:    newAddr,
		VaultNamespace:  s.vaultNamespace,
		VaultSkipVerify: s.vaultSkipVerify,
	}

	// Create new proxy with the new address
	newProxy, err := NewVaultReverseProxy(tempConfig, s.tokenProvider)
	if err != nil {
		return fmt.Errorf("failed to create new proxy: %w", err)
	}

	// Wrap proxy with debug logging if enabled
	var proxyHandler http.Handler = newProxy
	if tempConfig.Debug { // Note: we don't have cfg.Debug here, but we'd set it if needed
		// Debug mode skipped for now since we don't have logger passed through
	}

	// Replace the /v1/ route handler with the new proxy
	s.Mux.Handle("/v1/", proxyHandler)
	s.logger.Printf("INFO: broker: proxy updated to use %s", newAddr)

	return nil
}

// debugProxyHandler wraps a reverse proxy with debug logging for incoming requests
func debugProxyHandler(logger *log.Logger, proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("DEBUG: proxy request: %s %s", r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	})
}
