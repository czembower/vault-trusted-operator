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
			Token:   t.GetToken()[:20] + "...",
			Address: address,
		})
	})
	s.Mux.Handle("/v1/", vaultProxy)

}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
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
