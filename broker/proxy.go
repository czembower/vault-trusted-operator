package broker

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"vault-trusted-operator/authmanager"
)

func NewVaultReverseProxy(cfg Config, t *authmanager.TokenProvider) (*httputil.ReverseProxy, error) {
	cfg.Logger.Printf("proxy: starting")
	upstreamURL, err := url.Parse(cfg.VaultAddress)
	if err != nil {
		return nil, err
	}

	// Transport tuned for a proxy (keepalives, timeouts, TLS config).
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.VaultSkipVerify,
		},
	}

	rp := httputil.NewSingleHostReverseProxy(upstreamURL)
	rp.Transport = tr

	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		// Preserve base behavior (rewrites scheme/host/path).
		origDirector(req)

		// Optionally restrict what you forward upstream.
		// Example: disallow proxying to /v1/sys/* (dangerous) if your use case requires it.
		// if strings.HasPrefix(req.URL.Path, "/v1/sys/") { ... } // do in handler wrapper, not here.

		// Set Host header to upstream host (common expectation for Vault behind LB).
		req.Host = upstreamURL.Host
		req.Header.Set("X-Vault-Token", t.GetToken())
		req.Header.Set("X-Vault-Namespace", cfg.VaultNamespace)

		// Identify your proxy.
		req.Header.Set("PROXY-VIA", "go-vault-proxy")
	}

	// Ensure errors are returned cleanly.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Avoid leaking internal details.
		http.Error(w, "proxy: upstream error", http.StatusBadGateway)
	}

	// Optional: tighten response handling (e.g., strip headers).
	rp.ModifyResponse = func(resp *http.Response) error {
		// Example: prevent upstream from setting cookies via the proxy.
		// resp.Header.Del("Set-Cookie")
		return nil
	}

	return rp, nil
}

// Optional wrapper to add request-level policy / auth / logging.
func ProxyHandler(ctx context.Context, rp *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic hardening examples:
		// - Require a client auth mechanism before proxying
		// - Block dangerous endpoints if clients are untrusted
		// - Enforce methods
		rp.ServeHTTP(w, r)
	})
}
