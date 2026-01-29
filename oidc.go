// oidc.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skratchdot/open-golang/open"
)

type OIDCBootstrapper struct {
	Cfg  Config
	HTTP *http.Client
	Log  *log.Logger
}

type vaultOIDCAuthURLResp struct {
	Data struct {
		AuthURL string `json:"auth_url"`
	} `json:"data"`
}

type vaultLoginResp struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

type roleIDResp struct {
	Data struct {
		RoleID string `json:"role_id"`
	} `json:"data"`
}

type secretIDResp struct {
	Data struct {
		SecretID string `json:"secret_id"`
	} `json:"data"`
}

// Bootstrap performs interactive OIDC: opens browser, receives callback, exchanges for token, then fetches role_id and secret_id.
func (o *OIDCBootstrapper) Bootstrap(ctx context.Context, vaultAddr string) (roleID string, secretID string, err error) {
	oidcMount := normalizeMount(o.Cfg.OIDCMount)

	// Loopback callback
	redirect := "http://localhost:8250/oidc/callback"

	// 1) Ask Vault for auth_url
	authURL, state, nonce, err := o.getAuthURL(ctx, vaultAddr, oidcMount, o.Cfg.OIDCRole, redirect)
	if err != nil {
		return "", "", err
	}

	// 2) Start local server for callback
	cbURL, _ := url.Parse(redirect)
	l, err := net.Listen("tcp", cbURL.Host)
	if err != nil {
		return "", "", fmt.Errorf("listen on %s: %w", cbURL.Host, err)
	}
	defer l.Close()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{
		Handler: mux,
	}

	mux.HandleFunc(cbURL.Path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotCode := q.Get("code")
		gotState := q.Get("state")

		if gotState == "" || gotState != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			errCh <- errors.New("state mismatch")
			return
		}
		if gotCode == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- errors.New("missing code")
			return
		}

		io.WriteString(w, "Login successful. You can close this window and return to the CLI.\n")
		codeCh <- gotCode
	})

	go func() {
		_ = srv.Serve(l)
	}()

	// 3) Open browser
	if err := open.Start(authURL); err != nil {
		_ = srv.Shutdown(context.Background())
		return "", "", fmt.Errorf("open browser: %w", err)
	}

	// 4) Wait for callback or timeout/cancel
	var code string
	select {
	case <-ctx.Done():
		_ = srv.Shutdown(context.Background())
		return "", "", ctx.Err()
	case err := <-errCh:
		_ = srv.Shutdown(context.Background())
		return "", "", err
	case code = <-codeCh:
		_ = srv.Shutdown(context.Background())
	case <-time.After(120 * time.Second):
		_ = srv.Shutdown(context.Background())
		return "", "", errors.New("oidc callback timed out")
	}

	// 5) Exchange callback for Vault token
	token, err := o.exchangeCallback(ctx, vaultAddr, oidcMount, code, state, nonce)
	if err != nil {
		return "", "", err
	}

	// 6) Fetch role_id and secret_id using that token
	roleID, err = o.getRoleID(ctx, vaultAddr, token)
	if err != nil {
		return "", "", err
	}
	secretID, err = o.getSecretID(ctx, vaultAddr, token, int(o.Cfg.InMemSecretTTL.Seconds()))
	if err != nil {
		return "", "", err
	}

	return roleID, secretID, nil
}

func (o *OIDCBootstrapper) getAuthURL(ctx context.Context, vaultAddr, oidcMount, oidcRole, redirectURI string) (authURL, state, nonce string, err error) {
	payload := map[string]string{
		"role":         oidcRole,
		"redirect_uri": redirectURI,
	}

	u := fmt.Sprintf("%s/v1/auth/%s/oidc/auth_url", vaultAddr, oidcMount)
	respBytes, err := o.doJSON(ctx, http.MethodPost, u, payload, "")
	if err != nil {
		return "", "", "", err
	}

	var r vaultOIDCAuthURLResp
	if err := json.Unmarshal(respBytes, &r); err != nil {
		return "", "", "", err
	}

	authURL = r.Data.AuthURL
	parsed, err := url.Parse(authURL)
	if err != nil {
		return "", "", "", err
	}
	state = parsed.Query().Get("state")
	if state == "" {
		return "", "", "", errors.New("auth_url missing state")
	}
	nonce = parsed.Query().Get("nonce")
	if nonce == "" {
		return "", "", "", errors.New("auth_url missing nonce")
	}
	return authURL, state, nonce, nil
}

func (o *OIDCBootstrapper) exchangeCallback(ctx context.Context, vaultAddr, oidcMount, code, state, nonce string) (string, error) {
	u := fmt.Sprintf("%s/v1/auth/%s/oidc/callback?code=%s&state=%s&nonce=%s",
		vaultAddr, oidcMount, url.QueryEscape(code), url.QueryEscape(state), url.QueryEscape(nonce))

	respBytes, err := o.doJSON(ctx, http.MethodGet, u, nil, "")
	if err != nil {
		return "", err
	}

	var r vaultLoginResp
	if err := json.Unmarshal(respBytes, &r); err != nil {
		return "", err
	}
	if r.Auth.ClientToken == "" {
		return "", errors.New("empty client_token from OIDC callback")
	}
	return r.Auth.ClientToken, nil
}

func (o *OIDCBootstrapper) getRoleID(ctx context.Context, vaultAddr, token string) (string, error) {
	u := fmt.Sprintf("%s/v1/%s", vaultAddr, trimLeadingSlash(o.Cfg.AppRoleRoleIDPath()))
	respBytes, err := o.doJSON(ctx, http.MethodGet, u, nil, token)
	if err != nil {
		return "", err
	}

	var r roleIDResp
	if err := json.Unmarshal(respBytes, &r); err != nil {
		return "", err
	}
	if strings.TrimSpace(r.Data.RoleID) == "" {
		return "", errors.New("role_id empty")
	}
	return r.Data.RoleID, nil
}

func (o *OIDCBootstrapper) getSecretID(ctx context.Context, vaultAddr, token string, ttlSeconds int) (string, error) {
	u := fmt.Sprintf("%s/v1/%s", vaultAddr, trimLeadingSlash(o.Cfg.AppRoleSecretIDPath()))
	payload := map[string]any{
		"ttl": ttlSeconds,
	}
	respBytes, err := o.doJSON(ctx, http.MethodPost, u, payload, token)
	if err != nil {
		return "", err
	}

	var r secretIDResp
	if err := json.Unmarshal(respBytes, &r); err != nil {
		return "", err
	}
	if strings.TrimSpace(r.Data.SecretID) == "" {
		return "", errors.New("secret_id empty")
	}
	return r.Data.SecretID, nil
}

func (o *OIDCBootstrapper) doJSON(ctx context.Context, method, u string, payload any, token string) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if o.Cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", o.Cfg.Namespace)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault http %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

func normalizeMount(m string) string {
	m = strings.TrimSpace(m)
	m = strings.TrimPrefix(m, "/")
	m = strings.TrimPrefix(m, "auth/")
	if m == "" {
		return "oidc"
	}
	return m
}
