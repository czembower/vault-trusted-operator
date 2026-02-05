package authmanager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"vault-trusted-operator/config"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type AuthManager struct {
	Cfg     config.Config
	Log     *log.Logger
	Clients *VaultClientFactory
	Creds   *CredStore
	OIDC    *OIDCBootstrapper
	SIDRefr *SecretIDRefresher // Optional: used for proactive reauth to get fresh secret IDs

	mu     sync.Mutex
	client *vault.Client

	// watcher lifecycle
	watcherCancel context.CancelFunc
	watcherErr    error
}

func (a *AuthManager) Client(ctx context.Context, t *TokenProvider) (*vault.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// If we already have an authenticated client, check if it's still valid.
	// For batch tokens, IsTokenValid() will proactively return false near expiry.
	if a.client != nil && a.watcherErr == nil && t.IsTokenValid() {
		return a.client, nil
	}

	// Build (or rebuild) client
	client, err := a.Clients.New()
	if err != nil {
		return nil, err
	}

	secret, err := a.login(ctx, client)
	if err != nil {
		return nil, err
	}

	// Start a lifetime watcher for renewals; if it fails, we mark watcherErr and force re-auth next call.
	a.startWatcher(client, secret, t)

	a.client = client
	a.watcherErr = nil
	return a.client, nil
}

func (a *AuthManager) login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	roleID := a.Creds.RoleID()

	// 1) Prefer: in-memory secret-id
	if roleID != "" {
		if sid := a.Creds.InMemSecretID(); sid != "" {
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: using in-memory secret-id")
			}
			return a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: sid}, false)
		}
	}

	// 2) Next: wrapped secret-id token from *state*
	if roleID != "" {
		if wrapTok := a.Creds.WrappedSecretIDToken(); wrapTok != "" {
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: using wrapped secret-id token from state")
			}
			// IMPORTANT: WithWrappingToken expects the SecretID to be the WRAPPING TOKEN
			return a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: wrapTok}, true)
		}
	}

	// 3) Fallback: interactive OIDC bootstrap
	if a.Cfg.OIDCRole == "" {
		return nil, errors.New("no secret-id available and oidc-role is not set (cannot bootstrap)")
	}

	a.Log.Printf("INFO: auth: bootstrapping via OIDC (interactive)")
	rid, sid, err := a.OIDC.Bootstrap(ctx, client.Address())
	if err != nil {
		return nil, err
	}
	a.Creds.SetRoleID(rid)
	a.Creds.SetInMemSecretID(sid)

	return a.loginWithAppRole(ctx, client, rid, approle.SecretID{FromString: sid}, false)
}

func (a *AuthManager) loginWithAppRole(ctx context.Context, client *vault.Client, roleID string, sid approle.SecretID, wrapped bool) (*vault.Secret, error) {
	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: auth: attempting AppRole login")
	}
	var opts []approle.LoginOption
	if wrapped {
		opts = append(opts, approle.WithWrappingToken())
	}
	ar, err := approle.NewAppRoleAuth(roleID, &sid, opts...)
	if err != nil {
		return nil, err
	}

	// Use the standard Login method, which internally makes the correct request
	secret, err := client.Auth().Login(ctx, ar)
	if err != nil {
		return nil, fmt.Errorf("vault AppRole login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, errors.New("vault login returned empty auth")
	}
	return secret, nil
}

func (a *AuthManager) startWatcher(client *vault.Client, loginSecret *vault.Secret, t *TokenProvider) {
	// Stop prior watcher if any
	if a.watcherCancel != nil {
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: watcher: canceling stale watcher")
		}
		a.watcherCancel()
		a.watcherCancel = nil
	}

	wctx, cancel := context.WithCancel(context.Background())
	a.watcherCancel = cancel
	a.watcherErr = nil

	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: watcher: new lifetime watcher starting")
	}
	w, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: loginSecret,
	})
	if err != nil {
		a.watcherErr = fmt.Errorf("failed to create lifetime watcher: %w", err)
		return
	}

	ttl, _ := loginSecret.TokenTTL()
	renewable, _ := loginSecret.TokenIsRenewable()
	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: watcher: token TTL: %s | renewable: %t", ttl, renewable)
	}

	// Store token with expiry info for batch token detection
	t.SetTokenWithExpiry(client.Token(), ttl, renewable)
	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: watcher: set token: %s", TokenPrefix(t.GetToken()))
	}

	// For non-renewable (batch) tokens, trigger early refresh
	if !renewable {
		// Refresh at 2/3 of TTL to ensure we get a new secret ID before expiry
		refreshAt := time.Duration(float64(ttl) * 2 / 3)
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: watcher: non-renewable token detected; scheduling refresh in %v", refreshAt)
		}

		timer := time.NewTimer(refreshAt)
		go func() {
			defer timer.Stop()
			select {
			case <-wctx.Done():
				return
			case <-timer.C:
				if a.Cfg.Debug {
					a.Log.Printf("DEBUG: watcher: batch token TTL threshold reached, performing proactive re-auth")
				}
				// Perform re-authentication in the background
				a.performProactiveReauth(t)
			}
		}()
		return
	}

	go func() {
		// Watcher blocks until done or error.
		go w.Start()
		select {
		case <-wctx.Done():
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: watcher: done")
			}
			w.Stop()
			return
		case err := <-w.DoneCh():
			if err != nil {
				a.mu.Lock()
				a.watcherErr = fmt.Errorf("token renewal failed: %w", err)
				a.mu.Unlock()
			}
			return
		case <-w.RenewCh():
			// RenewCh may emit multiple times; keep listening until DoneCh or cancel.
			for {
				select {
				case <-wctx.Done():
					if a.Cfg.Debug {
						a.Log.Printf("DEBUG: watcher: renew phase done")
					}
					w.Stop()
					return
				case err := <-w.DoneCh():
					if err != nil {
						a.mu.Lock()
						a.watcherErr = fmt.Errorf("token renewal failed: %w", err)
						a.mu.Unlock()
					}
					return
				case <-w.RenewCh():
					// Token was renewed by the watcher
					t.SetTokenWithExpiry(client.Token(), ttl, true)
					if a.Cfg.Debug {
						a.Log.Printf("DEBUG: authmanager: renewed token: %s address: %p", TokenPrefix(t.GetToken()), t)
					}
				}
			}
		}
	}()
}

func (a *AuthManager) ForceReauth() {
	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: auth: attempting reauth")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}
	a.watcherErr = errors.New("forced reauth")
	a.client = nil
}

// performProactiveReauth attempts to re-authenticate without holding the main lock.
// This is called when batch tokens approach expiry.
func (a *AuthManager) performProactiveReauth(t *TokenProvider) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ensure we have a fresh secret ID before attempting login.
	// This is critical for batch tokens with single-use secret IDs.
	if a.SIDRefr != nil {
		if _, err := a.SIDRefr.RefreshOnce(ctx, a.Cfg.InMemSecretTTL, nil, t); err != nil {
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: failed to refresh secret ID: %v (proceeding with existing)", err)
			}
			// Fall through - attempt login with whatever secret ID we have
		} else if a.Cfg.Debug {
			a.Log.Printf("DEBUG: auth: obtained fresh secret ID")
		}
	}

	newClient, err := a.Clients.New()
	if err != nil {
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: auth: failed to create client: %v", err)
		}
		a.ForceReauth()
		return
	}

	secret, err := a.login(ctx, newClient)
	if err != nil {
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: auth: login failed: %v", err)
		}
		a.ForceReauth()
		return
	}

	// Update the client and token atomically
	a.mu.Lock()
	defer a.mu.Unlock()

	// Cancel the old watcher before starting the new one
	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}

	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: auth: successfully authenticated new token")
	}
	a.startWatcher(newClient, secret, t)
	a.client = newClient
	a.watcherErr = nil
}

func (a *AuthManager) Stop() {
	if a.Cfg.Debug {
		a.Log.Printf("INFO: auth: stopping")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}
}

// Export token
type TokenProvider struct {
	token       atomic.Value // string
	expiry      atomic.Value // time.Time
	originalTTL atomic.Value // time.Duration
	renewable   atomic.Value // bool
}

func NewTokenProvider() *TokenProvider {
	p := &TokenProvider{}
	p.token.Store("")
	p.expiry.Store(time.Time{})
	p.originalTTL.Store(time.Duration(0))
	p.renewable.Store(false)
	return p
}

func (p *TokenProvider) GetToken() string {
	t, _ := p.token.Load().(string)
	return t
}

func (p *TokenProvider) SetToken(token string) {
	p.token.Store(token)
}

// SetTokenWithExpiry sets the token and its expiration time.
func (p *TokenProvider) SetTokenWithExpiry(token string, ttl time.Duration, renewable bool) {
	p.token.Store(token)
	p.renewable.Store(renewable)
	p.originalTTL.Store(ttl)
	if ttl > 0 {
		p.expiry.Store(time.Now().Add(ttl))
	} else {
		p.expiry.Store(time.Time{})
	}
}

// IsTokenValid returns true if the token exists and hasn't expired yet.
// Returns false for batch tokens that are within the final 10% of their TTL.
func (p *TokenProvider) IsTokenValid() bool {
	token, _ := p.token.Load().(string)
	if token == "" {
		return false
	}

	expiry, _ := p.expiry.Load().(time.Time)
	if expiry.IsZero() {
		// No expiry set; assume valid
		return true
	}

	renewable, _ := p.renewable.Load().(bool)
	remaining := time.Until(expiry)

	// For batch tokens (non-renewable), be conservative: if less than 10% TTL remains, refresh
	if !renewable && remaining > 0 {
		originalTTL, _ := p.originalTTL.Load().(time.Duration)
		if originalTTL > 0 {
			tenPercent := originalTTL / 10
			if remaining < tenPercent {
				return false
			}
		}
	}

	// For renewable tokens, allow normal watcher-based refresh
	return remaining > 0
}

// TokenExpiry returns the token's expiration time and whether it's renewable.
func (p *TokenProvider) TokenExpiry() (expiry time.Time, renewable bool) {
	exp, _ := p.expiry.Load().(time.Time)
	ren, _ := p.renewable.Load().(bool)
	return exp, ren
}

// TokenPrefix returns a safe prefix of a token for logging.
func TokenPrefix(token string) string {
	if len(token) > 20 {
		return token[:20] + "..."
	}
	return token
}
