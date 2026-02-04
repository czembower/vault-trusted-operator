package authmanager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
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

	mu     sync.Mutex
	client *vault.Client

	// watcher lifecycle
	watcherCancel context.CancelFunc
	watcherErr    error
}

func (a *AuthManager) Client(ctx context.Context, t *TokenProvider) (*vault.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// If we already have an authenticated client, keep using it unless watcher reported failure.
	if a.client != nil && a.watcherErr == nil {
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
	a.startWatcher(ctx, client, secret, t)

	a.client = client
	a.watcherErr = nil
	return a.client, nil
}

func (a *AuthManager) login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	roleID := a.Creds.RoleID()

	// 1) Prefer: in-memory secret-id
	if roleID != "" {
		if sid := a.Creds.InMemSecretID(); sid != "" {
			a.Log.Printf("auth: using in-memory secret-id")
			return a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: sid}, false)
		}
	}

	// 2) Next: wrapped secret-id token from *state*
	if roleID != "" {
		if wrapTok := a.Creds.WrappedSecretIDToken(); wrapTok != "" {
			a.Log.Printf("auth: using wrapped secret-id token from state")
			// IMPORTANT: WithWrappingToken expects the SecretID to be the WRAPPING TOKEN
			return a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: wrapTok}, true)
		}
	}

	// 3) Fallback: interactive OIDC bootstrap
	if a.Cfg.OIDCRole == "" {
		return nil, errors.New("no secret-id available and oidc-role is not set (cannot bootstrap)")
	}

	a.Log.Printf("auth: no usable secret-id; bootstrapping via OIDC")
	rid, sid, err := a.OIDC.Bootstrap(ctx, client.Address())
	if err != nil {
		return nil, err
	}
	a.Creds.SetRoleID(rid)
	a.Creds.SetInMemSecretID(sid)

	return a.loginWithAppRole(ctx, client, rid, approle.SecretID{FromString: sid}, false)
}

func (a *AuthManager) loginWithAppRole(ctx context.Context, client *vault.Client, roleID string, sid approle.SecretID, wrapped bool) (*vault.Secret, error) {
	a.Log.Printf("auth: attempting AppRole login with Role ID %s and Secret ID %s", roleID, sid)
	var opts []approle.LoginOption
	if wrapped {
		opts = append(opts, approle.WithWrappingToken())
	}
	ar, err := approle.NewAppRoleAuth(roleID, &sid, opts...)
	if err != nil {
		return nil, err
	}
	secret, err := client.Auth().Login(ctx, ar)
	if err != nil {
		return nil, fmt.Errorf("vault AppRole login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, errors.New("vault login returned empty auth")
	}
	return secret, nil
}

func (a *AuthManager) startWatcher(ctx context.Context, client *vault.Client, loginSecret *vault.Secret, t *TokenProvider) {
	// Stop prior watcher if any
	if a.watcherCancel != nil {
		a.Log.Printf("watcher: canceling stale watcher")
		a.watcherCancel()
		a.watcherCancel = nil
	}

	wctx, cancel := context.WithCancel(context.Background())
	a.watcherCancel = cancel
	a.watcherErr = nil

	a.Log.Printf("watcher: new lifetime watcher starting")
	w, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: loginSecret,
	})
	if err != nil {
		a.watcherErr = fmt.Errorf("failed to create lifetime watcher: %w", err)
		return
	}

	t.SetToken(client.Token())
	a.Log.Printf("watcher: set token: %s address: %p", t.GetToken()[:20]+"...", t)
	ttl, _ := loginSecret.TokenTTL()
	renewable, _ := loginSecret.TokenIsRenewable()
	a.Log.Printf("watcher: token TTL: %s | renewable: %s", ttl, strconv.FormatBool(renewable))

	// if !renewable {
	// 	renewTimer := ttl * 2 / 3
	// 	a.Log.Printf("watcher: scheduling new login: %v", renewTimer)

	// 	go func() {
	// 		go a.backgroundSleep(ctx, renewTimer, t)
	// 	}()
	// }

	go func() {
		// Watcher blocks until done or error.
		go w.Start()
		select {
		case <-wctx.Done():
			a.Log.Printf("watcher: done")
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
					a.Log.Printf("watcher: renew phase done")
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
					t.SetToken(client.Token())
					a.Log.Printf("authmanager: renewed token: %s address: %p", t.GetToken()[:20]+"...", t)
				}
			}
		}
	}()
}

func (a *AuthManager) ForceReauth() {
	a.Log.Printf("auth: attempting reauth")
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}
	a.watcherErr = errors.New("forced reauth")
	a.client = nil
}

func (a *AuthManager) Stop() {
	a.Log.Printf("auth: stopping")
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}
}

// Export token
type TokenProvider struct {
	token atomic.Value
}

func NewTokenProvider() *TokenProvider {
	p := &TokenProvider{}
	p.token.Store("")
	return p
}

func (p *TokenProvider) GetToken() string {
	t, _ := p.token.Load().(string)
	return t
}

func (p *TokenProvider) SetToken(token string) {
	p.token.Store(token)
}

func (a *AuthManager) backgroundSleep(ctx context.Context, duration time.Duration, t *TokenProvider) error {
	<-time.After(duration) // Blocks until the timer fires
	a.Log.Printf("watcher: login timer breached, forcing reauth")
	a.ForceReauth()

	a.Log.Printf("watcher: background timer requesting new login")
	// authenticate!
	return nil
}
