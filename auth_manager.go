// auth_manager.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type AuthManager struct {
	Cfg     Config
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

func (a *AuthManager) Client(ctx context.Context) (*vault.Client, error) {
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
	a.startWatcher(client, secret)

	a.client = client
	a.watcherErr = nil
	return a.client, nil
}

func (a *AuthManager) login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	// Prefer: in-memory secret-id
	roleID := a.Creds.RoleID()
	secretID := a.Creds.InMemSecretID()
	if roleID != "" && secretID != "" {
		a.Log.Printf("auth: using in-memory secret-id")
		return a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: secretID}, false)
	}

	// Next: wrapped secret-id token from file (requires role-id file)
	if roleID != "" {
		if info, err := os.Stat(a.Cfg.SecretIDFile); err == nil && info.Size() > 0 {
			a.Log.Printf("auth: using wrapped secret-id token from file")
			return a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromFile: a.Cfg.SecretIDFile}, true)
		}
	}

	// Fallback: interactive OIDC bootstrap to obtain role_id and secret_id
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

	// Persist role-id to file for future non-interactive restarts
	if err := os.WriteFile(a.Cfg.RoleIDFile, []byte(rid), 0o600); err != nil {
		a.Log.Printf("warning: failed to write role-id file: %v", err)
	}

	return a.loginWithAppRole(ctx, client, rid, approle.SecretID{FromString: sid}, false)
}

func (a *AuthManager) loginWithAppRole(ctx context.Context, client *vault.Client, roleID string, sid approle.SecretID, wrapped bool) (*vault.Secret, error) {
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
		return nil, fmt.Errorf("vault login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, errors.New("vault login returned empty auth")
	}
	return secret, nil
}

func (a *AuthManager) startWatcher(client *vault.Client, loginSecret *vault.Secret) {
	// Stop prior watcher if any
	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}

	wctx, cancel := context.WithCancel(context.Background())
	a.watcherCancel = cancel
	a.watcherErr = nil

	w, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: loginSecret,
	})
	if err != nil {
		// If watcher cannot be created, treat it as an error so we can re-auth on next call
		a.watcherErr = fmt.Errorf("failed to create lifetime watcher: %w", err)
		return
	}

	go func() {
		// Watcher blocks until done or error.
		go w.Start()
		select {
		case <-wctx.Done():
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
					// no-op; could log if desired
				}
			}
		}
	}()
}

func (a *AuthManager) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.watcherCancel != nil {
		a.watcherCancel()
		a.watcherCancel = nil
	}
}
