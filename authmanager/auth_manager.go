package authmanager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"vault-trusted-operator/config"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type AuthManager struct {
	Cfg           config.Config
	Log           *log.Logger
	Clients       *VaultClientFactory
	Creds         *CredStore
	OIDC          *OIDCBootstrapper
	SIDRefr       *SecretIDRefresher
	mu            sync.Mutex
	client        *vault.Client
	watcherCancel context.CancelFunc
	watcherErr    error
}

// Initializes or returns an authenticated Vault client
// Implements retry-with-backoff for transient errors and fallback for credential rejections.
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

	// Attempt authentication with retry-with-backoff for transient errors.
	// Only try fallback when we detect a credential rejection (not just connectivity issues).
	const maxRetries = 3
	var lastErr error
	var backoffDuration time.Duration

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Apply exponential backoff on retries (skip for first attempt)
		// Use aggressive 150ms base with exponential doubling: 0ms → 150ms → 300ms → 600ms
		if attempt > 0 {
			backoffDuration = time.Duration(150<<uint(attempt-1)) * time.Millisecond
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: retry attempt %d after %v (transient error: %v)", attempt, backoffDuration, lastErr)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDuration):
				// Retry
			}
		}

		secret, fallbackUsed, err := a.loginWithFallback(ctx, client)
		if err == nil {
			// Success - start watcher and return
			a.startWatcher(client, secret, t)
			a.client = client
			a.watcherErr = nil

			// If we successfully authenticated using fallback, trigger immediate credential refresh.
			if fallbackUsed && a.SIDRefr != nil {
				a.mu.Unlock()
				a.refreshCredentialsOnFallback(ctx, t)
				a.mu.Lock()
			}

			return a.client, nil
		}

		lastErr = err

		// If this is a credential rejection error, don't retry - fall back or fail immediately
		if isCredentialRejected(err) {
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: credential rejected (not retrying): %v", err)
			}
			return nil, err
		}

		// If this is a transient error, retry if we haven't exhausted retries
		if isTransientError(err) {
			if attempt < maxRetries {
				if a.Cfg.Debug {
					a.Log.Printf("DEBUG: auth: transient error, will retry: %v", err)
				}
				continue
			}
			// Fall through to return error after max retries
		}

		// For other errors, return immediately (e.g., configuration errors)
		return nil, err
	}

	// Exhausted retries on transient error
	return nil, fmt.Errorf("authentication failed after %d retries: %w", maxRetries, lastErr)
}

// refreshCredentialsOnFallback asynchronously refreshes in-memory and wrapped secret IDs
// after a successful fallback authentication. This ensures we don't get a stale in-memory credential
// and that the invalidated wrapped token is replaced with a fresh one.
func (a *AuthManager) refreshCredentialsOnFallback(ctx context.Context, t *TokenProvider) {
	// Use a short timeout for credential refresh; don't block indefinitely
	refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Refresh in-memory secret ID
	if _, err := a.SIDRefr.RefreshOnce(refreshCtx, a.Cfg.CredTTL, nil, t); err != nil {
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: auth: failed to refresh in-memory secret ID after fallback: %v (proceeding with fallback credential)", err)
		}
		// Continue even on error; the fallback credential is still valid
	} else if a.Cfg.Debug {
		a.Log.Printf("DEBUG: auth: refreshed in-memory secret ID after fallback")
	}

	// Refresh wrapped secret ID (after in-memory succeeds or attempts)
	if err := a.SIDRefr.RefreshWrappedSecretID(refreshCtx, t); err != nil {
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: auth: failed to refresh wrapped secret ID after fallback: %v", err)
		}
		// Continue even on error; the fallback is still valid
	} else if a.Cfg.Debug {
		a.Log.Printf("DEBUG: auth: refreshed wrapped secret ID after fallback")
	}
}

func (a *AuthManager) login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	secret, _, err := a.loginWithFallback(ctx, client)
	return secret, err
}

// loginWithFallback attempts to authenticate with AppRole credentials in priority order:
// 1. In-memory secret ID (if available and not explicitly rejected)
// 2. Wrapped secret ID from state (if available and in-memory was rejected or unavailable)
// 3. OIDC bootstrap (as last resort)
//
// For transient errors (Vault unreachable), returns immediately without falling back further.
// Returns (*vault.Secret, fallbackUsed, error).
// If fallbackUsed is true, the caller should trigger a credential refresh to obtain a new in-memory secret ID
// and replace the now-invalidated wrapped secret ID.
func (a *AuthManager) loginWithFallback(ctx context.Context, client *vault.Client) (*vault.Secret, bool, error) {
	roleID := a.Creds.RoleID()

	// 1) Prefer: in-memory secret-id (if available)
	if roleID != "" {
		if sid := a.Creds.InMemSecretID(); sid != "" {
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: attempting login with in-memory secret-id")
			}
			secret, err := a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: sid}, false)
			if err == nil {
				return secret, false, nil
			}

			// Determine if this is a credential rejection or a transient error
			if isCredentialRejected(err) {
				// In-memory credential was explicitly rejected - log and try wrapped fallback
				a.Log.Printf("WARN: auth: in-memory secret-id rejected: %v (attempting wrapped secret-id fallback)", err)
			} else {
				// Transient error (Vault unreachable, timeout, etc.) - return immediately
				// Let the Client() retry loop handle retry with backoff
				return nil, false, err
			}
		}
	}

	// 2) Fallback: wrapped secret-id token from *state*
	if roleID != "" {
		if wrapTok := a.Creds.WrappedSecretIDToken(); wrapTok != "" {
			if a.Cfg.Debug {
				a.Log.Printf("DEBUG: auth: attempting login with wrapped secret-id token from state")
			}

			// Validate the wrapped token before using it
			// We pass 0 for expectedTTL to skip TTL validation (token may have been created with different TTL)
			if _, err := a.ValidateWrappedToken(ctx, wrapTok, 0); err != nil {
				a.Log.Printf("WARN: auth: wrapped token validation failed: %v (proceeding anyway)", err)
				// Continue anyway - the token might still be valid for unwrapping
			}

			// IMPORTANT: WithWrappingToken expects the SecretID to be the WRAPPING TOKEN
			secret, err := a.loginWithAppRole(ctx, client, roleID, approle.SecretID{FromString: wrapTok}, true)
			if err == nil {
				a.Log.Printf("INFO: auth: successfully authenticated with wrapped secret-id; will refresh credentials")
				return secret, true, nil
			}

			// Wrapped auth failed - determine if we should retry or proceed to bootstrap
			if isCredentialRejected(err) {
				// Wrapped credential explicitly rejected; proceed to OIDC bootstrap
				a.Log.Printf("WARN: auth: wrapped secret-id rejected: %v (proceeding to OIDC bootstrap)", err)
			} else {
				// Transient error - return immediately for retry
				a.Log.Printf("WARN: auth: wrapped secret-id authentication failed with transient error: %v (will retry)", err)
				return nil, false, err
			}
		}
	}

	// 3) Fallback: interactive OIDC bootstrap
	if a.Cfg.OIDCRole == "" {
		return nil, false, errors.New("no secret-id available and oidc-role is not set (cannot bootstrap)")
	}

	a.Log.Printf("INFO: auth: bootstrapping via OIDC (interactive)")
	rid, sid, err := a.OIDC.Bootstrap(ctx, client.Address())
	if err != nil {
		return nil, false, err
	}
	a.Creds.SetRoleID(rid)
	a.Creds.SetInMemSecretID(sid)

	secret, err := a.loginWithAppRole(ctx, client, rid, approle.SecretID{FromString: sid}, false)
	return secret, false, err
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
		for {
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
			case renewal := <-w.RenewCh():
				// Token was renewed — use the actual renewed TTL, not the original login TTL
				renewedTTL := time.Duration(renewal.Secret.Auth.LeaseDuration) * time.Second
				t.SetTokenWithExpiry(client.Token(), renewedTTL, true)
				if a.Cfg.Debug {
					a.Log.Printf("DEBUG: authmanager: renewed token: %s (TTL: %s) address: %p", TokenPrefix(t.GetToken()), renewedTTL, t)
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

// isCredentialRejected determines if an error is due to credential rejection
// (e.g., invalid secret ID, permission denied) versus transient connectivity issues.
// Returns true if Vault explicitly rejected the credential.
func isCredentialRejected(err error) bool {
	if err == nil {
		return false
	}

	// Check for explicit credential rejection errors from Vault
	var re *vault.ResponseError
	if errors.As(err, &re) {
		// 401 = Unauthorized (bad credentials)
		// 403 = Forbidden (could be bad token or policy denial)
		if re.StatusCode == 401 || re.StatusCode == 403 {
			msg := strings.ToLower(strings.Join(re.Errors, " "))
			// These messages indicate credential issues, not transient problems
			if strings.Contains(msg, "invalid secret id") ||
				strings.Contains(msg, "secret id invalid") ||
				strings.Contains(msg, "bad secret id") ||
				strings.Contains(msg, "permission denied") ||
				strings.Contains(msg, "role_id is invalid") ||
				strings.Contains(msg, "role id is invalid") {
				return true
			}
		}
	}

	// Check error message string for known credential rejection patterns
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "invalid secret id") ||
		strings.Contains(errMsg, "secret id invalid") ||
		strings.Contains(errMsg, "bad secret id") {
		return true
	}

	return false
}

// isTransientError determines if an error is transient and should be retried.
// Returns true for network errors, timeouts, and other issues where retrying may succeed.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context cancellation/deadline (not transient - higher level should handle)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for network-level errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Timeouts, connection refused, etc. are transient
		if netErr.Timeout() {
			return true
		}
		// Connection refused, reset, etc. are transient
		if strings.Contains(netErr.Error(), "connection refused") ||
			strings.Contains(netErr.Error(), "connection reset") ||
			strings.Contains(netErr.Error(), "i/o timeout") {
			return true
		}
	}

	// Check for Vault response errors with 5xx (server error)
	var re *vault.ResponseError
	if errors.As(err, &re) {
		// 5xx errors are transient (server is having issues, might recover)
		if re.StatusCode >= 500 && re.StatusCode < 600 {
			return true
		}
		// 429 = Too Many Requests (transient)
		if re.StatusCode == 429 {
			return true
		}
	}

	// Check error message for known transient patterns
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "connect") ||
		strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "unavailable") ||
		strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "dial") ||
		strings.Contains(errMsg, "refused") {
		return true
	}

	return false
}
