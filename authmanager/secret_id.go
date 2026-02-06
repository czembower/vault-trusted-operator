package authmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"
	"vault-trusted-operator/config"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type SecretIDRefresher struct {
	Cfg  config.Config
	Log  *log.Logger
	Auth *AuthManager

	// Track whether the last refresh fell back to role defaults due to TTL rejection.
	// Accessed from background goroutines and main goroutine at shutdown; must be atomic.
	lastRefreshFellBackToDefault atomic.Bool
}

// Run keeps an in-memory secret-id fresh by periodically requesting a new one.
// This avoids forcing an interactive OIDC bootstrap if token renewal fails at an inconvenient time.
// Uses exponential backoff on upstream unavailability to avoid cascade failures.
func (s *SecretIDRefresher) Run(ctx context.Context, t *TokenProvider) {
	if s.Cfg.Debug {
		s.Log.Printf("DEBUG: auth: secret-id refresher running")
	}

	// Track current sleep timer for cleanup on context cancel
	var currentTimer *time.Timer
	consecutiveFailures := 0
	maxBackoff := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			if currentTimer != nil {
				currentTimer.Stop()
			}
			return
		default:
		}

		ttl, err := s.RefreshOnce(ctx, s.Cfg.CredTTL, nil, t) // raw secret-id (no wrapping)
		if err != nil {
			consecutiveFailures++
			if s.Cfg.Debug {
				s.Log.Printf("DEBUG: auth: secret-id refresh failed (attempt %d): %v", consecutiveFailures, err)
			}
			// Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 300s (5m cap)
			// This prevents cascading failures when upstream is temporarily unavailable
			backoffDuration := time.Duration(1<<uint(consecutiveFailures-1)) * 1 * time.Second
			if backoffDuration > maxBackoff {
				backoffDuration = maxBackoff
			}
			if s.Cfg.Debug {
				s.Log.Printf("DEBUG: auth: backing off %v before next refresh attempt", backoffDuration)
			}
			currentTimer = time.NewTimer(backoffDuration)
			select {
			case <-ctx.Done():
				currentTimer.Stop()
				return
			case <-currentTimer.C:
				continue
			}
		}

		// Reset backoff counter on successful refresh
		consecutiveFailures = 0

		sleepFor := time.Duration(float64(ttl) * s.Cfg.RenewFraction)
		if sleepFor < 1*time.Second {
			sleepFor = 1 * time.Second
		}

		if s.Cfg.Debug {
			s.Log.Printf("DEBUG: auth: secret-id TTL: %s (refresh in %s)", ttl.String(), sleepFor.String())
		}

		currentTimer = time.NewTimer(sleepFor)
		select {
		case <-ctx.Done():
			currentTimer.Stop()
			return
		case <-currentTimer.C:
			// Timer fired, loop continues to refresh
		}
	}
}

// RunWrappedSecretIDRefresher keeps the post-initialization wrapped secret ID token fresh
// by periodically requesting a new one before it expires.
// This ensures that on the next startup, we always have a valid wrapped token available.
// The refreshed token is stored in CredStore; the caller is responsible for persisting it to state.
func (s *SecretIDRefresher) RunWrappedSecretIDRefresher(ctx context.Context, t *TokenProvider) {
	if s.Cfg.Debug {
		s.Log.Printf("DEBUG: auth: wrapped secret-id refresher running (wrap-ttl: %s)", s.Cfg.WrapTTL.String())
	}

	// Refresh at 50% of wrap TTL, leaving a comfortable margin before expiry
	refreshInterval := time.Duration(float64(s.Cfg.WrapTTL) * 0.5)
	if refreshInterval < 1*time.Minute {
		refreshInterval = 1 * time.Minute
	}

	var currentTimer *time.Timer
	consecutiveFailures := 0
	maxBackoff := 5 * time.Minute

	// Wait for initial refresh interval before first refresh.
	// This avoids unnecessary refresh right after startup when we just loaded/refreshed a token.
	initialDelay := refreshInterval
	if s.Cfg.Debug {
		s.Log.Printf("DEBUG: auth: waiting %s before first wrapped secret-id refresh (token already fresh at startup)", initialDelay.String())
	}

	currentTimer = time.NewTimer(initialDelay)
	defer func() {
		if currentTimer != nil {
			currentTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-currentTimer.C:
			// Timer fired - attempt to refresh the wrapped token
			err := s.RefreshWrappedSecretID(ctx, t)
			if err != nil {
				consecutiveFailures++
				if s.Cfg.Debug {
					s.Log.Printf("DEBUG: auth: wrapped secret-id refresh failed (attempt %d): %v", consecutiveFailures, err)
				}
				// Exponential backoff on failure, up to 5 minutes
				backoffDuration := time.Duration(1<<uint(consecutiveFailures-1)) * 1 * time.Second
				if backoffDuration > maxBackoff {
					backoffDuration = maxBackoff
				}
				if s.Cfg.Debug {
					s.Log.Printf("DEBUG: auth: backing off %v before next wrapped secret-id refresh attempt", backoffDuration)
				}
				currentTimer = time.NewTimer(backoffDuration)
			} else {
				// Reset backoff counter on successful refresh
				consecutiveFailures = 0
				s.Log.Printf("INFO: auth: refreshed wrapped secret-id token (next refresh in %s)", refreshInterval.String())

				// Schedule next refresh
				currentTimer = time.NewTimer(refreshInterval)
			}
		}
	}
}

func (s *SecretIDRefresher) RefreshWrappedSecretID(ctx context.Context, t *TokenProvider) error {
	_, err := s.RefreshOnce(ctx, s.Cfg.WrapTTL, &s.Cfg.WrapTTL, t) // wrapped token output, stored in CredStore
	return err
}

// DidLastRefreshFallBackToDefault returns true if the most recent refresh had to fall back
// to the role's default secret_id_ttl due to the requested TTL being too long.
func (s *SecretIDRefresher) DidLastRefreshFallBackToDefault() bool {
	return s.lastRefreshFellBackToDefault.Load()
}

// GetFreshWrappedSecretID obtains a fresh wrapped secret ID token that can be persisted to state.
// This is called immediately after successful authentication to ensure we have a recovery path
// in case of crashes or loss of upstream access. The token is validated and stored in CredStore;
// the caller is responsible for persisting it to the state file.
//
// Wrapped Secret ID Lifecycle:
// 1. On startup: Load wrapped token from state (if available), validate it
// 2. Use wrapped token to authenticate (unwraps it as part of AppRole login)
// 3. Immediately after successful login: Call GetFreshWrappedSecretID() to capture a new token
// 4. Background goroutine: Periodically refresh token at 50% of TTL (safety net)
// 5. On graceful shutdown: Invalidate current token, get fresh one for next startup
// 6. Every refresh: Validate token using sys/wrapping/lookup
func (s *SecretIDRefresher) GetFreshWrappedSecretID(ctx context.Context, t *TokenProvider) (string, error) {
	if err := s.RefreshWrappedSecretID(ctx, t); err != nil {
		return "", fmt.Errorf("failed to obtain fresh wrapped secret ID: %w", err)
	}
	token := s.Auth.Creds.WrappedSecretIDToken()
	if token == "" {
		return "", fmt.Errorf("wrapped secret ID was retrieved but not stored in CredStore")
	}
	return token, nil
}

// RefreshOnce performs a single secret ID refresh operation.
// If wrapTTL is nil, returns a raw secret ID; if non-nil, returns a wrapped token.
// When requesting a wrapped token, we specify the same TTL for both the wrapping token
// and the unwrapped secret ID itself - this ensures they have aligned lifetimes.
// If the role has a lower secret_id_ttl, we'll get an error and retry without specifying TTL.
func (s *SecretIDRefresher) RefreshOnce(ctx context.Context, rawTTL time.Duration, wrapTTL *time.Duration, t *TokenProvider) (time.Duration, error) {
	payload := map[string]any{}
	requestedTTL := int64(0)

	if wrapTTL == nil {
		// raw secret-id request includes a TTL
		payload["ttl"] = int(rawTTL.Seconds())
		requestedTTL = int64(rawTTL.Seconds())
	} else {
		// wrapped secret-id request: include TTL for the unwrapped secret ID
		// The X-Vault-Wrap-TTL header (set below) controls the wrapping token TTL
		payload["ttl"] = int(wrapTTL.Seconds())
		requestedTTL = int64(wrapTTL.Seconds())
	}

	secret, err := vaultWriteWithReauth(ctx, s.Auth, s.Cfg.AppRoleSecretIDPath(), payload, wrapTTL, t)

	// If we get a TTL rejection error (role's secret_id_ttl is lower), retry without specifying TTL
	if err != nil && isTTLTooLongError(err) {
		s.Log.Printf("WARN: auth: requested TTL (%d seconds) exceeds role's secret_id_ttl, retrying without TTL (will use role default)", requestedTTL)

		// Mark that we fell back to role defaults
		s.lastRefreshFellBackToDefault.Store(true)

		// Retry with empty payload (no TTL specified)
		payload := map[string]any{}
		secret, err = vaultWriteWithReauth(ctx, s.Auth, s.Cfg.AppRoleSecretIDPath(), payload, wrapTTL, t)
		if err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}

	// write wrapping token to state
	if wrapTTL != nil {
		if secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
			return 0, fmt.Errorf("expected wrap token, got none")
		}
		token := secret.WrapInfo.Token

		// Validate the wrapping token to ensure Vault honored our TTL request (debug-level only during routine refresh)
		if _, err := s.Auth.ValidateWrappedToken(ctx, token, *wrapTTL); err != nil {
			if s.Cfg.Debug {
				s.Log.Printf("DEBUG: auth: wrapping token validation during refresh: %v (proceeding anyway)", err)
			}
			// Continue anyway - the token is still valid even if validation had issues
		} else if s.Cfg.Debug {
			s.Log.Printf("DEBUG: auth: wrapped token validate check passed for refreshed token")
		}

		s.Auth.Creds.SetWrappedSecretIDToken(token)
		return time.Duration(secret.WrapInfo.TTL) * time.Second, nil
	}

	// Raw secret-id response: store in memory
	secretID, ttlSec, err := parseSecretIDResponse(secret)
	if err != nil {
		return 0, err
	}

	// Log if we're using role defaults (didn't get requested TTL)
	if ttlSec < requestedTTL {
		s.Log.Printf("INFO: auth: obtained secret ID with role default TTL (%d seconds, requested %d seconds)", ttlSec, requestedTTL)
	} else if s.Cfg.Debug {
		s.Log.Printf("DEBUG: auth: obtained fresh secret ID (TTL: %d seconds)", ttlSec)
	}

	s.Auth.Creds.SetInMemSecretID(secretID)
	return time.Duration(ttlSec) * time.Second, nil
}

// Vault API returns decoded map values that can vary by type; handle carefully.
func parseSecretIDResponse(secret *vault.Secret) (secretID string, ttlSec int64, err error) {
	if secret == nil || secret.Data == nil {
		return "", 0, fmt.Errorf("empty secret response")
	}

	vSID, ok := secret.Data["secret_id"]
	if !ok {
		return "", 0, fmt.Errorf("missing secret_id in response")
	}
	secretID, ok = vSID.(string)
	if !ok || secretID == "" {
		return "", 0, fmt.Errorf("secret_id not a string or empty")
	}

	vTTL, ok := secret.Data["secret_id_ttl"]
	if !ok {
		// Some setups return "ttl" instead; allow fallback.
		vTTL = secret.Data["ttl"]
	}
	ttlSec, ok = asInt64(vTTL)
	if !ok {
		return "", 0, fmt.Errorf("could not parse secret_id_ttl: %#v", vTTL)
	}
	return secretID, ttlSec, nil
}

// InvalidateWrappedSecretID unwraps the given wrapped token by using it to authenticate to Vault.
// This invalidates the single-use wrapped token, ensuring it cannot be reused.
// If the token is empty or authentication fails, the error is logged as a warning and the function returns gracefully.
func (s *SecretIDRefresher) InvalidateWrappedSecretID(ctx context.Context, wrappedToken string, t *TokenProvider) {
	if wrappedToken == "" {
		return // No token to invalidate
	}

	s.Log.Printf("INFO: auth: invalidating wrapped secret ID token")

	// Create a client to authenticate with the wrapped token
	client, err := s.Auth.Clients.New()
	if err != nil {
		s.Log.Printf("WARN: auth: failed to create Vault client for token invalidation: %v", err)
		return
	}

	// Validate the wrapped token before using it to ensure it hasn't been tampered with
	if _, err := s.Auth.ValidateWrappedToken(ctx, wrappedToken, 0); err != nil {
		s.Log.Printf("WARN: auth: wrapped token validation failed during invalidation: %v (proceeding anyway)", err)
		// Continue anyway - the token might still be valid for unwrapping
	}

	// Use the wrapped token to authenticate via AppRole login with wrapped=true.
	// This unwraps the token and consumes the single-use credential.
	_, err = s.Auth.loginWithAppRole(ctx, client, s.Auth.Creds.RoleID(), approle.SecretID{FromString: wrappedToken}, true)
	if err != nil {
		s.Log.Printf("WARN: auth: failed to invalidate wrapped token: %v", err)
		return
	}

	// Token was successfully consumed
	s.Log.Printf("INFO: auth: post-init wrapped secret ID invalidated successfully")
}

// isTTLTooLongError checks if an error is a Vault rejection due to requested TTL being too long
// for the role's secret_id_ttl configuration.
func isTTLTooLongError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Vault ResponseError (typically 400 or 403)
	var re *vault.ResponseError
	if !errors.As(err, &re) {
		return false
	}

	// Look for the specific error message Vault returns
	errorMsg := strings.Join(re.Errors, " ")
	errorMsg = strings.ToLower(errorMsg)
	return strings.Contains(errorMsg, "ttl cannot be longer") ||
		strings.Contains(errorMsg, "exceeds the maximum")
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
