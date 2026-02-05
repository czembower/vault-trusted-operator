package authmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"vault-trusted-operator/config"

	vault "github.com/hashicorp/vault/api"
)

type SecretIDRefresher struct {
	Cfg  config.Config
	Log  *log.Logger
	Auth *AuthManager
}

// Run keeps an in-memory secret-id fresh by periodically requesting a new one.
// This avoids forcing an interactive OIDC bootstrap if token renewal fails at an inconvenient time.
func (s *SecretIDRefresher) Run(ctx context.Context, t *TokenProvider) {
	s.Log.Printf("auth: secret-id refresher running")

	// Track current sleep timer for cleanup on context cancel
	var currentTimer *time.Timer

	for {
		select {
		case <-ctx.Done():
			if currentTimer != nil {
				currentTimer.Stop()
			}
			return
		default:
		}

		ttl, err := s.RefreshOnce(ctx, s.Cfg.InMemSecretTTL, nil, t) // raw secret-id (no wrapping)
		if err != nil {
			s.Log.Printf("secret-id refresh failed: %v", err)
			// Brief retry on failure
			currentTimer = time.NewTimer(1 * time.Second)
			select {
			case <-ctx.Done():
				currentTimer.Stop()
				return
			case <-currentTimer.C:
				continue
			}
		}

		sleepFor := time.Duration(float64(ttl) * s.Cfg.RenewFraction)
		if sleepFor < 1*time.Second {
			sleepFor = 1 * time.Second
		}

		s.Log.Printf("auth: secret-id TTL: %s (refresh in %s)", ttl.String(), sleepFor.String())

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

func (s *SecretIDRefresher) RefreshWrappedSecretID(ctx context.Context, t *TokenProvider) error {
	_, err := s.RefreshOnce(ctx, s.Cfg.WrapTTL, &s.Cfg.WrapTTL, t) // wrapped token output, stored in CredStore
	return err
}

// RefreshOnce performs a single secret ID refresh operation.
// If wrapTTL is nil, returns a raw secret ID; if non-nil, returns a wrapped token.
func (s *SecretIDRefresher) RefreshOnce(ctx context.Context, rawTTL time.Duration, wrapTTL *time.Duration, t *TokenProvider) (time.Duration, error) {
	payload := map[string]any{}
	if wrapTTL == nil {
		// raw secret-id request includes a TTL
		payload["ttl"] = int(rawTTL.Seconds())
	}

	secret, err := vaultWriteWithReauth(ctx, s.Auth, s.Cfg.AppRoleSecretIDPath(), payload, wrapTTL, t)

	if err != nil {
		return 0, err
	}

	// write wrapping token to state
	if wrapTTL != nil {
		if secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
			return 0, fmt.Errorf("expected wrap token, got none")
		}
		token := secret.WrapInfo.Token
		s.Auth.Creds.SetWrappedSecretIDToken(token)
		return time.Duration(secret.WrapInfo.TTL) * time.Second, nil
	}

	// Raw secret-id response: store in memory
	secretID, ttlSec, err := parseSecretIDResponse(secret)
	if err != nil {
		return 0, err
	}
	s.Log.Printf("auth: obtained fresh secret ID (TTL: %d seconds)", ttlSec)
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
