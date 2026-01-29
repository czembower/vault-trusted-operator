// secret_id.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type SecretIDRefresher struct {
	Cfg  Config
	Log  *log.Logger
	Auth *AuthManager
}

// Run keeps an in-memory secret-id fresh by periodically requesting a new one.
// This avoids forcing an interactive OIDC bootstrap if token renewal fails at an inconvenient time.
func (s *SecretIDRefresher) Run(ctx context.Context) {
	// Initial delay: try immediately
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ttl, err := s.refreshOnce(ctx, s.Cfg.InMemSecretTTL, nil) // raw secret-id (no wrapping)
		if err != nil {
			s.Log.Printf("secret-id refresh failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
				continue
			}
		}

		sleepFor := time.Duration(float64(ttl) * s.Cfg.RenewFraction)
		if sleepFor < 1*time.Second {
			sleepFor = 1 * time.Second
		}

		s.Log.Printf("secret-id TTL: %s (refresh in %s)", ttl.String(), sleepFor.String())

		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepFor):
		}
	}
}

// WriteWrappedSecretIDToFile requests a wrapped secret-id and writes the wrapping token to SecretIDFile.
// The wrapping token and secret ID are both valid for the period set by Cfg.WrapTTL
func (s *SecretIDRefresher) WriteWrappedSecretIDToFile(ctx context.Context) error {
	_, err := s.refreshOnce(ctx, s.Cfg.WrapTTL, &s.Cfg.WrapTTL) // wrapped token output
	return err
}

func (s *SecretIDRefresher) refreshOnce(ctx context.Context, rawTTL time.Duration, wrapTTL *time.Duration) (time.Duration, error) {
	client, err := s.Auth.Client(ctx)
	if err != nil {
		return 0, err
	}

	payload := map[string]any{}
	if wrapTTL == nil {
		// raw secret-id request includes a TTL
		payload["ttl"] = int(rawTTL.Seconds())
	}

	secret, err := vaultWrite(ctx, client, s.Cfg.AppRoleSecretIDPath(), payload, wrapTTL)
	if err != nil {
		return 0, err
	}

	// Wrapped path: write wrap token to file
	if wrapTTL != nil {
		if secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
			return 0, fmt.Errorf("expected wrap token, got none")
		}
		token := secret.WrapInfo.Token
		if err := os.WriteFile(s.Cfg.SecretIDFile, []byte(token), fs.FileMode(0o600)); err != nil {
			return 0, err
		}
		s.Auth.Creds.SetWrappedSecretIDToken(token)
		return time.Duration(secret.WrapInfo.TTL) * time.Second, nil
	}

	// Raw secret-id response: store in memory
	secretID, ttlSec, err := parseSecretIDResponse(secret)
	if err != nil {
		return 0, err
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
