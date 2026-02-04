package authmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

func vaultWriteWithReauth(
	ctx context.Context,
	auth *AuthManager,
	path string,
	payload map[string]any,
	wrapTTL *time.Duration,
	t *TokenProvider,
	s *SecretIDRefresher,
) (*vault.Secret, error) {

	// attempt #1
	secret, err := vaultWriteOnce(ctx, auth, path, payload, wrapTTL, t)
	if err == nil {
		return secret, nil
	}

	// If token rejected, force reauth and retry once.
	if isTokenRejected(err) {
		auth.Log.Printf("auth: token rejected")
		auth.ForceReauth()

		// attempt #2
		return vaultWriteOnce(ctx, auth, path, payload, wrapTTL, t)
	}

	return nil, err
}

func vaultWriteOnce(
	ctx context.Context,
	auth *AuthManager,
	path string,
	payload map[string]any,
	wrapTTL *time.Duration,
	t *TokenProvider,
) (*vault.Secret, error) {

	client, err := auth.Client(ctx, t)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req := client.NewRequest("POST", "/v1/"+trimLeadingSlash(path))
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.Headers.Set("Content-Type", "application/json")

	if wrapTTL != nil {
		req.Headers.Set("X-Vault-Wrap-TTL", fmt.Sprintf("%d", int(wrapTTL.Seconds())))
	}

	resp, err := client.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	secret, err := vault.ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func trimLeadingSlash(s string) string {
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}

func isTokenRejected(err error) bool {
	if err == nil {
		return false
	}

	// RawRequestWithContext errors often wrap a ResponseError
	var re *vault.ResponseError
	if ok := asResponseError(err, &re); ok {
		if re.StatusCode == 401 || re.StatusCode == 403 {
			// Try to distinguish "token rejected" from genuine ACL denial.
			// NOTE: Vault returns 403 for both bad token and policy denial.
			// If you want to reauth only on "bad token", check message text.
			msg := strings.ToLower(strings.Join(re.Errors, " "))
			if strings.Contains(msg, "bad token") ||
				strings.Contains(msg, "missing client token") ||
				strings.Contains(msg, "permission denied") {
				return true
			}
		}
	}
	return false
}

// Go doesn't have errors.As for non-stdlib constraints? It does; use errors.As.
// This helper exists so you can keep the calling code tidy.
func asResponseError(err error, target **vault.ResponseError) bool {
	// standard library
	// return errors.As(err, target)

	// If you already use errors.As elsewhere, just use that directly.
	// Included explicitly here to avoid ambiguity in the snippet.
	type aser interface{ Unwrap() error }
	for err != nil {
		if re, ok := err.(*vault.ResponseError); ok {
			*target = re
			return true
		}
		u, ok := err.(aser)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}
