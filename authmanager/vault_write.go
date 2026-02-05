package authmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
) (*vault.Secret, error) {

	// attempt #1
	secret, err := vaultWriteOnce(ctx, auth, path, payload, wrapTTL, t)
	if err == nil {
		return secret, nil
	}

	// If token rejected, force reauth and retry once.
	if isTokenRejected(err) {
		auth.Log.Printf("ERROR: auth: token rejected")
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

	// Check for Vault ResponseError with 401/403 status
	var re *vault.ResponseError
	if !errors.As(err, &re) {
		return false
	}

	if re.StatusCode != 401 && re.StatusCode != 403 {
		return false
	}

	// Try to distinguish "token rejected" from genuine ACL denial.
	// NOTE: Vault returns 403 for both bad token and policy denial.
	msg := strings.ToLower(strings.Join(re.Errors, " "))
	return strings.Contains(msg, "bad token") ||
		strings.Contains(msg, "missing client token") ||
		strings.Contains(msg, "permission denied")
}
