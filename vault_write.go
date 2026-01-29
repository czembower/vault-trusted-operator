// vault_write.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// vaultWrite performs a Vault write using RawRequest so we can set per-request headers (like X-Vault-Wrap-TTL)
// without mutating the global client headers.
func vaultWrite(ctx context.Context, client *vault.Client, path string, payload map[string]any, wrapTTL *time.Duration) (*vault.Secret, error) {
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
