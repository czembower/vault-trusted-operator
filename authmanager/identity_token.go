package authmanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OIDCTokenResponse is the response from /v1/identity/oidc/token/{role-name}
type OIDCTokenResponse struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Token string `json:"token"`
	} `json:"data"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
}

// OIDCTokenIssuer handles fetching identity tokens from Vault
type OIDCTokenIssuer struct {
	HTTP      *http.Client
	VaultAddr string
	Token     string
	Namespace string
	Log       interface{} // *log.Logger
}

// GetIdentityToken requests an identity token for the specified role
// Returns the JWT token string
func (o *OIDCTokenIssuer) GetIdentityToken(ctx context.Context, roleName string) (string, error) {
	if roleName == "" {
		return "", fmt.Errorf("role name cannot be empty")
	}

	// Build request URL
	path := fmt.Sprintf("/v1/identity/oidc/token/%s", roleName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.VaultAddr+path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set auth headers
	req.Header.Set("X-Vault-Token", o.Token)
	if o.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", o.Namespace)
	}

	// Execute request
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if tokenResp.Data.Token == "" {
		return "", fmt.Errorf("no token in response")
	}

	return tokenResp.Data.Token, nil
}

// ExtractTokenExpiry attempts to extract the exp claim from a JWT without validation
// This is a best-effort attempt and doesn't validate the signature or timestamps
// Returns nil if the token is malformed or doesn't contain an exp claim
func ExtractTokenExpiry(tokenString string) *time.Time {
	// JWT format: header.payload.signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode payload (second part) - add padding if necessary
	payload := parts[1]

	// Base64 URL padding
	switch len(payload) % 4 {
	case 1:
		return nil // Invalid base64
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	// Decode base64
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}

	// Parse JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil
	}

	// Extract exp claim
	if exp, ok := claims["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		return &t
	}

	return nil
}
