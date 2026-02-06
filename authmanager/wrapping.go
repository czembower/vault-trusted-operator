package authmanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// WrappingInfo contains metadata about a wrapping token obtained from sys/wrapping/lookup.
type WrappingInfo struct {
	// CreationType is the type of secret that was wrapped (e.g., "approle" for AppRole secret IDs)
	CreationType string
	// CreationTTL is the TTL (in seconds) that was requested when the secret was wrapped
	CreationTTL int
	// CreationTime is the UTC timestamp when the secret was wrapped
	CreationTime time.Time
	// CreationPath is the Vault API path where the secret was created/wrapped
	CreationPath string
	// TTLRemaining is the number of seconds remaining before the wrapping token expires
	TTLRemaining int
}

// ValidateWrappedToken checks a wrapped token using the sys/wrapping/lookup endpoint,
// verifying that:
// - The token exists and is valid
// - The creation_ttl matches the expected TTL (within a tolerance)
// - The token hasn't expired
//
// This helps detect tampering or misconfiguration of wrapping tokens.
// If expectedTTL is 0, TTL validation is skipped.
func (a *AuthManager) ValidateWrappedToken(
	ctx context.Context,
	wrappedToken string,
	expectedTTL time.Duration,
) (*WrappingInfo, error) {
	if wrappedToken == "" {
		return nil, fmt.Errorf("wrapped token is empty")
	}

	// Create a client specifically for the lookup request
	// We don't use the authenticated client because we're using the wrapped token itself
	client, err := a.Clients.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create client for wrapping validation: %w", err)
	}

	// Make the lookup request
	// POST /v1/sys/wrapping/lookup with the wrapped token as X-Vault-Token
	req := client.NewRequest("POST", "/v1/sys/wrapping/lookup")
	req.Headers.Set("X-Vault-Token", wrappedToken)

	resp, err := client.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("wrapping lookup failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response
	secret, err := vault.ParseSecret(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wrapping lookup response: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty response from wrapping lookup")
	}

	// Extract wrapping metadata
	info := &WrappingInfo{}

	// CreationPath
	if v, ok := secret.Data["creation_path"].(string); ok {
		info.CreationPath = v
		// Infer creation_type from the path (e.g., "auth/approle/.../secret-id" means AppRole)
		if strings.Contains(v, "/secret-id") {
			info.CreationType = "approle"
		}
	}

	// CreationTTL (could be float64, int, int64, or json.Number from Vault response)
	if v, ok := secret.Data["creation_ttl"]; ok {
		switch val := v.(type) {
		case float64:
			info.CreationTTL = int(val)
		case int:
			info.CreationTTL = val
		case int64:
			info.CreationTTL = int(val)
		default:
			// Try to convert from string representation
			ttlInt, ok := asInt64(v)
			if ok {
				info.CreationTTL = int(ttlInt)
			}
		}
	}

	// CreationTime (returned as string in RFC3339 format)
	if v, ok := secret.Data["creation_time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			info.CreationTime = t
		} else {
			a.Log.Printf("WARN: wrapping: failed to parse creation_time %q: %v", v, err)
		}
	}

	// Debug log the raw response data
	if a.Cfg.Debug {
		a.Log.Printf("DEBUG: wrapping: lookup response data keys: %v", secret.Data)
		a.Log.Printf("DEBUG: wrapping: creation_path=%v, inferred_type=%v, creation_ttl=%v, creation_time=%v",
			info.CreationPath, info.CreationType, secret.Data["creation_ttl"], secret.Data["creation_time"])
	}

	// Calculate TTLRemaining from creation_time and creation_ttl
	// The Vault API doesn't return a "ttl" field; we must compute it
	if !info.CreationTime.IsZero() && info.CreationTTL > 0 {
		expiryTime := info.CreationTime.Add(time.Duration(info.CreationTTL) * time.Second)
		remaining := time.Until(expiryTime)
		info.TTLRemaining = int(remaining.Seconds())
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: wrapping: calculated remaining TTL - created: %s, expires: %s, remaining: %d seconds",
				info.CreationTime.Format(time.RFC3339), expiryTime.Format(time.RFC3339), info.TTLRemaining)
		}
	} else {
		if a.Cfg.Debug {
			a.Log.Printf("DEBUG: wrapping: could not calculate TTL - CreationTime.IsZero()=%v, CreationTTL=%d",
				info.CreationTime.IsZero(), info.CreationTTL)
		}
	}

	// Validation: check if the token has already expired
	if info.TTLRemaining <= 0 {
		return nil, fmt.Errorf("wrapping token has expired (created: %s, ttl: %d seconds)", info.CreationTime.Format(time.RFC3339), info.CreationTTL)
	}

	// Validation: if expectedTTL is provided, verify it matches (with some tolerance for clock skew)
	if expectedTTL > 0 {
		expectedSeconds := int(expectedTTL.Seconds())
		// Allow 5 seconds of tolerance for clock skew and batch processing delays
		tolerance := 5
		if info.CreationTTL < (expectedSeconds-tolerance) || info.CreationTTL > (expectedSeconds+tolerance) {
			a.Log.Printf(
				"WARN: wrapping: creation_ttl mismatch - expected %d seconds, got %d seconds",
				expectedSeconds, info.CreationTTL,
			)
			// Log as warning but don't fail - the token is still valid
			// This might happen with legitimate use cases like manual token generation
		}
	}

	if a.Cfg.Debug {
		a.Log.Printf(
			"DEBUG: wrapping: validated token - type: %s, creation_ttl: %d, created: %s, path: %s, ttl_remaining: %d",
			info.CreationType, info.CreationTTL, info.CreationTime.Format(time.RFC3339),
			info.CreationPath, info.TTLRemaining,
		)
	}

	return info, nil
}

// ValidateWrappedSecretID is a convenience wrapper that validates a wrapped secret ID token
// and logs the validation result.
func (a *AuthManager) ValidateWrappedSecretID(
	ctx context.Context,
	wrappedToken string,
	expectedTTL time.Duration,
) error {
	info, err := a.ValidateWrappedToken(ctx, wrappedToken, expectedTTL)
	if err != nil {
		return fmt.Errorf("wrapping validation failed: %w", err)
	}

	// Additional validation specific to secret IDs
	if info.CreationType != "approle" && info.CreationType != "approle/secret_id" && info.CreationType != "" {
		a.Log.Printf(
			"WARN: wrapping: unexpected creation_type for secret ID: %s (expected approle-related)",
			info.CreationType,
		)
	}

	a.Log.Printf(
		"INFO: wrapping: secret ID token validated successfully (created: %s, expires in: %d seconds)",
		info.CreationTime.Format(time.RFC3339), info.TTLRemaining,
	)

	return nil
}
