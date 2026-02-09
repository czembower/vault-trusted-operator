package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"vault-trusted-operator/authmanager"
	"vault-trusted-operator/broker"
	"vault-trusted-operator/config"
	"vault-trusted-operator/keystore"

	"github.com/elastic/go-sysinfo"
)

// debugDumpState creates a debug representation of StatePayload with masked tokens
func debugDumpState(st *StatePayload) string {
	// Create a safe copy with masked tokens
	dump := map[string]interface{}{
		"role_id_present":        st.RoleID != "",
		"role_id":                maskSecret(st.RoleID, 32),
		"wrapped_token_present":  st.WrappedSecretIDToken != "",
		"wrapped_token":          maskSecret(st.WrappedSecretIDToken, 32),
		"identity_token_present": st.OIDCIdentityToken != "",
		"identity_token":         maskSecret(st.OIDCIdentityToken, 32),
		"selected_vault_addr":    st.SelectedVaultAddr,
		"config": map[string]interface{}{
			"vault_addrs":         st.Config.VaultAddrs,
			"namespace":           st.Config.Namespace,
			"appRole_mount":       st.Config.AppRoleMount,
			"appRole_role":        st.Config.AppRoleRole,
			"identity_token_role": st.Config.IdentityTokenRole,
			"probe_timeout":       st.Config.ProbeTimeout.String(),
			"wrap_ttl":            st.Config.WrapTTL.String(),
		},
	}
	b, _ := json.MarshalIndent(dump, "", "  ")
	return string(b)
}

// maskSecret returns masked representation of secret showing length and first chars
func maskSecret(secret string, showChars int) string {
	if secret == "" {
		return "[empty]"
	}
	if len(secret) <= showChars {
		return secret + " [" + fmt.Sprintf("%d chars, masked", len(secret)) + "]"
	}
	return secret[:showChars] + "... [" + fmt.Sprintf("%d chars, masked", len(secret)) + "]"
}

// writeTokenFile writes a plaintext token to a file with restrictive permissions (0600)
// Returns nil on success or if filePath is empty (feature disabled)
func writeTokenFile(filePath, token string) error {
	if filePath == "" {
		// Feature disabled
		return nil
	}

	// Write with restrictive permissions: owner-only read/write
	if err := os.WriteFile(filePath, []byte(token), 0600); err != nil {
		return fmt.Errorf("write token file %s: %w", filePath, err)
	}

	return nil
}

func main() {
	cfg := config.MustLoadConfig()
	reconfigure := cfg.Reconfigure
	debug := cfg.Debug
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	kp, err := (&keystore.Auto{
		Log:         logger,
		Mode:        cfg.KeyStore,
		FileKeyPath: cfg.StateKeyFile,
		BlobPath:    cfg.BlobFile,
	}).Resolve()
	if err != nil {
		logger.Fatalf("keystore: %v", err)
	}

	key, err := kp.GetOrCreateKey("vault-trusted-operator:v1")
	if err != nil {
		logger.Fatalf("keystore %s: %v", kp.Name(), err)
	}
	logger.Printf("INFO: keystore: %s", kp.Name())
	aad := []byte(getUniqueID())
	var st StatePayload

	if !cfg.Reconfigure {
		if err := LoadSealedState(cfg.StateFile, key, &st, aad); err == nil {
			if debug {
				logger.Printf("DEBUG: state file=%s", cfg.StateFile)
				logger.Printf("DEBUG: state key=%s", cfg.StateKeyFile)
				logger.Printf("DEBUG: loading state: role_id_present=%t wrapped_token_present=%t",
					st.RoleID != "",
					st.WrappedSecretIDToken != "",
				)
				logger.Printf("DEBUG: state payload (plaintext):\n%s", debugDumpState(&st))
			}
			// Note: SaveCount should be checked here for rollback detection if needed
			// Use persisted config as the source of truth on subsequent runs.
			cfg = st.Config
			logger.Printf("INFO: config: loaded sealed state from %s", cfg.StateFile)
			if SetFlagNamesCSV() != "" {
				logger.Printf("WARN: ignored command line arguments due to present state file: %v", SetFlagNamesCSV())
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			logger.Fatalf("failed to load sealed state file: %v", err)
		}
	}

	if cfg.Reconfigure {
		// Reconfigure mode: wipe state and start fresh
		st = StatePayload{
			Config: cfg,
		}
		logger.Printf("INFO: reconfigure mode enabled; starting fresh with new config")
		logger.Printf("INFO: vault addresses: %v", cfg.VaultAddrs)
	}

	cfg.Reconfigure = reconfigure
	cfg.Debug = debug
	httpc := NewHTTPClient(cfg)

	selector := &ServerSelector{
		HTTP:         httpc,
		HealthPath:   "/v1/sys/health",
		ProbeTimeout: cfg.ProbeTimeout,
		Logger:       logger,
		AcceptStatus: cfg.AcceptHealthStatuses,
		InsecureTLS:  cfg.InsecureTLS,
		PreferLowest: true,
	}

	logger.Printf("INFO: config: probing Vault servers: %v", cfg.VaultAddrs)
	primary, err := selector.Select(ctx, cfg.VaultAddrs)
	if err != nil {
		logger.Printf("ERROR: config: server selection failed: %v", err)
		logger.Printf("ERROR: config: attempted Vault addresses: %v", cfg.VaultAddrs)
		logger.Printf("ERROR: config: health check path: %s (ProbeTimeout: %v, AcceptStatuses: %v)", selector.HealthPath, cfg.ProbeTimeout, cfg.AcceptHealthStatuses)
		logger.Printf("ERROR: run with --debug flag for detailed probe output")
		logger.Fatalf("no usable Vault address: %v", err)
	}
	logger.Printf("INFO: config: using Vault server: %s", primary)

	creds := &authmanager.CredStore{}
	if st.RoleID != "" {
		creds.SetRoleID(st.RoleID)
	}
	if st.WrappedSecretIDToken != "" {
		creds.SetWrappedSecretIDToken(st.WrappedSecretIDToken)
	}

	clientFactory := &authmanager.VaultClientFactory{
		Cfg:       cfg,
		HTTP:      httpc,
		VaultAddr: primary,
	}

	auth := &authmanager.AuthManager{
		Cfg:     cfg,
		Log:     logger,
		Clients: clientFactory,
		Creds:   creds,
		OIDC:    &authmanager.OIDCBootstrapper{Cfg: cfg, HTTP: httpc, Log: logger},
	}

	t := *authmanager.NewTokenProvider()
	// Ensure we can authenticate at least once.
	if _, err := auth.Client(ctx, &t); err != nil {
		logger.Fatalf("initial auth failed: %v\nReconfiguration is required.", err)
	}

	// Keep a fresh in-memory SecretID so that if token renewal ever fails,
	// we can re-login without forcing interactive OIDC in the background.
	secretIDRefresher := &authmanager.SecretIDRefresher{
		Cfg:  cfg,
		Log:  logger,
		Auth: auth,
	}
	// Wire the refresher into the auth manager for proactive reauth
	auth.SIDRefr = secretIDRefresher

	// Acquire and store a fresh wrapped secret ID immediately after successful initialization.
	// If the role's secret_id_ttl is lower than the requested TTL, we'll fall back to the role default.
	//
	// Wrapped Secret ID Lifecycle:
	// 1. On startup: Load wrapped token from state (if available)
	// 2. Use wrapped token to authenticate (unwraps it as part of AppRole login) - validates it
	// 3. Immediately after successful login: Get fresh wrapped secret ID
	// 4. Persist new token to state (fallback if app crashes before shutdown)
	// 5. Background goroutine: Refresh token periodically at 50% of TTL (safety net)
	// 6. On graceful shutdown: Invalidate current token, get fresh one, persist for next startup
	// 7. All new tokens are validated using sys/wrapping/lookup
	// Note: Wrapped token requests may fall back to role default if requested TTL exceeds secret_id_ttl
	if err := secretIDRefresher.RefreshWrappedSecretID(ctx, &t); err != nil {
		logger.Printf("WARN: failed to acquire initial wrapped secret ID: %v (will retry at shutdown)", err)
	} else if cfg.Debug {
		logger.Printf("DEBUG: acquired fresh wrapped secret ID for recovery")
	}

	// Persist the post-initialization wrapped secret ID to state immediately.
	// This ensures if the process crashes before shutdown, we still have a recent fallback token.
	if wrappedToken := creds.WrappedSecretIDToken(); wrappedToken != "" {
		st.WrappedSecretIDToken = wrappedToken
		if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
			logger.Printf("WARN: failed to persist post-init wrapped secret ID: %v", err)
		} else if cfg.Debug {
			logger.Printf("DEBUG: persisted post-init wrapped secret ID to state")
		}
	}

	// If OIDC token role is configured, immediately request and persist an identity token
	if cfg.IdentityTokenRole != "" {
		issuer := &authmanager.OIDCTokenIssuer{
			HTTP:      httpc,
			VaultAddr: primary,
			Token:     t.GetToken(),
			Namespace: cfg.Namespace,
		}
		if idToken, err := issuer.GetIdentityToken(ctx, cfg.IdentityTokenRole); err != nil {
			logger.Printf("WARN: failed to acquire initial OIDC identity token: %v (will retry at shutdown)", err)
		} else {
			st.OIDCIdentityToken = idToken
			if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
				logger.Printf("WARN: failed to persist post-init OIDC identity token: %v", err)
			} else if cfg.Debug {
				logger.Printf("DEBUG: persisted initial OIDC identity token to state")
			}
			// Write plaintext token file if configured
			if err := writeTokenFile(cfg.IdentityTokenFile, idToken); err != nil {
				logger.Printf("WARN: failed to write OIDC token file: %v", err)
			} else if cfg.IdentityTokenFile != "" && cfg.Debug {
				logger.Printf("DEBUG: wrote OIDC identity token to file: %s", cfg.IdentityTokenFile)
			}
		}
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		secretIDRefresher.Run(ctx, &t)
	})

	// Also refresh the wrapped secret-id token periodically (before it expires)
	// This ensures we always have a fresh token available at next startup
	wg.Go(func() {
		secretIDRefresher.RunWrappedSecretIDRefresher(ctx, &t)
	})

	// Periodically persist wrapped token updates to state
	wg.Go(func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		var lastPersistedToken string

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check if wrapped token has been updated
				currentToken := creds.WrappedSecretIDToken()
				if currentToken != "" && currentToken != lastPersistedToken {
					// Token has changed - persist to state
					st.Config = cfg
					st.RoleID = creds.RoleID()
					st.WrappedSecretIDToken = currentToken
					st.SelectedVaultAddr = primary
					if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
						logger.Printf("WARN: failed to persist wrapped secret-id token refresh: %v", err)
					} else {
						if cfg.Debug {
							logger.Printf("DEBUG: persisted refreshed wrapped secret-id token to state")
						}
						lastPersistedToken = currentToken
					}
				}
			}
		}
	})

	// Periodically refresh and persist OIDC identity token if configured
	// Refresh timing is based on the token's exp claim - refreshes at 90% of TTL
	if cfg.IdentityTokenRole != "" {
		wg.Go(func() {
			// Helper function to calculate next refresh time
			calcNextRefresh := func(token string) time.Duration {
				expTime := authmanager.ExtractTokenExpiry(token)
				if expTime == nil {
					// Can't extract exp claim - use conservative 1 hour interval
					return 1 * time.Hour
				}

				// Calculate time until expiry
				timeUntilExpiry := time.Until(*expTime)

				// Refresh at 90% of token lifetime
				refreshAt := time.Duration(float64(timeUntilExpiry) * 0.9)

				// Ensure we have a minimum 1 minute refresh interval
				if refreshAt < 1*time.Minute {
					refreshAt = 1 * time.Minute
				}

				return refreshAt
			}

			// Calculate initial refresh delay
			refreshAfter := calcNextRefresh(st.OIDCIdentityToken)
			timer := time.NewTimer(refreshAfter)
			defer timer.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					issuer := &authmanager.OIDCTokenIssuer{
						HTTP:      httpc,
						VaultAddr: primary,
						Token:     t.GetToken(),
						Namespace: cfg.Namespace,
					}
					if idToken, err := issuer.GetIdentityToken(ctx, cfg.IdentityTokenRole); err != nil {
						logger.Printf("WARN: failed to refresh OIDC identity token: %v", err)
						// Retry in 5 minutes on error
						timer.Reset(5 * time.Minute)
					} else {
						st.Config = cfg
						st.RoleID = creds.RoleID()
						st.WrappedSecretIDToken = creds.WrappedSecretIDToken()
						st.SelectedVaultAddr = primary
						st.OIDCIdentityToken = idToken
						if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
							logger.Printf("WARN: failed to persist refreshed OIDC identity token: %v", err)
						} else if cfg.Debug {
							logger.Printf("DEBUG: persisted refreshed OIDC identity token to state")
						}
						// Write plaintext token file if configured
						if err := writeTokenFile(cfg.IdentityTokenFile, idToken); err != nil {
							logger.Printf("WARN: failed to write OIDC token file: %v", err)
						} else if cfg.IdentityTokenFile != "" && cfg.Debug {
							logger.Printf("DEBUG: wrote refreshed OIDC identity token to file: %s", cfg.IdentityTokenFile)
						}

						// Calculate next refresh based on new token's exp claim
						nextRefresh := calcNextRefresh(idToken)
						if cfg.Debug {
							logger.Printf("DEBUG: OIDC token will refresh in %v", nextRefresh)
						}
						timer.Reset(nextRefresh)
					}
				}
			}
		})
	}

	brokerCfg := broker.DefaultConfig()
	brokerCfg.PipeName = cfg.PipeName
	brokerCfg.SocketPath = cfg.SocketPath
	brokerCfg.SocketMode = uint32(cfg.SocketMode)
	brokerCfg.VaultAddress = primary
	brokerCfg.VaultNamespace = cfg.Namespace
	brokerCfg.VaultSkipVerify = cfg.InsecureTLS
	brokerCfg.Logger = logger
	brokerCfg.Debug = cfg.Debug
	brokerCfg.AllowedUIDs = cfg.AllowedUIDs
	brokerCfg.AllowedGIDs = cfg.AllowedGIDs
	brokerCfg.HTTPAddr = cfg.HTTPAddr
	brokerCfg.VaultAddresses = cfg.VaultAddrs
	brokerCfg.ServerSelector = selector
	// Provide identity token to broker for /health endpoint
	brokerCfg.IdentityTokenFunc = func() string {
		return st.OIDCIdentityToken
	}

	if len(cfg.AllowedUIDs) > 0 || len(cfg.AllowedGIDs) > 0 {
		logger.Printf("INFO: broker: access control enabled - UIDs: %v, GIDs: %v", cfg.AllowedUIDs, cfg.AllowedGIDs)
	}

	logger.Printf("INFO: running; press ctrl+c to exit")

	brokerErrCh := make(chan error, 1)
	go func() {
		brokerErrCh <- broker.Run(ctx, brokerCfg, &t, auth)
	}()

	// Wait for either signal (ctx cancelled) or broker fatal error.
	select {
	case <-ctx.Done():
		// Normal shutdown path (SIGINT/SIGTERM)
	case err := <-brokerErrCh:
		if err != nil && err != context.Canceled {
			logger.Printf("ERROR: broker stopped unexpectedly: %v", err)
			// Fall through to shutdown logic instead of Fatalf so credentials are persisted
		}
	}

	// Cancel context to signal all background goroutines, then wait for them
	// to finish before proceeding. This prevents the persistence ticker from
	// racing with shutdown's own SaveSealedState call.
	cancel()
	wg.Wait()

	// Graceful shutdown: Attempt to obtain a fresh wrapped token for next startup
	logger.Println("INFO: maint: shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Save the current wrapped token before invalidation in case refresh fails.
	// If we can't get a new one, we'll keep the existing one in state.
	preservedToken := creds.WrappedSecretIDToken()

	// 1. Invalidate the current wrapped token to prevent credential reuse.
	//    This unwraps the token and consumes the secret ID, ensuring single-use guarantees.
	if preservedToken != "" {
		secretIDRefresher.InvalidateWrappedSecretID(shutdownCtx, preservedToken, &t)
	}

	// 2. Get a fresh wrapped token for next startup (validated and stored in CredStore)
	//    Only persist to state if this succeeds. If it fails, we keep the pre-invalidation token.
	var refreshSucceeded bool
	if err := secretIDRefresher.RefreshWrappedSecretID(shutdownCtx, &t); err != nil {
		logger.Printf("WARN: config: failed to obtain fresh wrapped secret-id for shutdown: %v (keeping existing token in state)", err)
		refreshSucceeded = false
	} else {
		logger.Printf("INFO: config: obtained fresh wrapped secret-id token (wrapping TTL: %s)", cfg.WrapTTL)

		// Only warn if we actually had to fall back to role defaults
		if secretIDRefresher.DidLastRefreshFallBackToDefault() {
			logger.Printf("WARN: config: contained secret ID is using role's default TTL, not the requested TTL - verify role configuration allows desired TTL")
		}
		refreshSucceeded = true
	}

	// 3. Persist state for next startup
	//    - If refresh succeeded: persist the new fresh token from CredStore and selected vault address
	//    - If refresh failed: keep the pre-invalidation token (no state modification)
	logger.Printf("INFO: config: persisting state for next startup")
	st.Config = cfg
	st.RoleID = creds.RoleID()

	if refreshSucceeded {
		// New token was successfully procured and validated
		st.WrappedSecretIDToken = creds.WrappedSecretIDToken()
		// Persist the server address only if credential refresh succeeded (indicates upstream was healthy)
		st.SelectedVaultAddr = primary
		logger.Printf("INFO: config: persisted fresh wrapped secret-id token and vault address to state")
	} else {
		// Refresh failed; preserve the pre-invalidation token that was already in state
		st.WrappedSecretIDToken = preservedToken
		// Don't persist SelectedVaultAddr if refresh failed - let next startup re-probe all addresses
		// This forces a fresh server selection on next startup instead of using a potentially stale address
		st.SelectedVaultAddr = ""
		logger.Printf("INFO: config: refresh failed; preserved existing wrapped secret-id token; cleared vault address for re-probe on next startup")
	}

	if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
		logger.Fatalf("failed to save sealed state: %v", err)
	}
	if cfg.Debug {
		logger.Printf("DEBUG: shutdown state persisted (plaintext):\n%s", debugDumpState(&st))
	}
	// Zero the encryption key from memory now that state has been saved
	ZeroBytes(key)
	logger.Println("INFO: done")
}

func SetFlagNamesCSV() string {
	seen := map[string]struct{}{}

	flag.Visit(func(f *flag.Flag) {
		seen[f.Name] = struct{}{}
	})

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}

	sort.Strings(names)
	index := slices.Index(names, "debug")
	if index != -1 {
		names = slices.Delete(names, index, index+1)
	}
	return strings.Join(names, ", ")
}

func getUniqueID() string {
	self, err := sysinfo.Host()
	if err != nil {
		log.Fatal(err)
	}

	// Build host-specific AAD binding: hostname is stable, doesn't change with OS updates
	// This ensures state is bound to the host it was created on
	hostname, _ := os.Hostname()

	// Format: architecture-platform-uniqueID-hostname
	// Provides defense-in-depth by binding state to the specific host machine
	return self.Info().Architecture + "-" + self.Info().OS.Platform + "-" + self.Info().UniqueID + "-" + hostname
}
