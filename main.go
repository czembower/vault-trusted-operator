// main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := MustLoadConfig()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	httpc := NewHTTPClient(cfg)

	selector := &ServerSelector{
		HTTP:         httpc,
		HealthPath:   "/v1/sys/health",
		ProbeTimeout: cfg.ProbeTimeout,
		AcceptStatus: cfg.AcceptHealthStatuses,
		InsecureTLS:  cfg.InsecureTLS,
		PreferLowest: true,
	}

	primary, err := selector.Select(ctx, cfg.VaultAddrs)
	if err != nil {
		logger.Fatalf("no usable Vault address: %v", err)
	}
	logger.Printf("using Vault server: %s", primary)

	// Shared state (thread-safe)
	creds := &CredStore{}
	if err := creds.LoadRoleIDFromFile(cfg.RoleIDFile); err != nil {
		logger.Printf("role-id file load: %v", err)
	}
	if err := creds.LoadWrappedSecretIDTokenFromFile(cfg.SecretIDFile); err != nil {
		logger.Printf("secret-id file load: %v", err)
	}

	// Vault client factory (single server chosen above)
	clientFactory := &VaultClientFactory{
		Cfg:       cfg,
		HTTP:      httpc,
		VaultAddr: primary,
	}

	auth := &AuthManager{
		Cfg:     cfg,
		Log:     logger,
		Clients: clientFactory,
		Creds:   creds,
		OIDC:    &OIDCBootstrapper{Cfg: cfg, HTTP: httpc, Log: logger},
	}

	// Ensure we can authenticate at least once (foreground).
	if _, err := auth.Client(ctx); err != nil {
		logger.Fatalf("initial auth failed: %v", err)
	}

	// Keep a fresh in-memory SecretID so that if token renewal ever fails,
	// we can re-login without forcing interactive OIDC in the background.
	secretIDRefresher := &SecretIDRefresher{
		Cfg:  cfg,
		Log:  logger,
		Auth: auth,
	}
	go secretIDRefresher.Run(ctx)

	logger.Printf("running; press ctrl+c to exit")

	<-ctx.Done()

	// On shutdown: write a wrapped secret-id token to disk (so a service can restart non-interactively).
	logger.Println("---------------------------------------------------")
	logger.Printf("writing wrapped secret-id token to: %s", cfg.SecretIDFile)
	logger.Printf("service must be restarted prior to secret-id expiration (%s) to avoid manual authentication\n", cfg.WrapTTL)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := secretIDRefresher.WriteWrappedSecretIDToFile(shutdownCtx); err != nil {
		logger.Fatalf("failed to write wrapped secret-id token: %v", err)
	}
	logger.Println("done")
}
