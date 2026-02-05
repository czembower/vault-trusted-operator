package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"vault-trusted-operator/authmanager"
	"vault-trusted-operator/broker"
	"vault-trusted-operator/config"
	"vault-trusted-operator/keystore"

	"github.com/elastic/go-sysinfo"
)

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
	logger.Printf("keystore: %s", kp.Name())
	aad := []byte(getUniqueID())
	var st StatePayload

	if !cfg.Reconfigure {
		if err := LoadSealedState(cfg.StateFile, key, &st, aad); err == nil {
			if debug {
				logger.Printf("state file=%s", cfg.StateFile)
				logger.Printf("state key=%s", cfg.StateKeyFile)
				logger.Printf("loading state: role_id_present=%t wrapped_token_present=%t",
					st.RoleID != "",
					st.WrappedSecretIDToken != "",
				)
			}
			// Use persisted config as the source of truth on subsequent runs.
			cfg = st.Config
			logger.Printf("config: loaded sealed state from %s", cfg.StateFile)
			if SetFlagNamesCSV() != "" {
				logger.Printf("WARN: ignored command line arguments due to present state file: %v", SetFlagNamesCSV())
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			logger.Fatalf("failed to load sealed state file: %v", err)
		}
	}

	if cfg.Reconfigure {
		st = StatePayload{
			Config: cfg,
		}
		if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
			logger.Fatalf("failed to write initial sealed state file: %v", err)
		}
		logger.Printf("wrote initial sealed state to %s", cfg.StateFile)
	}

	cfg.Reconfigure = reconfigure
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
	logger.Printf("config: using Vault server: %s", primary)

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
	go secretIDRefresher.Run(ctx, &t)

	brokerCfg := broker.DefaultConfig()
	brokerCfg.PipeName = cfg.PipeName
	brokerCfg.SocketPath = cfg.SocketPath
	brokerCfg.SocketMode = uint32(cfg.SocketMode)
	brokerCfg.VaultAddress = primary
	brokerCfg.VaultNamespace = cfg.Namespace
	brokerCfg.VaultSkipVerify = cfg.InsecureTLS
	brokerCfg.Logger = logger
	brokerCfg.AllowedUIDs = cfg.AllowedUIDs
	brokerCfg.AllowedGIDs = cfg.AllowedGIDs

	if len(cfg.AllowedUIDs) > 0 || len(cfg.AllowedGIDs) > 0 {
		logger.Printf("broker: access control enabled - UIDs: %v, GIDs: %v", cfg.AllowedUIDs, cfg.AllowedGIDs)
	}

	if err := broker.Run(ctx, brokerCfg, &t); err != nil && err != context.Canceled {
		logger.Fatalf("broker stopped: %v", err)
	}

	logger.Printf("running; press ctrl+c to exit")

	<-ctx.Done()

	// On shutdown: write a wrapped secret-id token to state (so a service can restart non-interactively).
	logger.Println("maint: shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Get a fresh wrapped token at exit (stored in CredStore)
	if err := secretIDRefresher.RefreshWrappedSecretID(shutdownCtx, &t); err != nil {
		logger.Fatalf("config: failed to refresh wrapped secret-id token: %v", err)
	} else {
		logger.Printf("config: stored wrapped secret-id token with TTL %s", cfg.WrapTTL)
	}

	// Persist everything into the state
	logger.Printf("config: saving sealed state data")
	st.Config = cfg
	st.RoleID = creds.RoleID()
	st.WrappedSecretIDToken = creds.WrappedSecretIDToken()
	st.SelectedVaultAddr = primary

	if err := SaveSealedState(cfg.StateFile, key, &st, aad); err != nil {
		logger.Fatalf("failed to save sealed state: %v", err)
	}
	logger.Println("done")
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

	return self.Info().Architecture + "-" + self.Info().OS.Platform + "-" + self.Info().UniqueID
}
