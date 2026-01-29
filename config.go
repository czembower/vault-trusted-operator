// config.go
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Vault connectivity
	VaultAddrs    []string
	VaultAddrsCSV string
	Namespace     string
	InsecureTLS   bool
	ProbeTimeout  time.Duration
	ClientTimeout time.Duration

	// Auth
	AppRoleMount string
	AppRoleRole  string

	RoleIDFile   string
	SecretIDFile string

	// OIDC bootstrap (interactive fallback)
	OIDCMount       string
	OIDCRole        string // Vault OIDC role name
	OIDCRedirectURI string

	// SecretID behavior
	WrapTTL        time.Duration
	InMemSecretTTL time.Duration
	RenewFraction  float64

	AcceptHealthStatuses map[int]bool
}

func MustLoadConfig() Config {
	var cfg Config

	// Defaults close to your original constants.
	defaultAddrs := envOr("VAULT_ADDRS", "https://localhost:8200")
	defaultNamespace := envOr("VAULT_NAMESPACE", "")

	flag.StringVar(&cfg.VaultAddrsCSV, "vault-addrs", defaultAddrs, "Comma-separated Vault addresses (overrides VAULT_ADDRS)")
	flag.StringVar(&cfg.Namespace, "namespace", defaultNamespace, "Vault namespace")
	flag.BoolVar(&cfg.InsecureTLS, "insecure-tls", envBool("VAULT_SKIP_VERIFY", true), "skip TLS verification (NOT recommended)")
	flag.StringVar(&cfg.AppRoleMount, "approle-mount", envOr("APPROLE_MOUNT", "auth/approle"), "AppRole auth mount path")
	flag.StringVar(&cfg.AppRoleRole, "approle-role", envOr("APPROLE_ROLE", "my-approle"), "AppRole role name")

	flag.StringVar(&cfg.RoleIDFile, "role-id-file", envOr("ROLE_ID_FILE", "./role-id"), "role-id file path")
	flag.StringVar(&cfg.SecretIDFile, "secret-id-file", envOr("SECRET_ID_FILE", "./secret-id"), "secret-id wrap token file path")

	flag.StringVar(&cfg.OIDCMount, "oidc-mount", envOr("OIDC_MOUNT", "oidc"), "OIDC auth mount name (without auth/ prefix)")
	flag.StringVar(&cfg.OIDCRole, "oidc-role", envOr("OIDC_ROLE", "default_role"), "Vault OIDC role name")
	flag.StringVar(&cfg.OIDCRedirectURI, "oidc-redirect-uri", envOr("OIDC_REDIRECT_URI", "http://localhost:8250/oidc/callback"), "Vault OIDC callback URI")

	cfg.VaultAddrs = splitCSV(defaultAddrs)

	cfg.ProbeTimeout = envDuration("VAULT_PROBE_TIMEOUT", 2*time.Second)
	cfg.ClientTimeout = envDuration("VAULT_CLIENT_TIMEOUT", 2*time.Second)

	cfg.WrapTTL = envDuration("WRAP_TTL", 24*time.Hour)
	cfg.InMemSecretTTL = envDuration("INMEM_SECRETID_TTL", 60*time.Second)

	cfg.RenewFraction = envFloat("RENEW_FRACTION", 2.0/3.0)

	flag.Parse()

	cfg.VaultAddrs = splitCSV(cfg.VaultAddrsCSV)
	if len(cfg.VaultAddrs) == 0 {
		panic("no Vault addresses provided (set -vault-addrs or VAULT_ADDRS)")
	}

	// Normalize addresses from flag override if provided.
	if v := flag.Lookup("vault-addrs"); v != nil {
		// Not used; kept for extension.
	}

	// Accept these health statuses as "server is reachable and in a usable state"
	cfg.AcceptHealthStatuses = map[int]bool{
		200: true, // active
		429: true, // standby/too many req depending on setup; still reachable
		472: true, // DR secondary (Vault)
		473: true, // performance standby (Vault)
	}

	if len(cfg.VaultAddrs) == 0 {
		panic("no Vault addresses provided")
	}
	if cfg.RenewFraction <= 0 || cfg.RenewFraction >= 1 {
		panic("renew-fraction must be between 0 and 1")
	}

	return cfg
}

// helpers
func splitCSV(s string) []string {
	parts := strings.Split(strings.ReplaceAll(s, " ", ""), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func envOr(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v, ok := os.LookupEnv(k)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

func envFloat(k string, def float64) float64 {
	v, ok := os.LookupEnv(k)
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return def
	}
	return f
}

func envDuration(k string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(k)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		// allow seconds as integer
		if sec, err2 := strconv.Atoi(strings.TrimSpace(v)); err2 == nil {
			return time.Duration(sec) * time.Second
		}
		return def
	}
	return d
}

func (c Config) AppRoleSecretIDPath() string {
	// matches your original secretIdPath building
	return fmt.Sprintf("%s/role/%s/secret-id", strings.TrimPrefix(c.AppRoleMount, "/"), c.AppRoleRole)
}

func (c Config) AppRoleRoleIDPath() string {
	return fmt.Sprintf("%s/role/%s/role-id", strings.TrimPrefix(c.AppRoleMount, "/"), c.AppRoleRole)
}
