package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Vault connectivity
	VaultAddrs           []string
	VaultAddrsCSV        string
	Namespace            string
	InsecureTLS          bool
	ProbeTimeout         time.Duration
	ClientTimeout        time.Duration
	AcceptHealthStatuses map[int]bool

	// Auth
	AppRoleMount string
	AppRoleRole  string

	// OIDC bootstrap (interactive fallback)
	OIDCMount       string
	OIDCRole        string
	OIDCRedirectURI string

	// SecretID behavior
	WrapTTL        time.Duration
	WrapTTLRaw     string
	InMemSecretTTL time.Duration
	RenewFraction  float64

	// State management
	StateFile    string
	StateKeyFile string
	BlobFile     string
	KeyStore     string
	Reconfigure  bool `json:"-"`
	Debug        bool `json:"-"`

	// Broker
	PipeName   string
	SocketPath string
	SocketMode uint
}

func MustLoadConfig() Config {
	var cfg Config

	// Defaults close to your original constants.
	defaultAddrs := envOr("VAULT_ADDRS", "https://localhost:8200")
	defaultNamespace := envOr("VAULT_NAMESPACE", "")
	defaultWrapTTL := envOr("WRAP_TTL", "24h")
	defaultStateFile := envOr("STATE_FILE", "./state.json")
	defaultKeyStore := envOr("KEYSTORE", "auto")
	defaultStateKeyFile := envOr("STATE_KEY_FILE", "")
	defaultBlobFile := envOr("BLOB_FILE", "")

	flag.StringVar(&cfg.VaultAddrsCSV, "vault-addrs", defaultAddrs, "Comma-separated Vault addresses (overrides VAULT_ADDRS)")
	flag.StringVar(&cfg.Namespace, "namespace", defaultNamespace, "Vault namespace")
	flag.StringVar(&cfg.WrapTTLRaw, "wrap-ttl", defaultWrapTTL, "Wrapping TTL for secret-id token (e.g. 24h, 3600s) - note that this same TTL will be requested for the AppRole secret ID itself")
	flag.BoolVar(&cfg.InsecureTLS, "insecure-tls", envBool("VAULT_SKIP_VERIFY", false), "skip TLS verification (NOT recommended)")
	flag.StringVar(&cfg.AppRoleMount, "approle-mount", envOr("APPROLE_MOUNT", "auth/approle"), "AppRole auth mount path")
	flag.StringVar(&cfg.AppRoleRole, "approle-role", envOr("APPROLE_ROLE", "my-approle"), "AppRole role name")
	flag.StringVar(&cfg.OIDCMount, "oidc-mount", envOr("OIDC_MOUNT", "oidc"), "OIDC auth mount name (without auth/ prefix)")
	flag.StringVar(&cfg.OIDCRole, "oidc-role", envOr("OIDC_ROLE", "default_role"), "Vault OIDC role name")
	flag.StringVar(&cfg.OIDCRedirectURI, "oidc-redirect-uri", envOr("OIDC_REDIRECT_URI", "http://localhost:8250/oidc/callback"), "Vault OIDC callback URI")
	flag.StringVar(&cfg.StateFile, "state-file", defaultStateFile, "Path to sealed state envelope used by all backends")
	flag.StringVar(&cfg.KeyStore, "keystore", defaultKeyStore, "Keystore backend: auto|file|dpapi|tpm")
	flag.StringVar(&cfg.StateKeyFile, "state-key-file", defaultStateKeyFile, "Path to file keystore key (File backend only, defaults to same directory as state-file)")
	flag.StringVar(&cfg.BlobFile, "blob-file", defaultBlobFile, "Path to TPM2/DPAPI-protected blob file (Windows and Linux with TPM2 only)")
	flag.BoolVar(&cfg.Reconfigure, "reconfigure", envBool("RECONFIGURE", false), "Ignore existing state file and rewrite from flags/env")
	flag.StringVar(&cfg.SocketPath, "socket-path", "./socket.sock", "Unix socket path (non-Windows) for broker/proxy service")
	flag.UintVar(&cfg.SocketMode, "socket-mode", 0600, "Unix socket file mode for broker/proxy service")
	flag.StringVar(&cfg.PipeName, "pipe-path", "./pipe", "Windows named pipe name for broker/proxy service")
	flag.BoolVar(&cfg.Debug, "debug", envBool("DEBUG", false), "Print verbose debugging logs")
	flag.Parse()

	cfg.StateFile = mustAbs(cfg.StateFile)
	cfg.ProbeTimeout = envDuration("VAULT_PROBE_TIMEOUT", 2*time.Second)
	cfg.ClientTimeout = envDuration("VAULT_CLIENT_TIMEOUT", 2*time.Second)

	wrapTTL, err := parseFlexibleDuration(cfg.WrapTTLRaw)
	if err != nil {
		panic("invalid -wrap-ttl / WRAP_TTL: " + err.Error())
	}
	cfg.WrapTTL = wrapTTL
	cfg.InMemSecretTTL = envDuration("INMEM_SECRETID_TTL", 60*time.Second)
	cfg.RenewFraction = envFloat("RENEW_FRACTION", 2.0/3.0)

	cfg.VaultAddrs = splitCSV(cfg.VaultAddrsCSV)
	if len(cfg.VaultAddrs) == 0 {
		panic("no Vault addresses provided (set -vault-addrs or VAULT_ADDRS)")
	}

	// Keystore defaults must be explicit (non-empty) after config load.
	if strings.TrimSpace(cfg.KeyStore) == "" {
		cfg.KeyStore = "auto"
	}
	switch cfg.KeyStore {
	case "auto", "file", "dpapi":
	default:
		panic(fmt.Sprintf("invalid -keystore=%q (expected auto|file|dpapi)", cfg.KeyStore))
	}

	// Default key file paths to siblings of the state file if not explicitly provided.
	if strings.TrimSpace(cfg.StateKeyFile) == "" {
		cfg.StateKeyFile = filepath.Join(filepath.Dir(cfg.StateFile), "state.key")
	}
	if strings.TrimSpace(cfg.BlobFile) == "" {
		cfg.BlobFile = filepath.Join(filepath.Dir(cfg.StateFile), "state.key.dpapi")
	}
	cfg.StateKeyFile = mustAbs(cfg.StateKeyFile)
	cfg.BlobFile = mustAbs(cfg.BlobFile)

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
func mustAbs(p string) string {
	if p == "" {
		return ""
	}
	ap, err := filepath.Abs(p)
	if err != nil {
		panic("invalid path: " + err.Error())
	}
	return ap
}

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

func parseFlexibleDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Try Go duration first (e.g. 24h, 15m, 60s)
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	// Fallback: plain integer seconds
	if sec, err := strconv.Atoi(s); err == nil {
		return time.Duration(sec) * time.Second, nil
	}
	return 0, fmt.Errorf("expected duration like 24h or seconds integer, got %q", s)
}

func (c Config) AppRoleSecretIDPath() string {
	// matches your original secretIdPath building
	return fmt.Sprintf("%s/role/%s/secret-id", strings.TrimPrefix(c.AppRoleMount, "/"), c.AppRoleRole)
}

func (c Config) AppRoleRoleIDPath() string {
	return fmt.Sprintf("%s/role/%s/role-id", strings.TrimPrefix(c.AppRoleMount, "/"), c.AppRoleRole)
}
