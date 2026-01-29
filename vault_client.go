// vault_client.go
package main

import (
	"net/http"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type VaultClientFactory struct {
	Cfg       Config
	HTTP      *http.Client
	VaultAddr string
}

func (f *VaultClientFactory) New() (*vault.Client, error) {
	vcfg := &vault.Config{
		Address:    f.VaultAddr,
		HttpClient: f.HTTP,
		Timeout:    f.Cfg.ClientTimeout,
	}
	client, err := vault.NewClient(vcfg)
	if err != nil {
		return nil, err
	}
	if f.Cfg.Namespace != "" {
		client.SetNamespace(f.Cfg.Namespace)
	}
	client.SetReadYourWrites(true)
	client.SetClientTimeout(f.Cfg.ClientTimeout)

	// Ensure per-request timeouts are respected by HttpClient too.
	_ = time.Second // placeholder to keep time imported if you expand this
	return client, nil
}
