package authmanager

import (
	"net/http"
	"vault-trusted-operator/config"

	vault "github.com/hashicorp/vault/api"
)

type VaultClientFactory struct {
	Cfg       config.Config
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

	return client, nil
}
