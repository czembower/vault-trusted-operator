package keystore

type Provider interface {
	Name() string
	GetOrCreateKey(keyID string) ([]byte, error)
}
