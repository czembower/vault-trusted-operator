package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
	"vault-trusted-operator/config"

	"golang.org/x/crypto/chacha20poly1305"
)

const sealedStateVersion = 1

// Envelope stored on disk
type SealedStateFile struct {
	Version   int       `json:"version"`
	AEAD      string    `json:"aead"`
	NonceB64  string    `json:"nonce_b64"`
	CipherB64 string    `json:"cipher_b64"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	SaveCount uint64    `json:"save_count"` // Monotonic counter for rollback detection
}

type StatePayload struct {
	Config               config.Config `json:"config"`
	RoleID               string        `json:"role_id,omitempty"`
	WrappedSecretIDToken string        `json:"wrapped_secret_id_token,omitempty"`
	SelectedVaultAddr    string        `json:"selected_vault_addr,omitempty"`
}

// LoadOrCreateKey reads a base64 key from keyPath, or generates one if missing.
func LoadOrCreateKey(keyPath string) ([]byte, error) {
	b, err := os.ReadFile(keyPath)
	if err == nil {
		key, err := base64.StdEncoding.DecodeString(string(bytesTrimSpace(b)))
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("invalid key length %d", len(key))
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Create new key
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, err
	}

	enc := base64.StdEncoding.EncodeToString(key)
	tmp := keyPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc+"\n"), fs.FileMode(0o600)); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.Rename(tmp, keyPath); err != nil {
		return nil, fmt.Errorf("rename key: %w", err)
	}

	return key, nil
}

func SaveSealedState(statePath string, key []byte, payload any, aad []byte) error {
	now := time.Now().UTC()

	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	aeadInst, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	cipher := aeadInst.Seal(nil, nonce, plain, aad)

	env := SealedStateFile{
		Version:   sealedStateVersion,
		AEAD:      "chacha20poly1305",
		NonceB64:  base64.StdEncoding.EncodeToString(nonce),
		CipherB64: base64.StdEncoding.EncodeToString(cipher),
		UpdatedAt: now,
	}

	// preserve CreatedAt and increment SaveCount if file exists
	if existing, err := LoadSealedEnvelope(statePath); err == nil && !existing.CreatedAt.IsZero() {
		env.CreatedAt = existing.CreatedAt
		env.SaveCount = existing.SaveCount + 1
	} else {
		env.CreatedAt = now
		env.SaveCount = 1
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return err
	}

	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, out, fs.FileMode(0o600)); err != nil {
		return err
	}
	return os.Rename(tmp, statePath)
}

func LoadSealedState(statePath string, key []byte, out any, aad []byte) error {
	env, err := LoadSealedEnvelope(statePath)
	if err != nil {
		return err
	}
	if env.Version != sealedStateVersion {
		return fmt.Errorf("unsupported sealed state version: %d", env.Version)
	}
	if env.AEAD != "chacha20poly1305" {
		return fmt.Errorf("unsupported aead: %s", env.AEAD)
	}

	nonce, err := base64.StdEncoding.DecodeString(env.NonceB64)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	cipher, err := base64.StdEncoding.DecodeString(env.CipherB64)
	if err != nil {
		return fmt.Errorf("decode cipher: %w", err)
	}

	aeadInst, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}

	plain, err := aeadInst.Open(nil, nonce, cipher, aad)
	if err != nil {
		return fmt.Errorf("decrypt state: %w", err)
	}

	if err := json.Unmarshal(plain, out); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	return nil
}

func LoadSealedEnvelope(statePath string) (*SealedStateFile, error) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	var env SealedStateFile
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func bytesTrimSpace(b []byte) []byte {
	// minimal trim w/out pulling strings everywhere
	i := 0
	j := len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

// ZeroBytes securely overwrites a byte slice with zeros to minimize key exposure time in memory.
// This should be called after sensitive material (like encryption keys) is no longer needed.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
