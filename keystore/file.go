package keystore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	Log  *log.Logger
	Path string
}

func (p *File) Name() string { return "file" }

func (p *File) GetOrCreateKey(_ string) ([]byte, error) {
	return loadOrCreateFileKey(p.Path)
}

func loadOrCreateFileKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid key length %d", len(key))
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	tmp := path + ".tmp"
	enc := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(tmp, []byte(enc+"\n"), fs.FileMode(0o600)); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("rename key: %w", err)
	}
	return key, nil
}
