//go:build windows

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
	"unsafe"

	"golang.org/x/sys/windows"
)

func resolveDefaultCandidates(a *Auto) (Provider, error) {
	// Prefer DPAPI; fall back to file.
	if kp, err := newDPAPI(a); err == nil {
		return kp, nil
	}
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}

func newTPM2(a *Auto) (Provider, error) {
	// Not supported on non-Linux
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}

type DPAPI struct {
	Log      *log.Logger
	BlobPath string
}

func (p *DPAPI) Name() string { return "dpapi" }

func newDPAPI(a *Auto) (Provider, error) {
	if a.BlobPath == "" {
		return nil, fmt.Errorf("dpapi blob path is empty")
	}
	return &DPAPI{Log: a.Log, BlobPath: a.BlobPath}, nil
}

func (p *DPAPI) GetOrCreateKey(keyID string) ([]byte, error) {
	// Load existing blob
	if b, err := os.ReadFile(p.BlobPath); err == nil {
		blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("decode dpapi blob: %w", err)
		}
		plain, err := dpapiUnprotect(blob, []byte(keyID))
		if err != nil {
			return nil, fmt.Errorf("dpapi unprotect: %w", err)
		}
		if len(plain) != 32 {
			return nil, fmt.Errorf("invalid key length %d", len(plain))
		}
		return plain, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read dpapi blob: %w", err)
	}

	// Create new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	blob, err := dpapiProtect(key, []byte(keyID))
	if err != nil {
		return nil, fmt.Errorf("dpapi protect: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(p.BlobPath), 0o755); err != nil {
		return nil, err
	}

	tmp := p.BlobPath + ".tmp"
	enc := base64.StdEncoding.EncodeToString(blob)
	if err := os.WriteFile(tmp, []byte(enc+"\n"), fs.FileMode(0o600)); err != nil {
		return nil, fmt.Errorf("write dpapi blob: %w", err)
	}
	if err := os.Rename(tmp, p.BlobPath); err != nil {
		return nil, fmt.Errorf("rename dpapi blob: %w", err)
	}

	return key, nil
}

func dpapiProtect(plain []byte, entropy []byte) ([]byte, error) {
	in := bytesToBlob(plain)
	var out windows.DataBlob

	var ent *windows.DataBlob
	if len(entropy) > 0 {
		e := bytesToBlob(entropy)
		ent = e
	}

	if err := windows.CryptProtectData(in, nil, ent, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	return blobToBytes(&out), nil
}

func dpapiUnprotect(cipher []byte, entropy []byte) ([]byte, error) {
	in := bytesToBlob(cipher)
	var out windows.DataBlob

	var ent *windows.DataBlob
	if len(entropy) > 0 {
		e := bytesToBlob(entropy)
		ent = e
	}

	if err := windows.CryptUnprotectData(in, nil, ent, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	return blobToBytes(&out), nil
}

func bytesToBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{
		Size: uint32(len(b)),
		Data: &b[0],
	}
}

func blobToBytes(db *windows.DataBlob) []byte {
	if db == nil || db.Size == 0 || db.Data == nil {
		return nil
	}
	out := make([]byte, db.Size)
	copy(out, (*[1 << 30]byte)(unsafe.Pointer(db.Data))[:db.Size:db.Size])
	return out
}
