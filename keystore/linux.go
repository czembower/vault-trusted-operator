//go:build linux

package keystore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func newDPAPI(a *Auto) (Provider, error) {
	// Not supported on non-windows
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}

func tpmDevicePresent() bool {
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return true
	}
	return false
}

func resolveDefaultCandidates(a *Auto) (Provider, error) {
	if tpmDevicePresent() {
		if kp, err := newTPM2(a); err == nil {
			return kp, nil
		} else if a.Log != nil {
			a.Log.Printf("keystore: tpm2 present but unusable (%v); falling back to file", err)
		}
	}
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}

type tpm2BlobFile struct {
	Version int    `json:"version"`
	Public  string `json:"public"`  // base64(marshal(TPM2B_PUBLIC))
	Private string `json:"private"` // base64(marshal(TPM2B_PRIVATE))
}

type TPM2 struct {
	BlobPath   string // where the sealed blobs are stored
	DevicePath string // /dev/tpmrm0 or /dev/tpm0
}

func (p *TPM2) Name() string { return "tpm2" }

// newTPM2 constructs the TPM2 provider. You should pass an explicit blobPath from config.
func newTPM2(a *Auto) (Provider, error) {
	if a == nil {
		return nil, fmt.Errorf("tpm2: nil Auto")
	}
	if strings.TrimSpace(a.BlobPath) == "" {
		return nil, fmt.Errorf("tpm2: BlobPath is empty")
	}

	dev := "/dev/tpmrm0"
	if _, err := os.Stat(dev); err != nil {
		dev = "/dev/tpm0"
		if _, err2 := os.Stat(dev); err2 != nil {
			return nil, fmt.Errorf("tpm2: no device found at /dev/tpmrm0 or /dev/tpm0")
		}
	}

	return &TPM2{
		BlobPath:   a.BlobPath,
		DevicePath: dev,
	}, nil
}

func (p *TPM2) GetOrCreateKey(_ string) ([]byte, error) {
	// If blob exists, unseal
	if b, err := os.ReadFile(p.BlobPath); err == nil {
		return p.unsealFromBlob(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tpm2: read blob: %w", err)
	}

	// Create new key and seal it
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("tpm2: generate key: %w", err)
	}

	blobBytes, err := p.sealToTPM(key)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(p.BlobPath), 0o755); err != nil {
		return nil, fmt.Errorf("tpm2: mkdir blob dir: %w", err)
	}

	tmp := p.BlobPath + ".tmp"
	if err := os.WriteFile(tmp, blobBytes, fs.FileMode(0o600)); err != nil {
		return nil, fmt.Errorf("tpm2: write blob tmp: %w", err)
	}
	if err := os.Rename(tmp, p.BlobPath); err != nil {
		return nil, fmt.Errorf("tpm2: rename blob: %w", err)
	}

	return key, nil
}

func (p *TPM2) unsealFromBlob(blobBytes []byte) ([]byte, error) {
	var bf tpm2BlobFile
	if err := json.Unmarshal(blobBytes, &bf); err != nil {
		return nil, fmt.Errorf("tpm2: parse blob json: %w", err)
	}
	if bf.Version != 1 {
		return nil, fmt.Errorf("tpm2: unsupported blob version %d", bf.Version)
	}

	pubWire, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bf.Public))
	if err != nil {
		return nil, fmt.Errorf("tpm2: decode public b64: %w", err)
	}
	privWire, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bf.Private))
	if err != nil {
		return nil, fmt.Errorf("tpm2: decode private b64: %w", err)
	}

	inPub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubWire)
	if err != nil {
		return nil, fmt.Errorf("tpm2: unmarshal public: %w", err)
	}

	inPriv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privWire)
	if err != nil {
		return nil, fmt.Errorf("tpm2: unmarshal private: %w", err)
	}

	rw, err := transport.OpenTPM(p.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("tpm2: open device: %w", err)
	}
	defer rw.Close()

	primaryHandle, err := createPrimary(rw)
	if err != nil {
		return nil, err
	}
	defer flush(rw, primaryHandle)

	loadRsp, err := (&tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  *inPub,
		InPrivate: *inPriv,
	}).Execute(rw)
	if err != nil {
		return nil, fmt.Errorf("tpm2: load: %w", err)
	}
	defer flush(rw, loadRsp.ObjectHandle)

	unsealRsp, err := (&tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}).Execute(rw)
	if err != nil {
		return nil, fmt.Errorf("tpm2: unseal: %w", err)
	}

	secret := unsealRsp.OutData.Buffer
	if len(secret) != 32 {
		return nil, fmt.Errorf("tpm2: unexpected key length %d", len(secret))
	}

	out := make([]byte, 32)
	copy(out, secret)
	return out, nil
}

func (p *TPM2) sealToTPM(secret []byte) ([]byte, error) {
	rw, err := transport.OpenTPM(p.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("tpm2: open device: %w", err)
	}
	defer rw.Close()

	primaryHandle, err := createPrimary(rw)
	if err != nil {
		return nil, err
	}
	defer flush(rw, primaryHandle)

	// Template for a sealed keyed-hash object.
	// KeyedHash + NULL scheme, with UserWithAuth so Unseal is allowed.
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{Buffer: nil}),
	}

	inPublic := tpm2.New2B(pub)

	// Put the secret into the sensitive area.
	inSensitive := tpm2.TPM2BSensitiveCreate{
		Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{Buffer: nil},
			Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		},
	}

	createRsp, err := (&tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Auth:   tpm2.PasswordAuth(nil), // empty parent auth
		},
		InSensitive: inSensitive,
		InPublic:    inPublic,
		OutsideInfo: tpm2.TPM2BData{Buffer: nil},
		CreationPCR: tpm2.TPMLPCRSelection{}, // no PCR binding
	}).Execute(rw)
	if err != nil {
		return nil, fmt.Errorf("tpm2: create sealed object: %w", err)
	}

	// Persist TPM2B_PUBLIC and TPM2B_PRIVATE in wire form.
	pubWire := tpm2.Marshal(createRsp.OutPublic)
	privWire := tpm2.Marshal(createRsp.OutPrivate)

	bf := tpm2BlobFile{
		Version: 1,
		Public:  base64.StdEncoding.EncodeToString(pubWire),
		Private: base64.StdEncoding.EncodeToString(privWire),
	}

	out, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("tpm2: marshal blob json: %w", err)
	}
	out = append(out, '\n')
	return out, nil
}

func createPrimary(rw transport.TPM) (tpm2.TPMHandle, error) {
	// “Storage primary” template (RSA 2048 + AES-128-CFB) under Owner hierarchy.
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			Decrypt:             true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				Scheme:   tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
				KeyBits:  2048,
				Exponent: 0,
			}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: nil}),
	}

	rsp, err := (&tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:    tpm2.New2B(pub),
		InSensitive: tpm2.TPM2BSensitiveCreate{}, // empty
		OutsideInfo: tpm2.TPM2BData{Buffer: nil},
		CreationPCR: tpm2.TPMLPCRSelection{},
	}).Execute(rw)
	if err != nil {
		return 0, fmt.Errorf("tpm2: create primary: %w", err)
	}
	return rsp.ObjectHandle, nil
}

func flush(rw transport.TPM, h tpm2.TPMHandle) {
	_, _ = (&tpm2.FlushContext{FlushHandle: h}).Execute(rw)
}
