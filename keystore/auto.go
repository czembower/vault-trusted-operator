package keystore

import (
	"fmt"
	"log"
)

type Auto struct {
	Log         *log.Logger
	Mode        string
	FileKeyPath string
	BlobPath    string
}

func (a *Auto) Resolve() (Provider, error) {
	switch a.Mode {
	case "", "auto":
		return resolveDefaultCandidates(a)
	case "file":
		return &File{Log: a.Log, Path: a.FileKeyPath}, nil
	case "dpapi":
		return newDPAPI(a)
	case "tpm":
		return newTPM2(a)
	default:
		return nil, fmt.Errorf("unknown keystore mode: %q", a.Mode)
	}
}
