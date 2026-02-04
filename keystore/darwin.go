//go:build darwin

package keystore

func resolveDefaultCandidates(a *Auto) (Provider, error) {
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}

func newDPAPI(a *Auto) (Provider, error) {
	// Not supported on non-windows
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}

func newTPM2(a *Auto) (Provider, error) {
	// Not supported on non-Linux
	return &File{Log: a.Log, Path: a.FileKeyPath}, nil
}
