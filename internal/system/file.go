package system

import (
	"os"
	"path/filepath"
)

// WriteAtomic stages data beside path (dot-prefixed, so sudo and run-parts
// ignore it) with mode, lets prepare (nil: none) validate or chown the
// staged file, then renames it into place. A failure at any step leaves
// path untouched.
func WriteAtomic(path string, data []byte, mode os.FileMode, prepare func(tmp string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".vpsctl-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil && prepare != nil {
		err = prepare(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	return err
}
