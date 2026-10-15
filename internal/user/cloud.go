package user

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// LockDefaultCloudUsers locks every Default Cloud User present: empties its
// authorized_keys, locks the password and sets a nologin shell. Never deletes.
// locked names the users it locked.
func (m *Manager) LockDefaultCloudUsers() (locked []string, err error) {
	for _, u := range DefaultCloudUsers {
		pw, exists, err := m.Lookup(u)
		if err != nil {
			return locked, err
		}
		if !exists {
			continue
		}
		err = os.Truncate(filepath.Join(m.Root, pw.Home, ".ssh", "authorized_keys"), 0)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return locked, err
		}
		if err := m.run("usermod", "-L", "-s", "/usr/sbin/nologin", u); err != nil {
			return locked, err
		}
		locked = append(locked, u)
	}
	return locked, nil
}

// BlockCloudInitReinjection writes a cloud-init drop-in so the next boot does
// not recreate default users or re-inject their keys. No-op without cloud-init.
func (m *Manager) BlockCloudInitReinjection() error {
	dir := filepath.Join(m.Root, "/etc/cloud/cloud.cfg.d")
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return os.WriteFile(filepath.Join(dir, "99-vpsctl.cfg"), []byte("disable_root: true\nusers: []\n"), 0o644)
}
