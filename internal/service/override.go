package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/anhvandev/vpsctl/internal/guard"
	"github.com/anhvandev/vpsctl/internal/system"
)

// OverridePath is unit's override drop-in under root, the file `systemctl
// edit` uses, so package upgrades never touch it.
func OverridePath(root, unit string) string {
	return filepath.Join(root, "/etc/systemd/system", unit+".d", "override.conf")
}

// Apply writes content to path (a unit file or a drop-in of unit), checks unit
// with `systemd-analyze verify`, then reloads systemd. If verify fails nothing
// is applied: path gets its previous content back (or is removed, with the
// directory made for it) and the verify error is returned. Editing a Protected
// Unit is refused before anything is written.
func Apply(r system.Runner, path, unit string, content []byte) error {
	if err := guard.Check(guard.Facts{}, guard.UnitAction{Unit: unit, Verb: "edit"}); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	_, dirErr := os.Stat(dir)
	prev, prevErr := os.ReadFile(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return err
	}
	if _, err := run(r, "systemd-analyze", "verify", unit); err != nil {
		switch {
		case prevErr == nil:
			return errors.Join(err, os.WriteFile(path, prev, 0o644))
		case dirErr != nil:
			return errors.Join(err, os.RemoveAll(dir))
		default:
			return errors.Join(err, os.Remove(path))
		}
	}
	_, err := systemctl(r, "daemon-reload")
	return err
}

// Revert removes unit's override (see OverridePath) and reloads systemd.
// Protected Units are refused, as for Apply.
func Revert(r system.Runner, root, unit string) error {
	if err := guard.Check(guard.Facts{}, guard.UnitAction{Unit: unit, Verb: "edit"}); err != nil {
		return err
	}
	path := OverridePath(root, unit)
	if err := os.Remove(path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s has no override", unit)
	} else if err != nil {
		return err
	}
	os.Remove(filepath.Dir(path)) // only if empty: other drop-ins stay
	_, err := systemctl(r, "daemon-reload")
	return err
}
