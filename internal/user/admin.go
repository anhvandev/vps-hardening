// Package user creates the Admin User (key-only, per-user NOPASSWD sudo),
// installs/rotates its SSH key and locks Default Cloud Users.
package user

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/anhvandev/vpsctl/internal/system"
)

// Installer installs distro packages (wired to the real package installer by the caller).
type Installer interface {
	Install(pkgs ...string) error
}

// DefaultCloudUsers are the image-created logins Hardening locks.
var DefaultCloudUsers = []string{
	"ubuntu", "debian", "rocky", "almalinux", "cloud-user", "centos",
	"ec2-user", "fedora", "opensuse", "arch", "admin",
}

// Manager does user work on one host. Root prefixes every file path it
// touches ("" in production); TmpDir is the parent of the private-key temp
// dir ("" = os.TempDir); OpenTTY opens the controlling terminal (nil = /dev/tty).
type Manager struct {
	R       system.Runner
	Host    system.Host
	Pkgs    Installer
	Root    string
	TmpDir  string
	OpenTTY func() (io.WriteCloser, error)
}

var validName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// EnsureAdmin creates name if missing (key-only, no password), adds it to the
// admin group and grants per-user NOPASSWD sudo. Idempotent.
func (m *Manager) EnsureAdmin(name string) error {
	if name == "root" || slices.Contains(DefaultCloudUsers, name) {
		return fmt.Errorf("refusing admin user %q: root or a Default Cloud User that Hardening locks", name)
	}
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid user name %q", name)
	}
	acct, exists, err := m.lookup(name)
	if err != nil {
		return err
	}
	if exists && acct.uid < 1000 {
		return fmt.Errorf("refusing admin user %q: existing system user (UID %d < 1000)", name, acct.uid)
	}
	if !exists {
		cmd := []string{"useradd", "-m", "-s", "/bin/bash", name}
		if m.Host.Family == "debian" {
			cmd = []string{"adduser", "--disabled-password", "--gecos", "", name}
		}
		if err := m.run(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	if err := m.run("usermod", "-aG", m.Host.AdminGroup, name); err != nil {
		return err
	}
	// sudo first: visudo and /etc/sudoers.d come with it (bash bug 5).
	if res, err := m.R.Run("sudo", "-V"); err != nil || res.Code != 0 {
		if err := m.Pkgs.Install("sudo"); err != nil {
			return fmt.Errorf("install sudo: %w", err)
		}
	}
	return m.writeSudoers(name)
}

// writeSudoers installs a visudo-validated NOPASSWD rule for name. The 99-
// prefix sorts after %wheel/%sudo fragments: the last matching rule wins.
func (m *Manager) writeSudoers(name string) error {
	dst := filepath.Join(m.Root, "/etc/sudoers.d", "99-vpsctl-"+name)
	content := fmt.Sprintf("# Managed by vpsctl: %s is a key-only admin, password sudo would be unusable.\n# Delete this file to revoke.\n%s ALL=(ALL:ALL) NOPASSWD: ALL\n", name, name)
	if b, err := os.ReadFile(dst); err == nil && string(b) == content {
		return nil
	}
	return writeAtomic(dst, []byte(content), 0o440, func(tmp string) error {
		return m.run("visudo", "-cf", tmp)
	})
}

type account struct {
	uid, gid int
	home     string
}

// lookup reads name from the passwd database; exists is false when unknown.
func (m *Manager) lookup(name string) (acct account, exists bool, err error) {
	res, err := m.R.Run("getent", "passwd", name)
	if err != nil {
		return acct, false, fmt.Errorf("getent passwd %s: %w", name, err)
	}
	if res.Code == 2 {
		return acct, false, nil
	}
	f := strings.Split(strings.TrimSpace(res.Stdout), ":")
	if res.Code != 0 || len(f) < 7 {
		return acct, false, fmt.Errorf("getent passwd %s: exit %d: %q", name, res.Code, res.Stdout)
	}
	uid, err1 := strconv.Atoi(f[2])
	gid, err2 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil {
		return acct, false, fmt.Errorf("getent passwd %s: bad uid/gid in %q", name, res.Stdout)
	}
	return account{uid, gid, f[5]}, true, nil
}

// run runs a command and turns a non-zero exit into an error.
func (m *Manager) run(name string, args ...string) error {
	res, err := m.R.Run(name, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), res.Code, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// writeAtomic stages data beside path (dot-prefixed, so sudo ignores it), lets
// prepare validate/chown the staged file, then renames it into place. A
// failure at any step leaves path untouched.
func writeAtomic(path string, data []byte, mode os.FileMode, prepare func(tmp string) error) error {
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
