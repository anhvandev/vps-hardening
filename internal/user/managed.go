package user

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// CreateUser creates the Managed User name, key-only (never a password) and
// without sudo. Names are checked as for the Admin User; existing names are
// refused.
func (m *Manager) CreateUser(name string) error {
	_, exists, err := m.checkName("user", name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("user %q already exists", name)
	}
	return m.addUser(name)
}

// AddKey appends the pasted OpenSSH public key line pubkey to name's
// authorized_keys. Anything else is refused before install (the error never
// echoes the input); a key already there is not added twice.
func (m *Manager) AddKey(name, pubkey string) error {
	line, err := publicKeyLine(pubkey)
	if err != nil {
		return err
	}
	return m.appendKey(name, line)
}

// appendKey adds the public key line to name's authorized_keys unless its
// key blob is already there.
func (m *Manager) appendKey(name, line string) error {
	pw, exists, err := m.Lookup(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("user %q does not exist", name)
	}
	b, err := os.ReadFile(filepath.Join(m.Root, pw.Home, ".ssh", "authorized_keys"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	blob := strings.Fields(line)[1]
	for _, l := range strings.Split(string(b), "\n") {
		if slices.Contains(strings.Fields(l), blob) {
			return fmt.Errorf("this key is already in %s's authorized_keys", name)
		}
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	return m.writeAuthorizedKeys(pw, append(b, line+"\n"...))
}

var errNotPublicKey = errors.New("not an OpenSSH public key: paste one line like `ssh-ed25519 AAAA... comment`")

// publicKeyLine checks s is one "type base64 [comment]" line whose base64 key
// blob starts with the same type, and returns it trimmed.
func publicKeyLine(s string) (string, error) {
	s = strings.TrimSpace(s)
	f := strings.Fields(s)
	if strings.ContainsAny(s, "\r\n") || len(f) < 2 {
		return "", errNotPublicKey
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 4 {
		return "", errNotPublicKey
	}
	n := uint64(binary.BigEndian.Uint32(blob))
	if uint64(len(blob)) <= 4+n || string(blob[4:4+n]) != f[0] {
		return "", errNotPublicKey
	}
	return s, nil
}

// managed looks name up and refuses anything but an existing Managed User.
func (m *Manager) managed(name string) (PasswdEntry, error) {
	if !validName.MatchString(name) {
		return PasswdEntry{}, fmt.Errorf("invalid user name %q", name)
	}
	pw, exists, err := m.Lookup(name)
	if err != nil {
		return pw, err
	}
	if !exists {
		return pw, fmt.Errorf("user %q does not exist", name)
	}
	if pw.UID < 1000 || pw.UID >= 65534 {
		return pw, fmt.Errorf("refusing %q: not a Managed User (UID %d)", name, pw.UID)
	}
	return pw, nil
}

// GrantSudo gives name vpsctl's passwordless sudo rule (visudo-checked,
// installed atomically).
func (m *Manager) GrantSudo(name string) error {
	if _, err := m.managed(name); err != nil {
		return err
	}
	return m.writeSudoers(name)
}

// RevokeSudo removes vpsctl's sudo rule for name; admin-group membership and
// other sudoers rules are left alone.
func (m *Manager) RevokeSudo(name string) error {
	if _, err := m.managed(name); err != nil {
		return err
	}
	err := os.Remove(m.sudoersRule(name))
	if os.IsNotExist(err) {
		return fmt.Errorf("%s has no sudo rule from vpsctl (admin-group sudo is not changed here)", name)
	}
	return err
}

func (m *Manager) sudoersRule(name string) string {
	return filepath.Join(m.Root, "/etc/sudoers.d", "99-vpsctl-"+name)
}

// Lock suspends name: password locked and account expired, which also stops
// key logins and shows as Locked even for a key-only user.
func (m *Manager) Lock(name string) error {
	if _, err := m.managed(name); err != nil {
		return err
	}
	return m.run("usermod", "-L", "-e", "1", name)
}

// Unlock reverses Lock exactly: password unlocked, expiry cleared.
func (m *Manager) Unlock(name string) error {
	if _, err := m.managed(name); err != nil {
		return err
	}
	return m.run("usermod", "-U", "-e", "", name)
}

// Keys lists the key lines in name's authorized_keys.
func (m *Manager) Keys(name string) ([]string, error) {
	pw, err := m.managed(name)
	if err != nil {
		return nil, err
	}
	return m.keyLines(pw.Home), nil
}

// RemoveKey removes the key line key (as Keys returns it) from name's
// authorized_keys; everything else stays.
func (m *Manager) RemoveKey(name, key string) error {
	pw, err := m.managed(name)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(m.Root, pw.Home, ".ssh", "authorized_keys"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(string(b), "\n")
	kept := slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return strings.TrimSpace(l) == key })
	if len(kept) == len(lines) {
		return fmt.Errorf("that key is not in %s's authorized_keys", name)
	}
	return m.writeAuthorizedKeys(pw, []byte(strings.Join(kept, "\n")))
}

// DeleteUser deletes name, its home directory only when removeHome, and
// vpsctl's sudo rule so a later user of the same name does not inherit it.
func (m *Manager) DeleteUser(name string, removeHome bool) error {
	if _, err := m.managed(name); err != nil {
		return err
	}
	args := []string{name}
	if removeHome {
		args = []string{"-r", name}
	}
	if err := m.run("userdel", args...); err != nil {
		return err
	}
	if err := os.Remove(m.sudoersRule(name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
