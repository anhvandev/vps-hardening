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
