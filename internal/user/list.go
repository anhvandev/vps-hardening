package user

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ManagedUser is one human login as the Users screen shows it.
type ManagedUser struct {
	Name   string
	UID    int
	Home   string
	Sudo   bool // vpsctl's per-user NOPASSWD rule or admin-group membership
	Keys   int  // keys in authorized_keys
	Locked bool // password locked, account expired or nologin shell
}

// ManagedUsers lists the human accounts (1000 ≤ UID < 65534) in passwd order,
// read live from the passwd, group and shadow databases.
func (m *Manager) ManagedUsers() ([]ManagedUser, error) {
	passwd, err := m.getent("passwd")
	if err != nil {
		return nil, err
	}
	group, err := m.getent("group")
	if err != nil {
		return nil, err
	}
	shadow, err := m.getent("shadow")
	if err != nil {
		return nil, err
	}

	adminGID, admins := "", []string{}
	for _, f := range group {
		if len(f) >= 4 && f[0] == m.Host.AdminGroup {
			adminGID, admins = f[2], strings.Split(f[3], ",")
		}
	}
	shadowOf := map[string][]string{}
	for _, f := range shadow {
		shadowOf[f[0]] = f
	}

	var users []ManagedUser
	for _, f := range passwd {
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		// ponytail: fixed 1000..65533 human range, read login.defs UID_MIN/UID_MAX if a host differs.
		if err != nil || uid < 1000 || uid >= 65534 {
			continue
		}
		name := f[0]
		_, rule := os.Stat(filepath.Join(m.Root, "/etc/sudoers.d", "99-vpsctl-"+name))
		users = append(users, ManagedUser{
			Name:   name,
			UID:    uid,
			Home:   f[5],
			Sudo:   rule == nil || f[3] == adminGID || slices.Contains(admins, name),
			Keys:   m.countKeys(f[5]),
			Locked: noLogin(f[6]) || locked(shadowOf[name]),
		})
	}
	return users, nil
}

// getent returns the colon-split lines of one NSS database.
func (m *Manager) getent(db string) ([][]string, error) {
	res, err := m.R.Run("getent", db)
	if err != nil {
		return nil, fmt.Errorf("getent %s: %w", db, err)
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("getent %s: exit %d: %s", db, res.Code, strings.TrimSpace(res.Stderr))
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if line != "" {
			rows = append(rows, strings.Split(line, ":"))
		}
	}
	return rows, nil
}

func (m *Manager) countKeys(home string) int {
	b, _ := os.ReadFile(filepath.Join(m.Root, home, ".ssh", "authorized_keys"))
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

func noLogin(shell string) bool {
	return strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false")
}

// locked reads a shadow entry. A key-only user's never-set password is a bare
// "!" or "!!", not a lock; a lock is "!" in front of a real hash or "*", or
// an expiry date already passed (`usermod -L -e 1`).
func locked(sh []string) bool {
	if len(sh) < 8 {
		return false
	}
	if strings.HasPrefix(sh[1], "!") && strings.TrimLeft(sh[1], "!") != "" {
		return true
	}
	days, err := strconv.ParseInt(sh[7], 10, 64)
	return err == nil && days <= time.Now().Unix()/86400
}
