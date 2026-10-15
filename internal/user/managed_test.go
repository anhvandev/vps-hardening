package user

import (
	"strings"
	"testing"
)

// A Managed User is created key-only (never a password) and without sudo.
func TestCreateUserIsKeyOnly(t *testing.T) {
	for family, want := range map[string]string{
		"debian": "adduser --disabled-password --gecos  bob",
		"rhel":   "useradd -m -s /bin/bash bob",
	} {
		h := newFakeHost(t)
		m := newManager(h, family)
		if err := m.CreateUser("bob"); err != nil {
			t.Fatal(err)
		}
		calls := strings.Join(h.calls, "\n")
		if !strings.Contains(calls, want) || strings.Contains("\n"+calls, "\npasswd") || strings.Contains(calls, "chpasswd") || strings.Contains(calls, "usermod") {
			t.Fatalf("%s: calls %q", family, h.calls)
		}
		if _, ok, _ := m.Lookup("bob"); !ok {
			t.Fatalf("%s: bob not created", family)
		}
	}
}

// Names are checked as for the Admin User; existing names and system
// accounts are refused before anything is changed.
func TestCreateUserRefusesBadAndExistingNames(t *testing.T) {
	for _, name := range []string{"root", "ubuntu", "daemon", "alice", "Bob", "-x", ""} {
		h := newFakeHost(t)
		h.addUser("daemon", 1)
		h.addUser("alice", 1000)
		m := newManager(h, "debian")
		if err := m.CreateUser(name); err == nil {
			t.Fatalf("%q: created", name)
		}
		for _, c := range h.calls {
			if !strings.HasPrefix(c, "getent") {
				t.Fatalf("%q: mutated host: %q", name, h.calls)
			}
		}
	}
}
