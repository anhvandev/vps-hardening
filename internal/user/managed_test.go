package user

import (
	"io"
	"os"
	"path/filepath"
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

const (
	laptopKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqUmlD6QmJuWwhjzyNUY8yQ4d4sEujQ+Z4U4gWaFOPI bob@laptop"
	deskKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOiYRgOygAvBxXou9+czedWaVm66qdGEpPASTuWPmPjp bob@desk"
)

// A pasted public key is appended to authorized_keys (owner-only, SELinux
// context restored); the same key again is not added twice.
func TestAddKeyAppendsPastedPublicKeyOnce(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("bob", os.Getuid())
	m := newManager(h, "rhel")
	m.Host.SELinux = true
	ak := filepath.Join(h.root, "home/bob/.ssh/authorized_keys")
	os.MkdirAll(filepath.Dir(ak), 0o755)
	os.WriteFile(ak, []byte(deskKey), 0o644) // no trailing newline

	if err := m.AddKey("bob", "  "+laptopKey+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddKey("bob", strings.Replace(laptopKey, "bob@laptop", "other comment", 1)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if b, _ := os.ReadFile(ak); string(b) != deskKey+"\n"+laptopKey+"\n" {
		t.Fatalf("authorized_keys = %q", b)
	}
	if fi, _ := os.Stat(ak); fi.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(ak)); fi.Mode().Perm() != 0o700 {
		t.Fatalf(".ssh mode %v", fi.Mode().Perm())
	}
	if !strings.Contains(strings.Join(h.calls, "\n"), "restorecon -R "+filepath.Dir(ak)) {
		t.Fatalf("no restorecon on SELinux: %q", h.calls)
	}
}

// Anything that is not one public key line is refused before install, and
// the error never echoes what was pasted.
func TestAddKeyRefusesNonPublicKeys(t *testing.T) {
	for _, bad := range []string{
		"",
		"hello world",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIMqUmlD6QmJuWwhjzyNUY8yQ4d4sEujQ+Z4U4gWaFOPI", // blob is ed25519
		"ssh-ed25519 not-base64!!",
		laptopKey + "\n" + deskKey,
	} {
		h := newFakeHost(t)
		h.addUser("bob", os.Getuid())
		m := newManager(h, "debian")
		err := m.AddKey("bob", bad)
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
		if f := strings.Fields(bad); len(f) > 1 && strings.Contains(err.Error(), f[1]) {
			t.Fatalf("error echoes the input: %v", err)
		}
		if _, err := os.Stat(filepath.Join(h.root, "home/bob/.ssh/authorized_keys")); err == nil {
			t.Fatalf("%q installed", bad)
		}
	}
}

// A generated pair is shown once (here written to a 600 file) and its public
// half added beside the keys already there.
func TestGenerateKeyEmitsThenAddsPublicHalf(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("bob", os.Getuid())
	m := newManager(h, "debian")
	ak := filepath.Join(h.root, "home/bob/.ssh/authorized_keys")
	os.MkdirAll(filepath.Dir(ak), 0o700)
	os.WriteFile(ak, []byte(deskKey+"\n"), 0o600)
	keyOut := filepath.Join(t.TempDir(), "bob.key")

	if err := m.GenerateKey("bob", keyOut); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(keyOut); string(b) != "PRIVATE KEY\n" {
		t.Fatalf("key file = %q", b)
	}
	if fi, _ := os.Stat(keyOut); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(ak); string(b) != deskKey+"\nssh-ed25519 AAAA vpsctl\n" {
		t.Fatalf("authorized_keys = %q", b)
	}
	assertEmptyDir(t, m.TmpDir)
}

// Generated key material is removed on every path; a key nobody received
// (emit failed or never confirmed saved) is not installed.
func TestGenerateKeyCleansUpOnEveryFailure(t *testing.T) {
	cases := map[string]func(h *fakeHost, m *Manager){
		"ssh-keygen fails": func(h *fakeHost, m *Manager) { h.fail["ssh-keygen"] = true },
		"restorecon fails": func(h *fakeHost, m *Manager) { m.Host.SELinux = true; h.fail["restorecon"] = true },
		"tty write fails": func(h *fakeHost, m *Manager) {
			m.OpenTTY = func() (io.ReadWriteCloser, error) { return failWriter{}, nil }
		},
		"never saved": func(h *fakeHost, m *Manager) {
			m.OpenTTY = func() (io.ReadWriteCloser, error) { return fakeTTY{strings.NewReader("nope\n"), io.Discard}, nil }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			h.addUser("bob", os.Getuid())
			m := newManager(h, "debian")
			m.OpenTTY = func() (io.ReadWriteCloser, error) { return fakeTTY{strings.NewReader("saved\n"), io.Discard}, nil }
			setup(h, m)
			if err := m.GenerateKey("bob", ""); err == nil {
				t.Fatal("expected error")
			}
			assertEmptyDir(t, m.TmpDir)
			if name != "restorecon fails" {
				if _, err := os.Stat(filepath.Join(h.root, "home/bob/.ssh/authorized_keys")); err == nil {
					t.Fatal("key installed")
				}
			}
		})
	}
}
