package user

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anhvandev/vpsctl/internal/system"
)

// fakeHost is a stateful Runner: useradd/adduser create users that getent
// then returns, ssh-keygen writes a key pair. Commands named in fail exit 1.
type fakeHost struct {
	root  string
	users map[string]string // name -> passwd line
	fail  map[string]bool
	calls []string
}

func newFakeHost(t *testing.T) *fakeHost {
	root := t.TempDir()
	for _, d := range []string{"etc/sudoers.d", "home", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeHost{root: root, users: map[string]string{}, fail: map[string]bool{}}
}

func (h *fakeHost) addUser(name string, uid int) {
	h.users[name] = fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash", name, uid, os.Getgid(), name)
	os.MkdirAll(filepath.Join(h.root, "home", name), 0o755)
}

func (h *fakeHost) Run(name string, args ...string) (system.Result, error) {
	h.calls = append(h.calls, strings.Join(append([]string{name}, args...), " "))
	if h.fail[name] {
		return system.Result{Code: 1, Stderr: "boom"}, nil
	}
	switch name {
	case "getent":
		line, ok := h.users[args[1]]
		if !ok {
			return system.Result{Code: 2}, nil
		}
		return system.Result{Stdout: line + "\n"}, nil
	case "adduser", "useradd":
		h.addUser(args[len(args)-1], os.Getuid())
	case "ssh-keygen":
		f := args[len(args)-1]
		os.WriteFile(f, []byte("PRIVATE KEY\n"), 0o600)
		os.WriteFile(f+".pub", []byte("ssh-ed25519 AAAA vpsctl\n"), 0o644)
	}
	return system.Result{}, nil
}

// installerFunc adapts a func to Installer.
type installerFunc func(pkgs ...string) error

func (f installerFunc) Install(pkgs ...string) error { return f(pkgs...) }

func newManager(h *fakeHost, family string) *Manager {
	group := "wheel"
	if family == "debian" {
		group = "sudo"
	}
	return &Manager{
		R:      h,
		Host:   system.Host{Family: family, AdminGroup: group},
		Pkgs:   installerFunc(func(...string) error { return nil }),
		Root:   h.root,
		TmpDir: filepath.Join(h.root, "tmp"),
	}
}

func TestSudoInstalledBeforeAnySudoersFileIsWritten(t *testing.T) {
	h := newFakeHost(t)
	h.fail["sudo"] = true // image without sudo
	m := newManager(h, "debian")
	installed := false
	m.Pkgs = installerFunc(func(pkgs ...string) error {
		if len(pkgs) != 1 || pkgs[0] != "sudo" {
			t.Fatalf("installed %q, want sudo", pkgs)
		}
		entries, _ := os.ReadDir(filepath.Join(h.root, "etc/sudoers.d"))
		if len(entries) != 0 {
			t.Fatalf("sudoers.d not empty when sudo installed: %v", entries)
		}
		for _, c := range h.calls {
			if strings.HasPrefix(c, "visudo") {
				t.Fatal("visudo ran before sudo was installed")
			}
		}
		installed = true
		return nil
	})

	if err := m.EnsureAdmin("alice"); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("sudo was never installed")
	}
	got, err := os.ReadFile(filepath.Join(h.root, "etc/sudoers.d/99-vpsctl-alice"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "\nalice ALL=(ALL:ALL) NOPASSWD: ALL\n") {
		t.Fatalf("sudoers content: %q", got)
	}
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s not cleaned up: %v", dir, entries)
	}
}

func TestInstallKeyWritesKeyOutAndInstallsPubkey(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("alice", os.Getuid())
	m := newManager(h, "rhel")
	m.Host.SELinux = true
	keyOut := filepath.Join(t.TempDir(), "alice.key")

	if err := m.InstallKey("alice", keyOut, false, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(keyOut); string(b) != "PRIVATE KEY\n" {
		t.Fatalf("key-out = %q", b)
	}
	if fi, _ := os.Stat(keyOut); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key-out mode %v", fi.Mode().Perm())
	}
	ak := filepath.Join(h.root, "home/alice/.ssh/authorized_keys")
	if b, _ := os.ReadFile(ak); string(b) != "ssh-ed25519 AAAA vpsctl\n" {
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
	assertEmptyDir(t, m.TmpDir)

	// Re-run: key was emitted by vpsctl → kept, no new key generated.
	h.calls = nil
	if err := m.InstallKey("alice", keyOut, false, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(h.calls, "\n"), "ssh-keygen") {
		t.Fatal("regenerated an already-emitted key")
	}
}

func TestInstallKeyRefusesNeverEmittedKeyUnlessRotate(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("alice", os.Getuid())
	m := newManager(h, "debian")
	os.MkdirAll(filepath.Join(h.root, "home/alice/.ssh"), 0o700)
	os.WriteFile(filepath.Join(h.root, "home/alice/.ssh/authorized_keys"), []byte("ssh-ed25519 OLD\n"), 0o600)
	keyOut := filepath.Join(t.TempDir(), "k")

	err := m.InstallKey("alice", keyOut, false, true)
	if err == nil || !strings.Contains(err.Error(), "--rotate-key") {
		t.Fatalf("err = %v, want refusal mentioning --rotate-key", err)
	}
	if err := m.InstallKey("alice", keyOut, true, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "home/alice/.ssh/authorized_keys")); string(b) != "ssh-ed25519 AAAA vpsctl\n" {
		t.Fatalf("rotate did not replace key: %q", b)
	}
}

func TestPrivateKeyTempDirRemovedOnEveryFailure(t *testing.T) {
	cases := map[string]func(h *fakeHost, m *Manager){
		"ssh-keygen fails": func(h *fakeHost, m *Manager) { h.fail["ssh-keygen"] = true },
		"restorecon fails": func(h *fakeHost, m *Manager) { m.Host.SELinux = true; h.fail["restorecon"] = true },
		"tty write fails": func(h *fakeHost, m *Manager) {
			m.OpenTTY = func() (io.ReadWriteCloser, error) { return failWriter{}, nil }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			h.addUser("alice", os.Getuid())
			m := newManager(h, "debian")
			m.OpenTTY = func() (io.ReadWriteCloser, error) { return fakeTTY{strings.NewReader("saved\n"), io.Discard}, nil }
			setup(h, m)
			if err := m.InstallKey("alice", "", false, true); err == nil {
				t.Fatal("expected error")
			}
			assertEmptyDir(t, m.TmpDir)
		})
	}
}

func TestNoControllingTTYTellsToUseKeyOut(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("alice", os.Getuid())
	m := newManager(h, "debian")
	m.OpenTTY = func() (io.ReadWriteCloser, error) { return nil, errors.New("open /dev/tty: no such device") }

	err := m.InstallKey("alice", "", false, true)
	if err == nil || !strings.Contains(err.Error(), "--key-out") {
		t.Fatalf("err = %v, want hint to use --key-out", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "home/alice/.ssh/authorized_keys")); err == nil {
		t.Fatal("key installed although it could not be shown")
	}
}

func TestLockDefaultCloudUsersAndBlockCloudInit(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("ubuntu", 1000)
	h.addUser("alice", 1001)
	ak := filepath.Join(h.root, "home/ubuntu/.ssh/authorized_keys")
	os.MkdirAll(filepath.Dir(ak), 0o700)
	os.WriteFile(ak, []byte("ssh-rsa PROVIDER\n"), 0o600)
	os.MkdirAll(filepath.Join(h.root, "etc/cloud/cloud.cfg.d"), 0o755)
	m := newManager(h, "debian")

	if err := m.LockDefaultCloudUsers(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(ak); fi.Size() != 0 {
		t.Fatal("authorized_keys not emptied")
	}
	calls := strings.Join(h.calls, "\n")
	if !strings.Contains(calls, "usermod -L -s /usr/sbin/nologin ubuntu") {
		t.Fatalf("ubuntu not locked: %q", h.calls)
	}
	if strings.Contains(calls, "alice") || strings.Contains(calls, "usermod -L -s /usr/sbin/nologin debian") {
		t.Fatalf("locked a non-cloud or absent user: %q", h.calls)
	}

	if err := m.BlockCloudInitReinjection(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "etc/cloud/cloud.cfg.d/99-vpsctl.cfg")); string(b) != "disable_root: true\nusers: []\n" {
		t.Fatalf("cloud-init drop-in = %q", b)
	}
}

// fakeTTY reads the operator's typing from Reader and shows output on Writer.
type fakeTTY struct {
	io.Reader
	io.Writer
}

func (fakeTTY) Close() error { return nil }

type failWriter struct{}

func (failWriter) Read([]byte) (int, error)  { return 0, io.EOF }
func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write /dev/tty: EIO") }
func (failWriter) Close() error              { return nil }

// Spec "Private key display": after printing the key on the TTY, wait for the
// operator to type `saved` (re-prompting otherwise) before installing it.
func TestTTYKeyWaitsForSaved(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("alice", os.Getuid())
	m := newManager(h, "debian")
	var screen strings.Builder
	m.OpenTTY = func() (io.ReadWriteCloser, error) {
		return fakeTTY{strings.NewReader("ok\n Saved \nsaved\n"), &screen}, nil
	}
	if err := m.InstallKey("alice", "", false, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(screen.String(), "PRIVATE KEY\n") {
		t.Fatalf("key not shown: %q", screen.String())
	}
	if n := strings.Count(screen.String(), "Type 'saved'"); n != 3 {
		t.Fatalf("prompted %d times, want 3: %q", n, screen.String())
	}
	if _, err := os.Stat(filepath.Join(h.root, "home/alice/.ssh/authorized_keys")); err != nil {
		t.Fatal("key not installed after saved")
	}
}

// EOF (or a read error) before `saved` aborts: nothing installed, temp dir gone.
func TestTTYKeyNotConfirmedAborts(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("alice", os.Getuid())
	m := newManager(h, "debian")
	m.OpenTTY = func() (io.ReadWriteCloser, error) { return fakeTTY{strings.NewReader("nope\n"), io.Discard}, nil }
	if err := m.InstallKey("alice", "", false, true); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(filepath.Join(h.root, "home/alice/.ssh/authorized_keys")); err == nil {
		t.Fatal("key installed although never confirmed saved")
	}
	assertEmptyDir(t, m.TmpDir)
}

// --yes: the key is shown but nothing is read from the TTY.
func TestTTYKeyNoWaitWithYes(t *testing.T) {
	h := newFakeHost(t)
	h.addUser("alice", os.Getuid())
	m := newManager(h, "debian")
	m.OpenTTY = func() (io.ReadWriteCloser, error) { return fakeTTY{strings.NewReader(""), io.Discard}, nil }
	if err := m.InstallKey("alice", "", false, false); err != nil {
		t.Fatal(err)
	}
}

func TestLookupReadsPasswdEntry(t *testing.T) {
	h := newFakeHost(t)
	h.users["alice"] = "alice:x:1001:1002:Alice:/home/alice:/bin/bash"
	m := newManager(h, "debian")
	pw, ok, err := m.Lookup("alice")
	if err != nil || !ok || pw != (PasswdEntry{UID: 1001, GID: 1002, Home: "/home/alice"}) {
		t.Fatalf("Lookup(alice) = %+v, %v, %v", pw, ok, err)
	}
	if _, ok, err := m.Lookup("bob"); ok || err != nil {
		t.Fatalf("Lookup(bob) = %v, %v; want absent, no error", ok, err)
	}
}

func TestEnsureAdminRefusesSystemUsersAndDefaultCloudUsers(t *testing.T) {
	for _, name := range []string{"daemon", "ubuntu", "ec2-user", "root"} {
		h := newFakeHost(t)
		h.addUser("daemon", 1)
		m := newManager(h, "rhel")
		err := m.EnsureAdmin(name)
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("%s: err = %v, want refusal", name, err)
		}
		for _, c := range h.calls {
			if !strings.HasPrefix(c, "getent") {
				t.Fatalf("%s: mutated host after refusal: %q", name, h.calls)
			}
		}
	}
}
