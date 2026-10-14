package user

import (
	"fmt"
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
