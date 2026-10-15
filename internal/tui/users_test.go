package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// usersSim is a host with Managed User alice: adduser creates users that
// getent then returns, usermod -L/-U -e expires/unexpires them in shadow,
// userdel removes them, visudo passes, ssh-keygen writes secretKey and its
// public half.
type usersSim struct {
	*system.Fake
	passwd  []string
	expired map[string]bool
}

// addUser adds the Managed User name.
func (s *usersSim) addUser(name string) {
	s.passwd = append(s.passwd, fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash", name, os.Getuid(), os.Getgid(), name))
}

func (s *usersSim) Run(name string, args ...string) (system.Result, error) {
	switch {
	case name == "getent" && args[0] == "shadow":
		var out string
		for _, l := range s.passwd {
			u, _, _ := strings.Cut(l, ":")
			out += u + ":!:19000:0:99999:7::"
			if s.expired[u] {
				out += "1"
			}
			out += ":\n"
		}
		return system.Result{Stdout: out}, nil
	case name == "usermod":
		s.expired[args[len(args)-1]] = args[0] == "-L"
	case name == "userdel":
		s.passwd = slices.DeleteFunc(s.passwd, func(l string) bool { return strings.HasPrefix(l, args[len(args)-1]+":") })
	case name == "visudo":
	case name == "getent" && args[0] == "passwd":
		var out []string
		for _, l := range s.passwd {
			if len(args) == 1 || strings.HasPrefix(l, args[1]+":") {
				out = append(out, l+"\n")
			}
		}
		if len(out) == 0 {
			return system.Result{Code: 2}, nil
		}
		return system.Result{Stdout: strings.Join(out, "")}, nil
	case name == "adduser":
		s.addUser(args[len(args)-1])
	case name == "ssh-keygen":
		f := args[len(args)-1]
		os.WriteFile(f, []byte(secretKey), 0o600)
		os.WriteFile(f+".pub", []byte("ssh-ed25519 AAAAGENERATED vpsctl-alice\n"), 0o644)
	default:
		return s.Fake.Run(name, args...)
	}
	return system.Result{}, nil
}

// usersScreen opens the Users screen on a host with alice (no keys yet),
// after setup; the private key goes to tty, generated key material under the
// returned tmp.
func usersScreen(t *testing.T, tty *fakeTTY, setup ...func(*testHost, *usersSim)) (*testHost, *teatest.TestModel, string) {
	t.Helper()
	h := debianHost(t)
	h.fake.Results["getent group"] = system.Result{Stdout: "sudo:x:27:\n"}
	h.write("/run/.keep", "")
	sim := &usersSim{Fake: h.fake, passwd: []string{"root:x:0:0:root:/root:/bin/bash"}, expired: map[string]bool{}}
	sim.addUser("alice")
	for _, f := range setup {
		f(h, sim)
	}
	m := harden.NewMachine(sim, h.host, h.root, io.Discard)
	m.TmpDir = t.TempDir()
	m.OpenTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
	tm := teatest.NewTestModel(t, New(m, time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Users"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "LOCKED")
	return h, tm, m.TmpDir
}

func enter(tm *teatest.TestModel) { tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) }

func TestUsersCreateKeyOnlyUser(t *testing.T) {
	h, tm, _ := usersScreen(t, nil)
	tm.Type("c")
	waitFor(t, tm, "New user name")
	tm.Type("root")
	enter(tm)
	waitFor(t, tm, `refusing user "root"`)

	tm.Type("c")
	tm.Type("bob")
	enter(tm)
	waitFor(t, tm, "created bob")
	v := ctrlCView(t, tm)
	wantAll(t, v, "bob          no    0     no")
	al := actionLog(t, h)
	if !strings.Contains(al, "users create root: failed") || !strings.HasSuffix(al, "users create bob: ok\n") {
		t.Errorf("action log:\n%s", al)
	}
}

// A secret pasted into the name field never reaches the action log: a
// multi-line paste is refused, an invalid name is logged without echoing it.
func TestUsersCreateNeverLogsAnInvalidName(t *testing.T) {
	h, tm, _ := usersScreen(t, nil)
	tm.Type("c")
	waitFor(t, tm, "New user name")
	tm.Send(tea.PasteMsg{Content: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n"})
	waitFor(t, tm, "paste one line")
	tm.Send(tea.PasteMsg{Content: "SECRETKEYMATERIAL+/="})
	enter(tm)
	waitFor(t, tm, "invalid user name")
	ctrlCView(t, tm)
	if al := actionLog(t, h); strings.Contains(al, "SECRET") || !strings.HasSuffix(al, "users create: failed: invalid user name\n") {
		t.Errorf("action log:\n%s", al)
	}
}

const pastedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqUmlD6QmJuWwhjzyNUY8yQ4d4sEujQ+Z4U4gWaFOPI alice@laptop"

// A pasted public key is checked, then installed once; the key is never logged.
func TestUsersAddPastedKey(t *testing.T) {
	h, tm, _ := usersScreen(t, nil)
	tm.Type("a")
	waitFor(t, tm, "Public key for alice")
	tm.Send(tea.PasteMsg{Content: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n"})
	enter(tm)
	waitFor(t, tm, "not an OpenSSH public key")

	for range 2 {
		tm.Type("a")
		tm.Send(tea.PasteMsg{Content: pastedKey + "\n"})
		enter(tm)
	}
	waitFor(t, tm, "already in alice's authorized_keys")
	v := ctrlCView(t, tm)
	wantAll(t, v, "alice        no    1     no")
	al := actionLog(t, h)
	if strings.Count(al, "users add-key alice: ok") != 1 || strings.Contains(al, "AAAAC3") || strings.Contains(al, "SECRET") {
		t.Errorf("action log:\n%s", al)
	}
}

// A generated private key is shown raw on the real terminal until `saved`,
// then the public half is installed; nothing of the key stays behind or is logged.
func TestUsersGenerateKeyShownRaw(t *testing.T) {
	r, typed := io.Pipe()
	t.Cleanup(func() { typed.Close() })
	tty := &fakeTTY{in: r}
	h, tm, tmp := usersScreen(t, tty)
	tm.Type("g")
	waitFor(t, tm, "blank = show on screen")
	enter(tm)
	waitTTY(t, tty, "SECRETKEYMATERIAL")
	io.WriteString(typed, "saved\n")
	waitFor(t, tm, "added a generated key to alice")
	v := ctrlCView(t, tm)

	wantAll(t, v, "alice        no    1     no")
	b, _ := os.ReadFile(filepath.Join(h.root, "/home/alice/.ssh/authorized_keys"))
	if string(b) != "ssh-ed25519 AAAAGENERATED vpsctl-alice\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("key material left in %s: %v", tmp, left)
	}
	al := actionLog(t, h)
	if !strings.HasSuffix(al, "users generate-key alice: ok\n") || strings.Contains(al+v, "SECRETKEYMATERIAL") {
		t.Errorf("action log:\n%s", al)
	}
}

// With a key file the private key goes there (mode 600), not to the terminal.
func TestUsersGenerateKeyToFile(t *testing.T) {
	h, tm, _ := usersScreen(t, &fakeTTY{})
	keyFile := filepath.Join(t.TempDir(), "alice.key")
	tm.Type("g")
	tm.Send(tea.PasteMsg{Content: keyFile})
	enter(tm)
	waitFor(t, tm, "added a generated key to alice")
	ctrlCView(t, tm)

	if b, _ := os.ReadFile(keyFile); string(b) != secretKey {
		t.Errorf("key file = %q", b)
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", fi.Mode().Perm())
	}
	if al := actionLog(t, h); strings.Contains(al, keyFile) {
		t.Errorf("action log:\n%s", al)
	}
}

// withAdmins makes each name a usable Admin User: vpsctl's sudo rule and one key.
func withAdmins(names ...string) func(*testHost, *usersSim) {
	return func(h *testHost, s *usersSim) {
		for _, n := range names {
			if n != "alice" {
				s.addUser(n)
			}
			h.write("/etc/sudoers.d/99-vpsctl-"+n, n+" ALL=(ALL:ALL) NOPASSWD: ALL\n")
			h.write("/home/"+n+"/.ssh/authorized_keys", pastedKey+"\n")
		}
	}
}

// The Lockout Guard refuses locking the session's own user; another admin
// is locked, then unlocked, each logged.
func TestUsersLockGuardsOwnUser(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("l")
	waitFor(t, tm, "refused: alice is your own session's user, cannot lock it")
	tm.Type("jl")
	waitFor(t, tm, "locked bob")
	tm.Type("l")
	waitFor(t, tm, "unlocked bob")
	v := ctrlCView(t, tm)

	wantAll(t, v, "alice (you)  yes   1     no", "bob          yes   1     no")
	al := actionLog(t, h)
	for _, want := range []string{"users lock alice: failed: refused", "users lock bob: ok", "users unlock bob: ok"} {
		if !strings.Contains(al, want) {
			t.Errorf("action log missing %q:\n%s", want, al)
		}
	}
}

// On the console (no session user) the guard still keeps the last usable
// Admin User: revoking alice's sudo is refused; granting bob's goes through.
func TestUsersLastAdminKeptOnConsole(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	h, tm, _ := usersScreen(t, nil, withAdmins("alice"), func(_ *testHost, s *usersSim) { s.addUser("bob") })
	tm.Type("s")
	waitFor(t, tm, "refused: alice is the last usable Admin User")
	tm.Type("js")
	waitFor(t, tm, "granted sudo to bob")
	v := ctrlCView(t, tm)

	wantAll(t, v, "alice        yes   1     no", "bob          yes   0     no")
	al := actionLog(t, h)
	if !strings.Contains(al, "users revoke-sudo alice: failed: refused") || !strings.Contains(al, "users grant-sudo bob: ok") {
		t.Errorf("action log:\n%s", al)
	}
}

const deskKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOiYRgOygAvBxXou9+czedWaVm66qdGEpPASTuWPmPjp bob@desk"

// One key is picked by number from the user's keys and removed; the rest stay.
func TestUsersRemoveOneKey(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"), func(h *testHost, _ *usersSim) {
		h.write("/home/bob/.ssh/authorized_keys", pastedKey+"\n"+deskKey+"\n")
	})
	tm.Type("jx")
	waitFor(t, tm, "bob@desk")
	tm.Type("2")
	enter(tm)
	waitFor(t, tm, "removed a key from bob")
	ctrlCView(t, tm)

	if b, _ := os.ReadFile(filepath.Join(h.root, "/home/bob/.ssh/authorized_keys")); string(b) != pastedKey+"\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	if al := actionLog(t, h); !strings.HasSuffix(al, "users remove-key bob: ok\n") || strings.Contains(al, "AAAAC3") {
		t.Errorf("action log:\n%s", al)
	}
}

// Delete asks about the home directory; a blank answer keeps it.
func TestUsersDeleteKeepsHomeByDefault(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("jd")
	waitFor(t, tm, "blank keeps it")
	enter(tm)
	waitFor(t, tm, "deleted bob, home kept")
	v := ctrlCView(t, tm)

	if strings.Contains(v, "bob          ") {
		t.Errorf("bob still listed:\n%s", v)
	}
	if _, err := os.Stat(filepath.Join(h.root, "/home/bob/.ssh/authorized_keys")); err != nil {
		t.Errorf("home not kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "/etc/sudoers.d/99-vpsctl-bob")); err == nil {
		t.Error("bob's sudo rule left behind")
	}
	if al := actionLog(t, h); !strings.HasSuffix(al, "users delete bob: ok\n") {
		t.Errorf("action log:\n%s", al)
	}
}
