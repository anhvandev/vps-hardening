package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// usersSim is a host with Managed User alice: adduser creates users that
// getent then returns, ssh-keygen writes secretKey and its public half.
type usersSim struct {
	*system.Fake
	passwd []string
}

func (s *usersSim) Run(name string, args ...string) (system.Result, error) {
	switch {
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
		u := args[len(args)-1]
		s.passwd = append(s.passwd, fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash", u, os.Getuid(), os.Getgid(), u))
	case name == "ssh-keygen":
		f := args[len(args)-1]
		os.WriteFile(f, []byte(secretKey), 0o600)
		os.WriteFile(f+".pub", []byte("ssh-ed25519 AAAAGENERATED vpsctl-alice\n"), 0o644)
	default:
		return s.Fake.Run(name, args...)
	}
	return system.Result{}, nil
}

// usersScreen opens the Users screen on a host with alice (no keys yet);
// the private key goes to tty, generated key material under the returned tmp.
func usersScreen(t *testing.T, tty *fakeTTY) (*testHost, *teatest.TestModel, string) {
	t.Helper()
	h := debianHost(t)
	h.fake.Results["getent group"] = system.Result{Stdout: "sudo:x:27:\n"}
	h.fake.Results["getent shadow"] = system.Result{}
	h.write("/run/.keep", "")
	sim := &usersSim{Fake: h.fake, passwd: []string{
		"root:x:0:0:root:/root:/bin/bash",
		fmt.Sprintf("alice:x:%d:%d::/home/alice:/bin/bash", os.Getuid(), os.Getgid()),
	}}
	m := harden.NewMachine(sim, h.host, h.root, io.Discard)
	m.TmpDir = t.TempDir()
	m.OpenTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
	tm := teatest.NewTestModel(t, New(m), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type("jjjj")
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
