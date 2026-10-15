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
// userdel removes them (recorded in deleted), visudo passes, ssh-keygen
// writes secretKey and its public half.
type usersSim struct {
	*system.Fake
	passwd  []string
	expired map[string]bool
	deleted []string // userdel command lines
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
		s.deleted = append(s.deleted, strings.Join(append([]string{name}, args...), " "))
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
func usersScreen(t *testing.T, tty *fakeTTY, setup ...func(*testHost, *usersSim)) (*testHost, *usersSim, *teatest.TestModel, string) {
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
	waitFor(t, tm, "STATE")
	return h, sim, tm, m.TmpDir
}

func enter(tm *teatest.TestModel) { tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) }

// managed reports whether sim has the user name.
func (s *usersSim) managed(name string) bool {
	return slices.ContainsFunc(s.passwd, func(l string) bool { return strings.HasPrefix(l, name+":") })
}

// New users come from a form and are created as a Task; a refused name
// fails the Task with the reason.
func TestUsersCreateKeyOnlyUser(t *testing.T) {
	h, sim, tm, _ := usersScreen(t, nil)
	tm.Type("a")
	waitFor(t, tm, "New user")
	tm.Type("root")
	enter(tm)
	waitFor(t, tm, `refusing user "root"`)
	enter(tm) // close the card

	tm.Type("abob")
	enter(tm)
	waitFor(t, tm, "SUMMARY  created bob")
	ctrlCView(t, tm)
	if !sim.managed("bob") {
		t.Errorf("bob not created: %q", sim.passwd)
	}
	al := actionLog(t, h)
	if !strings.Contains(al, "users create root: failed") || !strings.HasSuffix(al, "users create bob: ok\n") {
		t.Errorf("Task History:\n%s", al)
	}
}

// A secret pasted into the name field is refused by the form: nothing runs
// and nothing reaches Task History.
func TestUsersCreateNeverLogsAnInvalidName(t *testing.T) {
	h, _, tm, _ := usersScreen(t, nil)
	tm.Type("a")
	waitFor(t, tm, "New user")
	tm.Send(tea.PasteMsg{Content: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n"})
	enter(tm)
	waitFor(t, tm, "invalid user name")
	ctrlCView(t, tm)
	if al := actionLog(t, h); al != "" || len(taskOutputs(t, h)) != 0 {
		t.Errorf("Task History %q, outputs %q", al, taskOutputs(t, h))
	}
}

const pastedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMqUmlD6QmJuWwhjzyNUY8yQ4d4sEujQ+Z4U4gWaFOPI alice@laptop"

// A pasted public key is checked, then installed once; the key never
// reaches Task History or a Task's output.
func TestUsersAddPastedKey(t *testing.T) {
	h, _, tm, _ := usersScreen(t, nil)
	tm.Type("i")
	waitFor(t, tm, "Add a key to alice")
	tm.Send(tea.PasteMsg{Content: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n"})
	enter(tm)
	waitFor(t, tm, "not an OpenSSH public key")
	enter(tm)

	tm.Type("i")
	tm.Send(tea.PasteMsg{Content: pastedKey + "\n"})
	enter(tm)
	waitFor(t, tm, "SUMMARY  added a key to alice")
	enter(tm)
	tm.Type("i")
	tm.Send(tea.PasteMsg{Content: pastedKey + "\n"})
	enter(tm)
	waitFor(t, tm, "is already in alice's")
	ctrlCView(t, tm)
	if b, _ := os.ReadFile(filepath.Join(h.root, "/home/alice/.ssh/authorized_keys")); string(b) != pastedKey+"\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	al := actionLog(t, h)
	if strings.Count(al, "users add-key alice: ok") != 1 {
		t.Errorf("Task History:\n%s", al)
	}
	for _, s := range append(taskOutputs(t, h), al) {
		if strings.Contains(s, "AAAAC3") || strings.Contains(s, "SECRET") {
			t.Errorf("key material logged:\n%s", s)
		}
	}
}

// With the key field blank a pair is generated: the private key is shown raw
// on the real terminal until `saved`, then the public half is installed;
// nothing of the key stays behind or is logged.
func TestUsersGenerateKeyShownRaw(t *testing.T) {
	r, typed := io.Pipe()
	t.Cleanup(func() { typed.Close() })
	tty := &fakeTTY{in: r}
	h, _, tm, tmp := usersScreen(t, tty)
	tm.Type("i")
	waitFor(t, tm, "blank = generate")
	enter(tm)
	waitTTY(t, tty, "SECRETKEYMATERIAL")
	io.WriteString(typed, "saved\n")
	waitFor(t, tm, "SUMMARY  added a generated key to alice")
	v := ctrlCView(t, tm)

	b, _ := os.ReadFile(filepath.Join(h.root, "/home/alice/.ssh/authorized_keys"))
	if string(b) != "ssh-ed25519 AAAAGENERATED vpsctl-alice\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("key material left in %s: %v", tmp, left)
	}
	al := actionLog(t, h)
	if !strings.HasSuffix(al, "users generate-key alice: ok\n") {
		t.Errorf("Task History:\n%s", al)
	}
	for _, s := range append(taskOutputs(t, h), al, v) {
		if strings.Contains(s, "SECRETKEYMATERIAL") {
			t.Errorf("private key leaked:\n%s", s)
		}
	}
}

// With a key file the private key goes there (mode 600), not to the terminal.
func TestUsersGenerateKeyToFile(t *testing.T) {
	h, _, tm, _ := usersScreen(t, &fakeTTY{})
	keyFile := filepath.Join(t.TempDir(), "alice.key")
	tm.Type("i")
	waitFor(t, tm, "blank = generate")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
	tm.Send(tea.PasteMsg{Content: keyFile})
	enter(tm)
	waitFor(t, tm, "SUMMARY  added a generated key to alice")
	ctrlCView(t, tm)

	if b, _ := os.ReadFile(keyFile); string(b) != secretKey {
		t.Errorf("key file = %q", b)
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", fi.Mode().Perm())
	}
	if al := actionLog(t, h); strings.Contains(al, keyFile) {
		t.Errorf("Task History:\n%s", al)
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

// The operator's own user is marked (you); its Lock is disabled with the
// Lockout Guard's reason in the detail box, and l does nothing.
func TestUsersLockDisabledOnOwnUser(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, sim, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("l")
	v := ctrlCView(t, tm)

	wantAll(t, v, "alice (you)", "◆ Lock: alice is your own session's user, cannot lock it", "[ Lock ]")
	if strings.Contains(v, "Lock alice?") || sim.expired["alice"] || h.actionLog() != "" {
		t.Errorf("expired %v, Task History %q:\n%s", sim.expired, h.actionLog(), v)
	}
}

// Another admin is locked after a Yes/No, as a Task.
func TestUsersLockAnotherAdmin(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, sim, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("l") // disabled on alice: nothing to answer
	tm.Type("jl")
	waitFor(t, tm, "Lock bob?")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY  locked bob")
	ctrlCView(t, tm)

	if sim.expired["alice"] || !sim.expired["bob"] {
		t.Errorf("expired %v", sim.expired)
	}
	if al := actionLog(t, h); strings.Count(al, "\n") != 1 || !strings.Contains(al, "users lock bob: ok") {
		t.Errorf("Task History:\n%s", al)
	}
}

// On the console (no session user) the guard still keeps the last usable
// Admin User: alice's Sudo off is disabled; granting bob's goes through.
func TestUsersLastAdminKeptOnConsole(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	h, _, tm, _ := usersScreen(t, nil, withAdmins("alice"), func(_ *testHost, s *usersSim) { s.addUser("bob") })
	tm.Type("s")
	tm.Type("j")
	tm.Type("s")
	waitFor(t, tm, "Grant sudo to bob?")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY  granted sudo to bob")
	ctrlCView(t, tm)

	if _, err := os.Stat(filepath.Join(h.root, "/etc/sudoers.d/99-vpsctl-alice")); err != nil {
		t.Errorf("alice's sudo rule: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "/etc/sudoers.d/99-vpsctl-bob")); err != nil {
		t.Errorf("bob's sudo rule: %v", err)
	}
	if al := actionLog(t, h); strings.Count(al, "\n") != 1 || !strings.Contains(al, "users grant-sudo bob: ok") {
		t.Errorf("Task History:\n%s", al)
	}
}

const deskKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOiYRgOygAvBxXou9+czedWaVm66qdGEpPASTuWPmPjp bob@desk"

// One key, numbered in the detail box, is picked by number and removed
// after a Yes/No; the rest stay.
func TestUsersRemoveOneKey(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, _, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"), func(h *testHost, _ *usersSim) {
		h.write("/home/bob/.ssh/authorized_keys", pastedKey+"\n"+deskKey+"\n")
	})
	tm.Type("j")
	waitFor(t, tm, "bob@desk")
	tm.Type("x2")
	enter(tm)
	waitFor(t, tm, "Remove key 2 of bob?")
	tm.Type("y")
	waitFor(t, tm, "SUMMARY  removed a key from bob")
	ctrlCView(t, tm)

	if b, _ := os.ReadFile(filepath.Join(h.root, "/home/bob/.ssh/authorized_keys")); string(b) != pastedKey+"\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	if al := actionLog(t, h); !strings.HasSuffix(al, "users remove-key bob: ok\n") || strings.Contains(al, "AAAAC3") {
		t.Errorf("Task History:\n%s", al)
	}
}

// Delete is the dangerous confirm: enter does nothing until the user's name
// is typed exactly.
func TestUsersDeleteNeedsTheName(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, sim, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("jd")
	waitFor(t, tm, `Type "bob" to confirm`)
	tm.Type("bo")
	enter(tm)
	v := ctrlCView(t, tm)
	wantAll(t, v, "Delete user bob", `Type "bob" to confirm: bo`)
	if len(sim.deleted) != 0 || h.actionLog() != "" {
		t.Errorf("ran %q, Task History %q", sim.deleted, h.actionLog())
	}
}

// Typing the name deletes the user as a Task; the home directory is kept by
// default.
func TestUsersDeleteDangerousKeepsHome(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	h, sim, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("jd")
	waitFor(t, tm, "home /home/bob: keep")
	tm.Type("bob")
	enter(tm)
	waitFor(t, tm, "SUMMARY  deleted bob, home kept")
	ctrlCView(t, tm)

	if !slices.Equal(sim.deleted, []string{"userdel bob"}) {
		t.Errorf("ran %q", sim.deleted)
	}
	if _, err := os.Stat(filepath.Join(h.root, "/home/bob/.ssh/authorized_keys")); err != nil {
		t.Errorf("home not kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "/etc/sudoers.d/99-vpsctl-bob")); err == nil {
		t.Error("bob's sudo rule left behind")
	}
	if al := actionLog(t, h); strings.Count(al, "\n") != 1 || !strings.HasSuffix(al, "users delete bob: ok\n") {
		t.Errorf("Task History:\n%s", al)
	}
}

// tab in the delete dialog switches to deleting the home directory too.
func TestUsersDeleteWithHome(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	_, sim, tm, _ := usersScreen(t, nil, withAdmins("alice", "bob"))
	tm.Type("jd")
	waitFor(t, tm, "home /home/bob: keep")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
	waitFor(t, tm, "delete (tab: keep")
	tm.Type("bob")
	enter(tm)
	waitFor(t, tm, "SUMMARY  deleted bob and its home")
	ctrlCView(t, tm)
	if !slices.Equal(sim.deleted, []string{"userdel -r bob"}) {
		t.Errorf("ran %q", sim.deleted)
	}
}
