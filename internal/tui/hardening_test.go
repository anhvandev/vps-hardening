package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

const secretKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n"

// hardenSim is sshSim plus the user side of Hardening: adduser creates users
// that getent then returns, ssh-keygen writes a key pair, sudo/visudo/usermod pass.
type hardenSim struct {
	*sshSim
	users map[string]string
}

func (s *hardenSim) Run(name string, args ...string) (system.Result, error) {
	switch {
	case name == "getent" && len(args) == 2 && args[0] == "passwd":
		if line, ok := s.users[args[1]]; ok {
			return system.Result{Stdout: line}, nil
		}
		return system.Result{Code: 2}, nil
	case name == "adduser":
		u := args[len(args)-1]
		s.users[u] = fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash\n", u, os.Getuid(), os.Getgid(), u)
	case name == "ssh-keygen":
		f := args[len(args)-1]
		os.WriteFile(f, []byte(secretKey), 0o600)
		os.WriteFile(f+".pub", []byte("ssh-ed25519 AAAA vpsctl-alice\n"), 0o644)
	case name == "usermod" || name == "visudo" || name == "sudo":
	default:
		return s.sshSim.Run(name, args...)
	}
	return system.Result{}, nil
}

// fakeTTY is the operator's real terminal: what the key code writes, and a
// pipe the test types into.
type fakeTTY struct {
	in  *io.PipeReader
	mu  sync.Mutex
	out strings.Builder
}

func (f *fakeTTY) Read(p []byte) (int, error) { return f.in.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}
func (f *fakeTTY) Close() error { return nil }
func (f *fakeTTY) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.String()
}

// unhardenedHost is a fresh ubuntu host on port 22 (only Stage A's drop-in,
// so not hardened); the operator types into the returned pipe.
func unhardenedHost(t *testing.T) (*testHost, *hardenSim, *fakeTTY, *io.PipeWriter) {
	h, ssh := portChangeHost(t)
	h.write("/etc/ssh/sshd_config.d/00-vpsctl.conf", "# Managed by vpsctl - do not edit by hand.\nPort 22\n")
	h.write("/etc/sudoers.d/.keep", "")
	os.RemoveAll(filepath.Join(h.root, "/home/alice")) // alice is new
	r, w := io.Pipe()
	t.Cleanup(func() { w.Close() })
	return h, &hardenSim{sshSim: ssh, users: map[string]string{}}, &fakeTTY{in: r}, w
}

// startWizard opens the TUI on sim with tty as the terminal, opens the
// Hardening wizard with h, types user and runs it.
func startWizard(t *testing.T, h *testHost, sim *hardenSim, tty *fakeTTY, user string) *teatest.TestModel {
	t.Helper()
	m := harden.NewMachine(sim, h.host, h.root, io.Discard)
	m.OpenTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
	tm := teatest.NewTestModel(t, New(m), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "NOT HARDENED")
	tm.Type("h")
	waitFor(t, tm, "Admin user")
	tm.Type(user)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	return tm
}

// waitTTY blocks until the terminal received s.
func waitTTY(t *testing.T, tty *fakeTTY, s string) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); !strings.Contains(tty.String(), s); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("terminal never got %q:\n%s", s, tty.String())
		}
	}
}

// ctrlCView quits from wherever the focus is and returns the last frame.
func ctrlCView(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	return ansi.Strip(tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).View().Content)
}

func hardenLog(t *testing.T, h *testHost) string {
	t.Helper()
	logs, _ := filepath.Glob(filepath.Join(h.root, "/var/log/vpsctl/harden-*.log"))
	if len(logs) != 1 {
		t.Fatalf("want one Hardening log, got %q", logs)
	}
	b, _ := os.ReadFile(logs[0])
	return string(b)
}

func TestHardeningWizardHappyPath(t *testing.T) {
	h, sim, tty, typed := unhardenedHost(t)
	tm := startWizard(t, h, sim, tty, "alice")

	// The key goes raw to the real terminal, outside the alternate screen.
	waitTTY(t, tty, "SECRETKEYMATERIAL")
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return bytes.Contains(b, []byte(ansi.ResetModeAltScreenSaveCursor))
	}, teatest.WithDuration(3*time.Second))
	io.WriteString(typed, "saved\n")

	waitFor(t, tm, "ssh -p 22 alice@10.0.0.2")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyLeft}) // to "Login works"
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "Hardening complete")
	v := ctrlCView(t, tm) // still in the wizard: the banner is gone without leaving it

	if strings.Contains(v, "NOT HARDENED") {
		t.Errorf("banner still shown after Hardening:\n%s", v)
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "/home/alice/.ssh/authorized_keys"))
	if string(b) != "ssh-ed25519 AAAA vpsctl-alice\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	hl, al := hardenLog(t, h), actionLog(t, h)
	if !strings.Contains(hl, "== SUMMARY ==") || !strings.HasSuffix(al, "harden --user alice: ok\n") {
		t.Errorf("Hardening log:\n%s\naction log:\n%s", hl, al)
	}
	for name, s := range map[string]string{"frame": v, "Hardening log": hl, "action log": al} {
		if strings.Contains(s, "SECRETKEYMATERIAL") {
			t.Errorf("private key in the %s", name)
		}
	}
}

// The wizard validates like `vpsctl harden`: bad combinations never start a
// run; root, Default Cloud Users and system accounts are refused.
func TestHardeningWizardValidatesLikeCLI(t *testing.T) {
	h, sim, tty, _ := unhardenedHost(t)
	tm := startWizard(t, h, sim, tty, "root")
	waitFor(t, tm, `refusing admin user "root"`)

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Type("2222")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // Skip firewall
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "cannot be combined with --skip-firewall")
	ctrlCView(t, tm)
	if al := actionLog(t, h); strings.Contains(al, "2222") {
		t.Errorf("rejected input ran:\n%s", al)
	}
}

// Stopping at the Verify Gate is the CLI's exit 3: pre-run SSH restored,
// the banner stays.
func TestHardeningWizardStopAtGate(t *testing.T) {
	h, sim, tty, typed := unhardenedHost(t)
	dropIn := filepath.Join(h.root, "/etc/ssh/sshd_config.d/00-vpsctl.conf")
	before, _ := os.ReadFile(dropIn)
	tm := startWizard(t, h, sim, tty, "alice")
	waitTTY(t, tty, "SECRETKEYMATERIAL")
	io.WriteString(typed, "saved\n")
	waitFor(t, tm, "Stop safely")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "Stop safely" is the default
	waitFor(t, tm, "Stopped at the Verify Gate")
	v := ctrlCView(t, tm)

	wantAll(t, v, "NOT HARDENED", "password auth still enabled")
	after, _ := os.ReadFile(dropIn)
	if string(after) != string(before) || sim.listening != 22 {
		t.Errorf("drop-in %q, listening %d", after, sim.listening)
	}
	if al := actionLog(t, h); !strings.Contains(al, "harden --user alice: failed: stopped at the Verify Gate") {
		t.Errorf("action log:\n%s", al)
	}
}
