package tui

import (
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

const (
	aptRefresh  = "env DEBIAN_FRONTEND=noninteractive apt-get update"
	aptSimulate = "apt-get -s --with-new-pkgs -o Debug::NoLocking=true upgrade"
	aptSecurity = "env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold --only-upgrade openssl"
	aptAll      = "env DEBIAN_FRONTEND=noninteractive apt-get --with-new-pkgs upgrade -y -o Dpkg::Options::=--force-confold"
)

// updatesHost is debianHost with one security and one other update pending
// and a kernel update waiting for a reboot.
func updatesHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.fake.Results[aptRefresh] = system.Result{Stdout: "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\n"}
	h.fake.Results[aptSimulate] = system.Result{Stdout: "Reading package lists...\n" +
		"Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n" +
		"Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])\n"}
	h.write("/var/run/reboot-required", "*** System restart required ***\n")
	h.write("/var/run/reboot-required.pkgs", "linux-image-6.8.0-49-generic\n")
	h.write("/run/.keep", "") // the lock lives under /run
	return h
}

// liveFake runs scripted commands like Exec runs real ones under a Task:
// output reaches the Task as it is written. It holds cmd, output shown,
// until release is closed.
type liveFake struct {
	*system.Fake
	cmd     string
	release chan struct{}
}

func (l liveFake) RunLive(w io.Writer, name string, args ...string) (system.Result, error) {
	res, err := l.Fake.Run(name, args...)
	io.WriteString(w, res.Stdout)
	if strings.Join(append([]string{name}, args...), " ") == l.cmd {
		<-l.release
	}
	return res, err
}

// openUpdates starts the TUI on h, commands going through r, and opens the
// loaded Updates screen.
func openUpdates(t *testing.T, h *testHost, r system.Runner) *teatest.TestModel {
	t.Helper()
	tm := teatest.NewTestModel(t, New(harden.NewMachine(r, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("Updates"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "KIND")
	return tm
}

// The list is read after refreshing the package lists: current → new
// version and kind per package, counts and the pending reboot on top.
func TestUpdatesList(t *testing.T) {
	h := updatesHost(t)
	tm := openUpdates(t, h, h.fake)
	v := ctrlCView(t, tm)
	wantAll(t, v, "1 security · 1 other · "+glyph("⚠")+" reboot required (kernel 6.8.0-49-generic)",
		"openssl", "3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5", "security",
		"tzdata", "2024a-3ubuntu1.1 → 2025b-0ubuntu0.24.04", "other",
		"[ Install security ]", "[ Install all … ]", "[ Reboot … ]")
	if r := slices.Index(h.fake.Calls, aptRefresh); r < 0 || !slices.Contains(h.fake.Calls[r:], aptSimulate) {
		t.Errorf("not refreshed before listing: %q", h.fake.Calls)
	}
}

// Install security asks Yes/No, then runs as a Task: refresh, then the
// security packages only, the package manager's output shown while it runs.
func TestUpdatesInstallSecurityTask(t *testing.T) {
	h := updatesHost(t)
	h.fake.Results[aptSecurity] = system.Result{Stdout: "Unpacking openssl (3.0.13-0ubuntu3.5) over (3.0.13-0ubuntu3.4) ...\n"}
	r := liveFake{h.fake, aptSecurity, make(chan struct{})}
	tm := openUpdates(t, h, r)
	tm.Type("s")
	waitFor(t, tm, "Install 1 security update?")
	h.fake.Calls = nil
	tm.Type("y")
	waitFor(t, tm, "Unpacking openssl") // live: the install has not returned yet
	close(r.release)
	waitFor(t, tm, "SUMMARY  security updates installed")
	ctrlCView(t, tm)

	if i := slices.Index(h.fake.Calls, aptRefresh); i < 0 || !slices.Contains(h.fake.Calls[i:], aptSecurity) || slices.Contains(h.fake.Calls, aptAll) {
		t.Errorf("ran %q", h.fake.Calls)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, "updates install security: ok") {
		t.Errorf("Task History:\n%s", log)
	}
	wantAll(t, oneOutput(t, h), "$ "+aptRefresh, "$ "+aptSecurity, "Unpacking openssl")
}

// Install all is dangerous: it runs only once "all" is typed.
func TestUpdatesInstallAllNeedsTyping(t *testing.T) {
	h := updatesHost(t)
	h.fake.Results[aptAll] = system.Result{}
	tm := openUpdates(t, h, h.fake)
	tm.Type("u")
	waitFor(t, tm, `Type "all" to confirm`)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // nothing typed: no
	tm.Type("all")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  all updates installed")
	ctrlCView(t, tm)
	if strings.Count(strings.Join(h.fake.Calls, "\n"), aptAll) != 1 {
		t.Errorf("ran %q", h.fake.Calls)
	}
	if log := actionLog(t, h); !strings.Contains(log, "updates install all: ok") {
		t.Errorf("Task History:\n%s", log)
	}
}

// Reboot wants "reboot" typed; its Task History entry is written before
// the reboot command runs.
func TestUpdatesReboot(t *testing.T) {
	h := updatesHost(t)
	h.fake.Results["systemctl reboot"] = system.Result{}
	r := blockOn{h.fake, "systemctl reboot", make(chan struct{})}
	tm := openUpdates(t, h, r)
	tm.Type("b")
	waitFor(t, tm, `Type "reboot" to confirm`)
	tm.Type("reboot")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "$ systemctl reboot")
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 || !strings.Contains(log, " reboot: ok") {
		t.Errorf("Task History before the reboot:\n%s", log)
	}
	close(r.release)
	waitFor(t, tm, "SUMMARY")
	ctrlCView(t, tm)
	if !slices.Contains(h.fake.Calls, "systemctl reboot") {
		t.Errorf("ran %q", h.fake.Calls)
	}
	if log := actionLog(t, h); strings.Count(log, "\n") != 1 {
		t.Errorf("Task History:\n%s", log)
	}
}

// While another session holds the global lock, reboot is refused with the
// holder: nothing runs, nothing is recorded.
func TestUpdatesRebootRefusedWhileLocked(t *testing.T) {
	h := updatesHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openUpdates(t, h, h.fake)
	tm.Type("breboot")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "refused: locked by ")
	ctrlCView(t, tm)
	if slices.Contains(h.fake.Calls, "systemctl reboot") {
		t.Errorf("ran %q", h.fake.Calls)
	}
	if log := actionLog(t, h); log != "" {
		t.Errorf("Task History:\n%s", log)
	}
}
