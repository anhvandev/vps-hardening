package tui

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/anhvandev/vpsctl/internal/actionlog"
	"github.com/anhvandev/vpsctl/internal/harden"
	"github.com/anhvandev/vpsctl/internal/system"
)

// f2bHost is debianHost with fail2ban running two jails (two bans in sshd)
// and /run present for the global lock.
func f2bHost(t *testing.T) *testHost {
	h := debianHost(t)
	h.fake.Results["fail2ban-client status"] = system.Result{Stdout: "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"}
	h.fake.Results["fail2ban-client status sshd"] = system.Result{Stdout: "Status for the jail: sshd\n|- Filter\n|  `- Total failed:\t9\n" +
		"`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t2\n   `- Banned IP list:\t198.51.100.7 2001:db8::9\n"}
	h.fake.Results["fail2ban-client status recidive"] = system.Result{Stdout: "Status for the jail: recidive\n" +
		"`- Actions\n   |- Currently banned:\t0\n   `- Banned IP list:\t\n"}
	h.fake.Results["fail2ban-client set sshd unbanip 2001:db8::9"] = system.Result{Stdout: "1\n"}
	if err := os.MkdirAll(filepath.Join(h.root, "/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *testHost) actionLog() string {
	b, _ := os.ReadFile(filepath.Join(h.root, actionlog.LogPath))
	return string(b)
}

// Unbanning the selected IP runs as a Task: its command in the output, one
// Task History line, and the list re-read after.
func TestFail2banUnbanSelectedIPAsTask(t *testing.T) {
	h := f2bHost(t)
	tm := openFail2ban(h)
	waitFor(t, tm, "2001:db8::9")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Type("u")
	waitFor(t, tm, "SUMMARY  unbanned 2001:db8::9 from sshd")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // close the card
	v := ctrlCView(t, tm)
	wantAll(t, v, "sshd", "recidive", "198.51.100.7")
	if !slices.Contains(h.fake.Calls, "fail2ban-client set sshd unbanip 2001:db8::9") {
		t.Errorf("no unban call in %q", h.fake.Calls)
	}
	if log := h.actionLog(); strings.Count(log, "\n") != 1 || !strings.Contains(log, "fail2ban unban 2001:db8::9 sshd: ok") {
		t.Errorf("Task History = %q", log)
	}
	wantAll(t, oneOutput(t, h), "$ fail2ban-client set sshd unbanip 2001:db8::9")
}

func TestFail2banUnbanWhileLockedIsRefused(t *testing.T) {
	h := f2bHost(t)
	lk, err := actionlog.Lock(filepath.Join(h.root, actionlog.LockPath))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	tm := openFail2ban(h)
	waitFor(t, tm, "198.51.100.7")
	tm.Type("u")
	waitFor(t, tm, "refused: locked by")
	ctrlCView(t, tm)
	for _, c := range h.fake.Calls {
		if strings.Contains(c, "unbanip") {
			t.Errorf("unbanned while locked: %q", c)
		}
	}
}

const f2bDropIn = "/etc/fail2ban/jail.d/00-vpsctl.local"

// The operator's SSH session IP (from SSH_CONNECTION of the sudo that started
// vpsctl) is suggested; saving appends it to the drop-in's ignoreip and
// reloads, as a Task.
func TestFail2banIgnoreSessionIP(t *testing.T) {
	h := f2bHost(t)
	h.fake.Results["fail2ban-client reload"] = system.Result{Stdout: "OK\n"}
	h.write(f2bDropIn, "[DEFAULT]\nignoreip = 10.0.0.0/8\n\n[sshd]\nenabled = true\nport = 22\n")
	pid := strconv.Itoa(os.Getpid())
	h.write("/proc/"+pid+"/stat", pid+" (vpsctl) S 4242 4242 4242 0")
	h.write("/proc/"+pid+"/environ", "SUDO_USER=alice\x00")
	h.write("/proc/4242/environ", "TERM=xterm\x00SSH_CONNECTION=203.0.113.5 50122 10.0.0.2 22\x00")
	tm := openFail2ban(h)
	waitFor(t, tm, "10.0.0.0/8")
	tm.Type("a")
	waitFor(t, tm, "203.0.113.5")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  added 203.0.113.5 to the ignore list")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // close the card
	wantAll(t, ctrlCView(t, tm), "Ignore list: 10.0.0.0/8 203.0.113.5")
	b, _ := os.ReadFile(filepath.Join(h.root, f2bDropIn))
	if want := "[DEFAULT]\nignoreip = 10.0.0.0/8 203.0.113.5\n\n[sshd]\nenabled = true\nport = 22\n"; string(b) != want {
		t.Errorf("drop-in =\n%s\nwant\n%s", b, want)
	}
	if !slices.Contains(h.fake.Calls, "fail2ban-client reload") {
		t.Errorf("no reload in %q", h.fake.Calls)
	}
	if log := h.actionLog(); !strings.Contains(log, "fail2ban ignore 203.0.113.5: ok") {
		t.Errorf("Task History = %q", log)
	}
}

func TestFail2banIgnoreValidatesInput(t *testing.T) {
	h := f2bHost(t)
	h.fake.Results["fail2ban-client reload"] = system.Result{Stdout: "OK\n"}
	h.write(f2bDropIn, "[sshd]\nenabled = true\nport = 22\n")
	tm := openFail2ban(h)
	waitFor(t, tm, "198.51.100.7")
	tm.Type("a")
	tm.Type("300.1.1.1")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "not an IP or CIDR")
	if slices.Contains(h.fake.Calls, "fail2ban-client reload") {
		t.Fatal("reloaded on invalid input")
	}
	for range len("300.1.1.1") {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	tm.Type("192.0.2.0/24")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "SUMMARY  added 192.0.2.0/24")
	ctrlCView(t, tm)
	b, _ := os.ReadFile(filepath.Join(h.root, f2bDropIn))
	if want := "[DEFAULT]\nignoreip = 192.0.2.0/24\n\n[sshd]\nenabled = true\nport = 22\n"; string(b) != want {
		t.Errorf("drop-in =\n%s\nwant\n%s", b, want)
	}
}

// newBan lists a new ban in sshd once banned is set: fail2ban banned
// someone while the screen was open.
type newBan struct {
	*system.Fake
	banned atomic.Bool
}

func (r *newBan) Run(name string, args ...string) (system.Result, error) {
	if r.banned.Load() && strings.Join(append([]string{name}, args...), " ") == "fail2ban-client status sshd" {
		return system.Result{Stdout: "`- Actions\n   `- Banned IP list:\t203.0.113.99\n"}, nil
	}
	return r.Fake.Run(name, args...)
}

// While open, the screen re-reads fail2ban on each refresh tick.
func TestFail2banAutoRefreshes(t *testing.T) {
	h := f2bHost(t)
	r := &newBan{Fake: h.fake}
	tm := teatest.NewTestModel(t, New(harden.NewMachine(r, h.host, h.root, io.Discard), time.Now()), teatest.WithInitialTermSize(120, 40))
	waitFor(t, tm, "RAM")
	tm.Type(menuTo("fail2ban"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor(t, tm, "198.51.100.7")
	r.banned.Store(true)
	tm.Send(refreshMsg{})
	waitFor(t, tm, "203.0.113.99")
	ctrlCView(t, tm)
}

// openFail2ban starts the TUI on h and opens the fail2ban screen.
func openFail2ban(h *testHost) *teatest.TestModel {
	tm := start(h)
	waitFor(h.t, tm, "RAM")
	tm.Type(menuTo("fail2ban"))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	return tm
}

func TestFail2banMissingOrStoppedIsAState(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  *system.Result
		want string
	}{
		{"not installed", nil, "fail2ban is not installed"},
		{"inactive", &system.Result{Code: 255, Stderr: "Failed to access socket path"}, "fail2ban is not running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := debianHost(t)
			delete(h.fake.Results, "fail2ban-client status")
			if tc.res != nil {
				h.fake.Results["fail2ban-client status"] = *tc.res
			}
			tm := openFail2ban(h)
			waitFor(t, tm, tc.want)
			ctrlCView(t, tm)
		})
	}
}
